//! The commands a person types for the devices under a recovery phrase
//! (decision 2026-10-04 §5 to §8): `cordelia phrase`, `add-device`,
//! `accept`, `devices`, `remove-device`, `renew`, `settle` and `init
//! --new-key`.
//!
//! **Each of these commands refuses a node of another version than its
//! own** (§16; §10.1, rule 6), with the note that says how to restart
//! it: a route of the same name may mean another thing there. `cordelia
//! devices`, which only shows, is answered beside such a node, with the
//! note. **A command that makes or asks for a recovery phrase also asks
//! how the node stands first,** and shows no word where the node is held
//! up (§10.1).
//!
//! **Every yes is asked here, at a terminal** ([`crate::terminal`]), and
//! each command that asks refuses, before anything else, where its input
//! is not one. What a command then asks of the node is a call that any
//! program with the node's token can make: the yes stops a command that
//! is run by mistake, and nothing else.
//!
//! **The recovery phrase stays in this process** (§5). It is made here
//! (`cordelia phrase`), or typed here with echo off, one word at a time
//! (`remove-device`, `renew`, `settle`), and is in memory that is
//! overwritten when it is dropped. It is never an argument, is never
//! sent to the node, and is in no error and no file. A command that
//! needs it:
//!
//! 1. is handed by the node what is to be signed over: the statement
//!    that the device has applied and the change entry it keeps, as their
//!    signed bytes;
//! 2. prepares the next statement, with no phrase, and **shows its lists
//!    from the bytes it is about to sign**, each key with the first words
//!    of its fingerprint;
//! 3. asks its yes, and only then the phrase;
//! 4. signs the statement, seals the part of the change entry that is
//!    for the phrase, signs the entry, **and drops the phrase**;
//! 5. hands the node the change entry, and waits for nothing before
//!    that.
//!
//! What the node is handed is what every device of the person's is
//! shown: the change entry. For a new phrase it is also handed the
//! statement key, which every device that follows a phrase is given.

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use cordelia_api::change::{Prepared, prepare_change, prepare_settlement};
use cordelia_api::look::{CarriedWordLook, held_named, joined, lists_of};
use cordelia_api::person::{PersonError, first_entry};
use cordelia_core::config::{self, Config};
use cordelia_core::protocol::{
    CHANGE_FETCH_MAX_SECS, LEAVING_SEND_WAIT_SECS, MAX_ENTRY_CHANNEL_BYTES_AT_RELAY,
    PERSONAL_CHANNEL_WARN_BYTES, PHRASE_WORDS, STATUS_AMBER_WAIT_SECS,
};
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::fingerprint;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::{Phrase, PhraseError};
use cordelia_crypto::statement::{Device, SignedStatement, Statement, StatementError};

use crate::terminal::{Terminal, TypedBack};

pub(crate) mod wait;
use crate::{
    Told, api_post, api_post_told, note_another_version, refuse_another_version,
    refuse_before_a_phrase,
};

/// What a recovery phrase is for, who has it, and that it is no wallet's:
/// said wherever one is made (decision 2026-10-04 §5).
const WHOSE_WORDS: &str = "\
Your recovery phrase is twelve words.

  - You need it to remove a device, or to recover on a new machine.
    (You can add a device without it.)
  - Nobody else has it, and this device does not keep it. It is shown once, now.
  - It is not a wallet phrase. Never type it into a wallet, and never type a wallet's words here.";

/// What `cordelia phrase` says on a machine that follows no phrase, after
/// what a phrase is for and before any word of a new one is shown
/// (decision 2026-10-04 §5.2, §9): a person who has a phrase already,
/// and has lost every device, wants `cordelia recover`. A phrase made
/// here first would be another: `cordelia recover` refuses a machine that
/// follows one.
const HAS_ONE_ALREADY: &str = "\
If you have a recovery phrase already and every device is lost, do not make a new one.
Press Ctrl-C, and recover with the phrase you have:
  cordelia recover";

/// What `cordelia phrase` says before it goes on, by where the device
/// stands among its person's devices (`among`): [`WHOSE_WORDS`], and on
/// a machine that follows no phrase [`HAS_ONE_ALREADY`] after it.
fn phrase_opening(among: &str) -> String {
    match among {
        "no_phrase" => format!("{WHOSE_WORDS}\n\n{HAS_ONE_ALREADY}\n"),
        _ => format!("{WHOSE_WORDS}\n"),
    }
}

/// What is said where a person did not say yes.
pub(crate) const NOT_A_YES: &str = "That was not a yes. Nothing was done.";

/// How often the node is asked while a command waits for something to
/// come about.
const ASK_EVERY: Duration = Duration::from_secs(1);

/// How long `cordelia accept` stays and says what became of the key.
/// The node goes on asking for the rest of the hour, and `cordelia
/// status` says what became of it.
const ACCEPT_STAYS: Duration = Duration::from_secs(60);

/// How often a mistyped phrase may be typed again at one prompt.
const PHRASE_TRIES: usize = 3;

/// How often the node is asked again whether it made what a command
/// handed it, where its answer was lost: once every [`ASK_EVERY`].
const ASKS_AGAIN: usize = 10;

// ── What the node says ──────────────────────────────────────────────

/// Everything the node says of this device and its person
/// (`cordelia_api::look::Look`, with what waits to be sent).
///
/// Refused where what answered says nothing of where the device stands
/// (it has no `state`): that is no look of a node of this version, and
/// nothing is read from it (decision 2026-10-04 §16).
pub(crate) fn look(config_path: &str) -> anyhow::Result<Value> {
    looks(config_path, false)
}

/// [`look`], with how many versions the device holds that it has sent to
/// no relay, and of how many names (decision 2026-10-04 §16): what a
/// command that has this device begin again says before its yes
/// ([`waits_says`]). The node works that count out only where a request
/// asks for it, and only such a command asks: a status, which a status
/// bar runs every few seconds, does not.
fn look_with_what_waits(config_path: &str) -> anyhow::Result<Value> {
    looks(config_path, true)
}

/// What a look asks the node for beside what every look says: the count
/// of what the device has sent to no relay, where `what_waits`, and
/// nothing otherwise.
fn look_asks(what_waits: bool) -> Value {
    match what_waits {
        true => json!({ "sent_to_no_relay": true }),
        false => json!({}),
    }
}

/// [`look`], asking as [`look_asks`] says.
fn looks(config_path: &str, what_waits: bool) -> anyhow::Result<Value> {
    let seen = api_post(config_path, "/api/v1/devices/list", look_asks(what_waits))?;
    if seen["state"].as_str().is_none() {
        anyhow::bail!(no_look_says(std::env::consts::OS));
    }
    Ok(seen)
}

/// What a command says where what answered at the node's address is no
/// look of a node of this command's version ([`look`]), on the system
/// named: nothing was done, and how the node is restarted
/// ([`cordelia_api::commands::restart_says`]).
fn no_look_says(os: &str) -> String {
    format!(
        "what answered at the node's address says nothing of where this device stands: it is \
         no node of this command's version. Nothing was done. Restart the node:\n{}",
        cordelia_api::commands::restart_says(os)
    )
}

pub(crate) fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_default()
}

/// Whether the node made what a command handed it, where the node's
/// answer was lost (decision 2026-10-04 §16): the node is asked again,
/// before anything is said. `made` is what the change entry that the
/// command made is named by, and the node made it where that is the
/// latest change entry it keeps.
///
/// `false` says that this could not be learned, and not that nothing was
/// made: the node did not answer, or it keeps another entry so far, and
/// may still be at work on what it was handed.
pub(crate) fn made_all_the_same(config_path: &str, made: &[u8; 32]) -> bool {
    let made = hex::encode(made);
    for _ in 0..ASKS_AGAIN {
        std::thread::sleep(ASK_EVERY);
        let asked = api_post_told(
            config_path,
            "/api/v1/devices/list",
            json!({}),
            Some(Duration::from_secs(3)),
        );
        if let Ok(Told::Yes(seen)) = asked
            && seen["latest"] == made.as_str()
        {
            return true;
        }
    }
    false
}

pub(crate) fn list<'a>(value: &'a Value, field: &str) -> impl Iterator<Item = &'a Value> {
    value[field].as_array().into_iter().flatten()
}

/// A file's name, or a line that may hold one, as it is printed
/// (decision 2026-10-04 §16): another device may have written the name.
/// It is cut where a name is cut, and its control characters, the marks
/// that change the direction of text, and what cannot be seen and is no
/// part of ordinary writing, are shown as escapes, as local history
/// prints names.
pub(crate) fn file_shown(name: &str) -> String {
    crate::history_cmd::printable(&cordelia_api::look::name_shown(name))
}

/// Whether a row that the node shows is this device's: its key is `own`,
/// the one in this device's key file (decision 2026-10-04 §16). Which
/// row is this device's is never the node's word.
fn is_own(device: &Value, own: &[u8; 32]) -> bool {
    decode_public_key(text(device, "key")).ok() == Some(*own)
}

/// This device's key, read from its key file as `cordelia id` reads it
/// (decision 2026-10-04 §16). What a command shows as this device, signs
/// for and prints is this, and never the node's word of it: whatever
/// answers at the node's address could otherwise name a key of its own.
pub(crate) fn own_key(config_path: &str) -> anyhow::Result<[u8; 32]> {
    let mut config = Config::load(&config::expand_tilde(config_path))?;
    config.apply_env_overrides();
    let key_path = config.data_dir().join(cordelia_api::commands::KEY_FILE);
    if !key_path.exists() {
        anyhow::bail!("this device has no key yet: `cordelia init` gives it one.");
    }
    Ok(NodeIdentity::from_file(&key_path)?.public_key())
}

/// Refuse where `answer`, which the node gave, names another key as this
/// device than `own`, the key in this device's key file (decision
/// 2026-10-04 §16). An answer that names none is refused likewise.
pub(crate) fn names_this_device(answer: &Value, own: &[u8; 32]) -> anyhow::Result<()> {
    if decode_public_key(text(answer, "this_device")).ok() == Some(*own) {
        return Ok(());
    }
    anyhow::bail!(not_this_devices_key_says(own, std::env::consts::OS))
}

/// What a command says where what answered at the node's address names
/// another key as this device than `own`, or none ([`names_this_device`]),
/// on the system named: nothing was done, and how the node is restarted
/// ([`cordelia_api::commands::restart_says`]), since a node that still
/// runs under the key the device had before answers so.
fn not_this_devices_key_says(own: &[u8; 32], os: &str) -> String {
    format!(
        "what answered at the node's address does not name this device's key, which is the \
         one in its key file ({}). Nothing was done. A node goes on under the key it was \
         started with. If this device was given a new key, restart the node:\n{}",
        fingerprint::shown(own),
        cordelia_api::commands::restart_says(os)
    )
}

/// A device as it is shown for a decision: the first four words of its
/// key's fingerprint, and its label (decision 2026-10-04 §6, §16).
///
/// **The words come first, and the label after them, quoted.** A label
/// is whatever the device that added a key called it: it may hold
/// brackets, and words of the list. Shown first it could put counterfeit
/// words where a person looks for the real ones. Quoted, with whatever
/// would end the quotes marked, it cannot pass for anything that this
/// command says itself.
pub(crate) fn named(label: &str, key: &[u8; 32]) -> String {
    words_then(&fingerprint::shown(key), label)
}

/// A device that the node shows, as [`named`] says it.
fn shown(device: &Value) -> String {
    words_then(text(device, "words"), text(device, "label"))
}

// ── The carried word (decision 2026-10-19 §4, rules 6 and 7) ────────

/// The relays that a look lists, each by the name that this device's
/// configuration gives it and with its key where the device knows one:
/// what another device's carried word names a relay by (rule 6).
fn relays_known(seen: &Value) -> Vec<(String, Option<String>)> {
    list(seen, "relays")
        .map(|relay| {
            let key = relay["key"].as_str().map(str::to_string);
            (text(relay, "relay").to_string(), key)
        })
        .collect()
}

/// The carried word of a device that a look shows, where it is read
/// (rule 5: the node reads it, and never beside `sent`).
fn carried_word_of(device: &Value) -> Option<CarriedWordLook> {
    serde_json::from_value(device["carried_word"].clone()).ok()
}

/// What another device's carried word says, as a line says it: the
/// relays that hold what it carried (`<held>`), and how many may still
/// lack it (`<not yet>`). The two never overlap.
fn held_by_another(word: &CarriedWordLook, seen: &Value) -> (String, u64) {
    let known = relays_known(seen);
    let known: Vec<(&str, Option<&str>)> = known
        .iter()
        .map(|(name, key)| (name.as_str(), key.as_deref()))
        .collect();
    (held_named(word, &known), word.not_yet)
}

/// `<n> other relay` or `<n> other relays`.
fn other_relays(n: u64) -> String {
    match n {
        1 => "1 other relay".into(),
        n => format!("{n} other relays"),
    }
}

/// This device's own line where its own word is the carried word (rule
/// 7; decision 2026-10-19 §5, S4): `<held>` is each relay at which
/// nothing that it carried waits, by its rows of what it sent, reached or
/// not; `<not yet>` is every other relay. `None` where the look names no
/// relay as holding what it carried.
fn own_carried_line(seen: &Value) -> Option<String> {
    let mut held: Vec<String> = Vec::new();
    let mut not_yet: Vec<String> = Vec::new();
    for relay in list(seen, "relays") {
        let name = text(relay, "relay").to_string();
        match relay["has_what_was_carried"] == true {
            true => held.push(name),
            false => not_yet.push(name),
        }
    }
    if held.is_empty() {
        return None;
    }
    let mut line = format!("this device has sent what it carried to {}", joined(&held));
    if !not_yet.is_empty() {
        line.push_str(&format!("; not yet to {}", joined(&not_yet)));
    }
    Some(line)
}

/// The words of a key's fingerprint, and then its label, quoted.
pub(crate) fn words_then(words: &str, label: &str) -> String {
    match label.is_empty() {
        true => format!("the device ({words})"),
        false => format!("({words}) {label:?}"),
    }
}

/// A time in seconds, as a person reads it.
pub(crate) fn time_of(at: u64) -> String {
    i64::try_from(at)
        .ok()
        .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("{at}"))
}

/// The name that this machine goes by, for the label of a device that a
/// person gave none.
pub(crate) fn default_label() -> String {
    #[cfg(unix)]
    let host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned();
    #[cfg(not(unix))]
    let host = String::new();
    let label: String = host
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    match label.is_empty() {
        true => "device".into(),
        false => label,
    }
}

/// An entry, from the hex of its bytes, checked as whatever a device is
/// given is checked.
pub(crate) fn entry_of(hex_bytes: &str) -> anyhow::Result<CheckedEntry> {
    Ok(Entry::from_wire(&hex::decode(hex_bytes)?)?.check()?)
}

/// What the lines that `cordelia status` adds say of this device and its
/// person: a few words, and then a sentence each.
pub fn status_lines(seen: &Value) -> (String, Vec<String>) {
    let short = match seen["short"].as_str() {
        Some(short) => short.to_string(),
        None => {
            let devices = list(seen, "devices").count()
                + list(seen, "added")
                    .filter(|added| added["counted"] == true)
                    .count();
            let change = seen["change"].as_u64().unwrap_or(0);
            match devices {
                1 => format!("this device alone, under a recovery phrase (change {change})"),
                devices => format!("{devices} devices under a recovery phrase (change {change})"),
            }
        }
    };
    // A line may name a file, as another device wrote its name: it is
    // printed as local history prints names.
    let says = list(seen, "says")
        .filter_map(|line| line.as_str())
        .map(crate::history_cmd::printable)
        .collect();
    (short, says)
}

/// What a command that has this device begin again says before its yes
/// (decision 2026-10-04 §16), where the device holds versions that it
/// has sent to no relay: how many, of how many names, as the node counts
/// them. Beginning again lets go of everything that the device's store
/// holds, and nothing is refused for it: a person who begins again has
/// said so. `None` where nothing waits.
fn waits_says(seen: &Value) -> Option<String> {
    let count = |field: &str| seen["sent_to_no_relay"][field].as_u64().unwrap_or(0) as usize;
    let (versions, names) = (count("versions"), count("names"));
    if versions == 0 {
        return None;
    }
    Some(format!(
        "{} of {} that this device holds {} been sent to no relay yet: {} let go with \
         everything else that it holds.",
        counted(versions, "version"),
        counted(names, "name"),
        match versions {
            1 => "has",
            _ => "have",
        },
        match versions {
            1 => "it is",
            _ => "they are",
        }
    ))
}

/// What `cordelia phrase` says, before its yes, of what the device has
/// sent to no relay ([`waits_says`], decision 2026-10-04 §16): where it
/// goes on to ask a yes, on a device that is alone under a phrase or one
/// of several. **A device that has stopped is refused,** and nothing is
/// let go there: nothing is said of it. (`cordelia init --new-key`,
/// which that refusal names, says it before its own yes.)
fn waits_before_a_new_phrase(seen: &Value) -> Option<String> {
    match text(seen, "among") {
        "alone" | "several" => waits_says(seen),
        _ => None,
    }
}

/// What the yes of `cordelia accept` says on a device that is alone
/// under a recovery phrase (decision 2026-10-04 §5.1): it leaves that
/// phrase, and joins the devices of `from`. Leaving lets go of
/// everything that the device holds, a name that a carry or a recovery
/// holds among it: **what it has sent to no relay is said first**
/// ([`waits_says`], decision 2026-10-04 §16), as before the yes of any
/// command that has a device begin again.
fn alone_says(seen: &Value, from: &str) -> String {
    let leaves = format!(
        "The recovery phrase that this device follows stops working here: this device leaves \
         it, and joins the devices of {from}."
    );
    match waits_says(seen) {
        Some(waits) => format!("{waits}\n{leaves}"),
        None => leaves,
    }
}

// ── cordelia phrase ─────────────────────────────────────────────────

/// `cordelia phrase`: make the recovery phrase of this person's devices
/// here (decision 2026-10-04 §5, §5.2).
///
/// The phrase is made in this process, shown once with each word's
/// number, and typed back whole, a word at a time, before anything is
/// made. The node is handed the first statement's change entry and the
/// statement key, and never the words.
///
/// **Nothing is shown on a terminal that keeps what is shown** (decision
/// 2026-10-04 §16): inside GNU `screen` the command stops before it
/// asks the node anything, and no phrase is made
/// ([`Terminal::keeps_what_is_shown`]). The commands that only read a
/// phrase show none, and are not stopped there.
///
/// **Each word typed back is held against the word that was shown at its
/// number** (decision 2026-10-04 §16), here and at no other command: a
/// phrase written down wrongly is found out word by word. The third
/// try that is not the word shown stops the command, and nothing is
/// made ([`Terminal::phrase_back`]).
pub fn phrase(config_path: &str, name: Option<String>) -> anyhow::Result<()> {
    let at = Terminal::for_a_phrase()?;
    // A terminal that keeps what is shown is shown nothing: before the
    // node is asked anything, and before there is a phrase to show.
    if at.keeps_what_is_shown() {
        anyhow::bail!(
            "this terminal can keep what is shown in its scrollback.\nRun `cordelia phrase` in \
             a terminal outside `screen`. Nothing was made."
        );
    }
    refuse_before_a_phrase(config_path)?;
    // The first statement is made for the key in this device's key file.
    let this_device = own_key(config_path)?;
    let seen = look_with_what_waits(config_path)?;
    names_this_device(&seen, &this_device)?;
    let among = text(&seen, "among").to_string();
    println!("{}", phrase_opening(&among));
    // What a device that follows a phrase already would let go of.
    if let Some(waits) = waits_before_a_new_phrase(&seen) {
        println!("{waits}");
    }
    let agreed = match among.as_str() {
        "no_phrase" => true,
        "alone" => at.yes(
            "This replaces the recovery phrase that this device follows: the old one stops \
             working here, and what the relays hold under it is left behind.",
        )?,
        "several" => {
            let others = seen["others"].as_u64().unwrap_or(0);
            at.yes(&format!(
                "This device leaves the {others} device{} it is with and starts again alone, \
                 under a new phrase. It says so to {} first. It still holds what it held, and \
                 is still listed there: removing it, with the old phrase, is what cuts it off.",
                if others == 1 { "" } else { "s" },
                if others == 1 { "it" } else { "them" },
            ))?
        }
        _ => anyhow::bail!(
            "{}. A device that has stopped makes no phrase of its own: `cordelia init \
             --new-key` starts it afresh.",
            seen["cannot_go_on"]
                .as_str()
                .unwrap_or("this device has stopped")
        ),
    };
    if !agreed {
        println!("{NOT_A_YES}");
        return Ok(());
    }
    let label = name.unwrap_or_else(default_label);
    // A label that a statement would refuse is refused before any word
    // is shown.
    Device::new(this_device, &label)?;

    // What is said above the words, and below them.
    let says = "Your recovery phrase (shown once):";
    let asks = "Write the twelve words down, in order. Keep them where only you can read \
                them.\nPress Enter when you have. The words are then cleared from the screen. ";
    // The terminal's size is read before there is a phrase: where it has
    // no room for the twelve words, none is made.
    let in_a_row = match words_in_a_row(at.size(), says, asks) {
        Ok(in_a_row) => in_a_row,
        Err(too_small) => anyhow::bail!(too_small),
    };

    let phrase = Phrase::generate()?;
    at.once(
        says,
        numbered(phrase.words()?.as_str(), in_a_row).as_str(),
        asks,
    )?;
    let made = {
        // Each word is held against the word shown by its place in the
        // list: the words themselves are not set beside each other.
        let typed_back = at.phrase_back(
            "Now type the words back, one at a time. What you type is not shown.",
            &*phrase.places()?,
        )?;
        if let Some(why) = not_typed_back_says(&typed_back) {
            anyhow::bail!(why);
        }
        println!("\nAll twelve match.");
        first_entry(&phrase, &this_device, &label)?
    };
    // The phrase has signed and sealed: it is dropped here, and
    // overwritten, before the node is asked anything.
    drop(phrase);

    let asked = api_post_told(
        config_path,
        "/api/v1/phrase/make",
        json!({
            "entry": hex::encode(made.entry.to_wire()),
            "statement_key": hex::encode(made.statement_key),
            "from": among,
        }),
        Some(Duration::from_secs(30)),
    );
    match asked {
        Ok(Told::Yes(_)) => {}
        // The node refused: it said so, and made nothing.
        Ok(Told::No { message, .. }) => anyhow::bail!(
            "{message}\nNothing was made, and the words that were shown are no phrase of \
             anything: do not keep them."
        ),
        // The answer was lost, and the node may have made the phrase all
        // the same: it is asked again before anything is said of it.
        Err(lost) => {
            println!("\n{lost}\nThe node's answer was lost. Asking it again...");
            if !made_all_the_same(config_path, &made.entry.id()) {
                anyhow::bail!(
                    "it is not known whether the node made the new phrase: it does not say \
                     that it follows it so far, and it may still. KEEP the twelve words until \
                     `cordelia devices` shows which recovery phrase this device follows: the \
                     new one is shown there as ({}). If it shows another, or none, the words \
                     are no phrase of anything.",
                    fingerprint::shown(&made.entry.author)
                );
            }
        }
    }
    println!(
        "\nThis device follows the new recovery phrase, alone. It is listed as {} (change 1).",
        named(&label, &this_device)
    );
    println!(
        "Each relay is shown the change first, before anything else is sent there: `cordelia \
         devices` says which hold it.\nAdd another device with `cordelia add-device <its \
         key>`."
    );
    Ok(())
}

/// What `cordelia phrase` says where the words that it showed were not
/// all typed back, and `None` where they were (decision 2026-10-04 §5):
/// at the third miss, or where the input ended first. Either way nothing
/// is made, and the words that were shown are a phrase of nothing: a
/// person is told so, and not to keep them.
fn not_typed_back_says(typed_back: &TypedBack) -> Option<String> {
    let nothing_made = "Nothing was made, and the words you were shown are not a recovery \
                        phrase: do not keep them.";
    match typed_back {
        TypedBack::All => None,
        TypedBack::Missed => Some(format!(
            "Three tries did not match. {nothing_made} Run `cordelia phrase` again."
        )),
        TypedBack::Ended(said) => Some(format!("{said}. {nothing_made}")),
    }
}

/// How many of the twelve words are shown to a row on a terminal of
/// `size`, its columns and lines, with `says` above them and `asks`
/// below (decision 2026-10-04 §5):
///
/// - four, as a rule, and where the terminal says nothing of its size;
/// - **one, where the terminal is narrower than a row of four,** so that
///   no row is broken over two lines, and a number parted from its word;
/// - and **where it has no room for them even so, what to say:** nothing
///   is shown, and nothing is made. What does not fit scrolls off the top
///   of a screen that keeps no lines, and is not seen.
///
/// A line of `says` or `asks` that is longer than the terminal is wide
/// goes on to the next line, and is counted so.
fn words_in_a_row(size: Option<(usize, usize)>, says: &str, asks: &str) -> Result<usize, String> {
    let Some((columns, lines)) = size else {
        return Ok(4);
    };
    let in_a_row = if columns >= widest_row(4) { 4 } else { 1 };
    // What the words need: at the width that the terminal has, or, where
    // it is narrower than one word with its number, at that width.
    let needs_columns = columns.max(widest_row(1));
    let needs_lines = lines_taken(says, needs_columns)
        + 1
        + PHRASE_WORDS.div_ceil(in_a_row)
        + 1
        + lines_taken(asks, needs_columns);
    if columns < needs_columns || lines < needs_lines {
        return Err(format!(
            "this terminal is too small to show the twelve words: it has {columns} columns and \
             {lines} lines.\nThey need {needs_columns} columns and {needs_lines} lines. Nothing \
             was made."
        ));
    }
    Ok(in_a_row)
}

/// How many columns the widest row of the words can take, `in_a_row` of
/// them to a row: the rows of twelve of the longest words of the list.
fn widest_row(in_a_row: usize) -> usize {
    let longest = ["abstract"; PHRASE_WORDS].join(" ");
    let rows = numbered(&longest, in_a_row);
    rows.lines().map(str::len).max().unwrap_or(0)
}

/// How many lines `text` takes on a terminal of `columns`: a line that is
/// longer than the terminal is wide goes on to the next.
fn lines_taken(text: &str, columns: usize) -> usize {
    text.lines()
        .map(|line| line.len().div_ceil(columns).max(1))
        .sum()
}

/// The twelve `words` as they are shown: each with its number,
/// `in_a_row` to a row, the columns lined up. So the numbers that a
/// person writes down are the numbers that the words are asked for by.
///
/// The text is overwritten when it is dropped, and is never moved as it
/// grows: it has room for sixteen bytes a word, which is a number, a full
/// stop and a space, the eight letters of the longest word, and what
/// parts it from the next.
fn numbered(words: &str, in_a_row: usize) -> Zeroizing<String> {
    use std::fmt::Write;
    let (longest, between) = (8, 3);
    let mut rows = Zeroizing::new(String::with_capacity(PHRASE_WORDS * 16));
    let mut after_the_last = 0;
    for (at, word) in words.split(' ').enumerate() {
        match at % in_a_row {
            0 if at == 0 => rows.push_str("  "),
            0 => rows.push_str("\n  "),
            _ => rows.extend(std::iter::repeat_n(' ', after_the_last)),
        }
        // Written where it is: no copy of a word is made on the way.
        let _ = write!(rows, "{:>2}. {word}", at + 1);
        after_the_last = longest.max(word.len()) - word.len() + between;
    }
    rows
}

// ── cordelia add-device ─────────────────────────────────────────────

/// `cordelia add-device <key>`: hand a device what it needs to be one of
/// the person's (decision 2026-10-04 §6). The phrase is not typed to
/// add: a device that is in vouches for the new one.
pub fn add_device(config_path: &str, key: &str, name: Option<String>) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let device = decode_public_key(key).map_err(|e| {
        anyhow::anyhow!("that is no device's key, as `cordelia id` prints one: {e}")
    })?;
    // The key that the other device is told to type is the one in this
    // device's key file.
    let own = own_key(config_path)?;
    let body = json!({ "device": key, "label": name });
    let would = api_post(config_path, "/api/v1/devices/add/look", body.clone())?;
    names_this_device(&would, &own)?;
    // What the yes is for goes with the request: the node refuses where
    // adding the key would by then do the other (§16).
    let yes_is_for = match text(&would, "would") {
        "hand_again" => "hand_again",
        _ => "add",
    };
    let agreed = match yes_is_for {
        "hand_again" => at.yes(&format!(
            "{} is one of your devices already: this hands it the last change again, and \
             adds nothing.",
            named(text(&would, "label"), &device)
        ))?,
        _ => {
            let label = name.as_deref().unwrap_or("the new device");
            if let Some(was) = would["left_out_as"].as_str() {
                println!(
                    "This key was not in the last change. This device knew it as {was:?}, and \
                     it holds what your devices held before that change."
                );
            }
            if would["counts_already"] == true {
                println!("This key counts as one of your devices already, by an earlier addition.");
            }
            at.yes(&format!(
                "This gives {} every name's memory, and the means to read what your devices \
                 write from now on.",
                named(label, &device)
            ))?
        }
    };
    if !agreed {
        println!("{NOT_A_YES}");
        return Ok(());
    }
    let mut body = body;
    body["would"] = yes_is_for.into();
    let added = api_post(config_path, "/api/v1/devices/add", body)?;
    names_this_device(&added, &own)?;
    let this_device = encode_public_key(&own)?;
    match added["record"] == true {
        true => println!(
            "\nAdded. Every device of yours shows the addition until a person clears it there."
        ),
        false => println!("\nThe last change is handed to it again."),
    }
    println!("\nOn the other device, within the hour, run:");
    println!("  cordelia accept {this_device}");
    println!(
        "\nIt shows these words for this device's key before it asks its yes: {}",
        fingerprint::shown(&own)
    );
    Ok(())
}

// ── cordelia accept ─────────────────────────────────────────────────

/// `cordelia accept <key>`: take what the device of that key hands over
/// (decision 2026-10-04 §5.1). What it does goes by the state this
/// device is in, and its yes says which.
pub fn accept(config_path: &str, key: &str) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let typed = decode_public_key(key).map_err(|e| {
        anyhow::anyhow!("that is no device's key, as `cordelia id` prints one: {e}")
    })?;
    let own = own_key(config_path)?;
    let seen = look_with_what_waits(config_path)?;
    names_this_device(&seen, &own)?;
    let from = named("", &typed);
    // What the yes says goes by the row of §5.1 that the device stands
    // in, and the key is kept with that row: it is spent in no other.
    let (row, says) = match (text(&seen, "state"), text(&seen, "among")) {
        ("no_phrase", _) => {
            let folders = seen["folders"].as_u64().unwrap_or(0);
            let says = format!(
                "This device, and the {folders} folder{} it maps, will join the devices of \
                 {from}: what is in those folders will be sent to them.",
                if folders == 1 { "" } else { "s" }
            );
            ("no_phrase", says)
        }
        ("removed", _) => anyhow::bail!(
            "this device was removed: `cordelia init --new-key` first. It is then added as a \
             new device."
        ),
        // A closed device is added again by a hand-over of a clear change
        // that lists it (decision 2026-10-24 (removal), rule 10).
        ("fork", _) => (
            "several",
            format!(
                "This device is closed: a device that was removed holds the secret of the \
                 change it follows. It takes, within the hour, only what {from} hands over \
                 under the recovery phrase that it already follows, where that brings a change \
                 that lists it and that no removed device holds. Anything else moves nothing."
            ),
        ),
        ("not_listed" | "not_opened", _) => (
            "not_listed",
            format!(
                "This device takes, within the hour, only what {from} hands over under the \
                 recovery phrase that it already follows, with the change that stopped it or \
                 one made after that. It keeps its folders, and carries what it holds."
            ),
        ),
        (_, "alone") => {
            if seen["sync_on"] == true {
                anyhow::bail!(
                    "sync is on here, and this device is alone under a recovery phrase: \
                     `cordelia sync off` first, so that sending its folders to another set of \
                     devices takes two acts."
                );
            }
            ("alone", alone_says(&seen, &from))
        }
        _ => (
            "several",
            format!(
                "This device is one of several. It takes, within the hour, only what {from} \
                 hands over under the recovery phrase that it already follows, where that \
                 brings a change it can apply. Anything else moves nothing."
            ),
        ),
    };
    if !at.yes(&says)? {
        println!("{NOT_A_YES}");
        return Ok(());
    }
    let typed_in = json!({ "key": key, "row": row });
    let kept = api_post(config_path, "/api/v1/devices/accept", typed_in)?;
    let until = kept["until"].as_u64().map(time_of).unwrap_or_default();
    println!("\nAsking the relays for what {from} hands over, until {until}.");

    // It stays for a while, and says what became of the key. The node
    // goes on asking after that, until the hour is gone.
    let ends = Instant::now() + ACCEPT_STAYS;
    let mut said = String::new();
    loop {
        std::thread::sleep(ASK_EVERY);
        let seen = look(config_path)?;
        let of_the_key = list(&seen, "accepting").find(|typed| text(typed, "key") == key);
        let Some(of_the_key) = of_the_key else {
            anyhow::bail!("the node keeps that key no longer: type it again (`cordelia accept`)");
        };
        let now_said = text(of_the_key, "said");
        if of_the_key["taken"] == true {
            println!("{}.", capitalised(now_said));
            return Ok(());
        }
        if !now_said.is_empty() && now_said != said {
            println!("So far: {now_said}.");
            said = now_said.to_string();
        }
        if Instant::now() >= ends {
            println!(
                "Nothing was taken yet. This device goes on asking until {until}: `cordelia \
                 status` says what became of it."
            );
            return Ok(());
        }
    }
}

// ── cordelia devices ────────────────────────────────────────────────

/// `cordelia devices`: one place to look (decision 2026-10-04 §8). With
/// `clear`, each notice is asked about at the terminal, and what a person
/// says yes to is shown on this device no more.
pub fn devices(config_path: &str, clear: bool) -> anyhow::Result<()> {
    let own = own_key(config_path)?;
    if clear {
        let at = Terminal::at()?;
        // Clearing is an act: it is not sent to a node of another
        // version. Without one, `devices` only shows, and is answered
        // beside such a node, with the note (§10.1, rule 6).
        refuse_another_version(config_path)?;
        let seen = look(config_path)?;
        names_this_device(&seen, &own)?;
        return clear_notices(config_path, &at, &seen);
    }
    note_another_version(config_path);
    let seen = look(config_path)?;
    names_this_device(&seen, &own)?;
    for line in devices_lines(&seen, &own) {
        println!("{line}");
    }
    Ok(())
}

/// The addresses that a relay's name (`host:port`) is found at on this
/// machine, as a node dials it: what a row of what waits there is matched
/// by where the node gives the row no name. None where the name is found
/// at none.
fn addresses_of(name: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    name.to_socket_addrs()
        .map(|found| found.map(|address| address.to_string()).collect())
        .unwrap_or_default()
}

/// The addresses of each of `names` ([`addresses_of`]), looked up by
/// `lookup` within `wait` for all of them together, as the node bounds
/// its own lookups of its relays (`STREAM_TIMEOUT_SECS`). Where the
/// lookups do not end in time, none is found for any name: each relay is
/// then listed by its name, and what waits at its address after it, and
/// the command is not held up.
fn addresses_within(
    names: Vec<String>,
    wait: std::time::Duration,
    lookup: fn(&str) -> Vec<String>,
) -> Vec<Vec<String>> {
    let count = names.len();
    let (found, answer) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = found.send(names.iter().map(|name| lookup(name)).collect());
    });
    answer
        .recv_timeout(wait)
        .unwrap_or_else(|_| vec![Vec::new(); count])
}

/// A mebibyte: every size of what a relay keeps is said in MiB (decision
/// 2026-10-19 §2, rule 5).
const MIB: u64 = 1024 * 1024;

/// `bytes` in MiB, to a tenth.
fn mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / MIB as f64)
}

/// What the personal channel holds, as the last sync cycle that read it
/// found, where it is past the line (decision 2026-10-19 §2, rules 3 and
/// 5): `cordelia devices` shows the sizes past the line only.
fn past_the_line(seen: &Value) -> Option<&Value> {
    let filled = &seen["personal_channel"];
    (filled["total"].as_u64()? > PERSONAL_CHANNEL_WARN_BYTES).then_some(filled)
}

/// What `device` signed of the personal channel, as `filled` says, in
/// bytes as a relay counts them.
fn signed_by(filled: &Value, device: &Value) -> u64 {
    filled["by"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|signed| signed["key"] == device["key"])
        .map(|signed| {
            signed["words"].as_u64().unwrap_or(0) + signed["not_words"].as_u64().unwrap_or(0)
        })
        .sum()
}

/// What `cordelia devices` prints, a line each. `own` is this device's
/// key, from its key file: which row is this device's goes by it.
fn devices_lines(seen: &Value, own: &[u8; 32]) -> Vec<String> {
    devices_lines_at(seen, own, chrono::Utc::now().timestamp(), &LOOKED_UP)
}

/// How `cordelia devices` looks up the relays' names
/// ([`addresses_within`]): by what, and within how long.
struct Lookup {
    wait: std::time::Duration,
    by: fn(&str) -> Vec<String>,
}

/// The lookup that `cordelia devices` makes: the system's, within the
/// stream timeout, as the node bounds its own lookups of its relays.
const LOOKED_UP: Lookup = Lookup {
    wait: std::time::Duration::from_secs(cordelia_core::protocol::STREAM_TIMEOUT_SECS),
    by: addresses_of,
};

/// Whether it is too soon, at `now`, to say anything against `device`,
/// which this device has not heard to have applied the change (decision
/// 2026-10-04 §8). A device says that it has applied a change in the
/// personal channel, and its word takes a moment to arrive. So for
/// `STATUS_AMBER_WAIT_SECS`:
///
/// - **after this device took a typed key** (it took what that key
///   handed it, and has heard from nobody since), of every device;
/// - **after this device added `device`** (its record says when, and this
///   device wrote that time), of that one.
///
/// **Each runs from a time that this device's own clock gave:** when it
/// took the key, or when it added the device. A time that another device
/// wrote (the record of a device that another added) holds nothing back,
/// and nor does a time ahead of this device's clock.
fn too_soon_to_say(seen: &Value, device: &Value, own: &[u8; 32], now: i64) -> bool {
    let just = |at: i64| {
        now.checked_sub(at)
            .is_some_and(|ago| (0..STATUS_AMBER_WAIT_SECS as i64).contains(&ago))
    };
    let took = list(seen, "accepting")
        .filter(|typed| typed["taken"] == true)
        .filter_map(|typed| typed["taken_at"].as_i64())
        .any(just);
    let added_here = is_own(&device["by"], own);
    took || (added_here && device["at"].as_i64().is_some_and(just))
}

/// [`devices_lines`], at `now`, in seconds: what is said of a device
/// that has not been heard from goes by how long ago this device joined,
/// or that one was added ([`too_soon_to_say`]).
fn devices_lines_at(seen: &Value, own: &[u8; 32], now: i64, lookup: &Lookup) -> Vec<String> {
    let mut out = Vec::new();
    let change = seen["change"].as_u64();
    out.push(format!(
        "This device: {}",
        encode_public_key(own).unwrap_or_default()
    ));
    let Some(change) = change else {
        out.extend(list(seen, "says").filter_map(|line| Some(line.as_str()?.to_string())));
        return out;
    };
    out.push(format!("The last change it has applied: change {change}."));
    if let Some(words) = seen["phrase_words"].as_str() {
        out.push(format!("The recovery phrase it follows: ({words})."));
    }
    if let Some(why) = seen["cannot_go_on"].as_str() {
        out.push(format!("This device cannot go on: {why}."));
    }
    if let Some(left) = seen["statements_left"].as_u64() {
        out.push(format!(
            "The recovery phrase can make {left} more change{}.",
            if left == 1 { "" } else { "s" }
        ));
    }
    let applied = |device: &Value| match device["applied"].as_u64() {
        _ if is_own(device, own) => "this device".to_string(),
        // Whether it has sent what it held when it applied the change
        // (§8): it says so itself, once it has.
        Some(number) if number == change => match device["sent"] == true {
            true => format!("has applied change {change}, and has sent what it held"),
            // Its carried word (decision 2026-10-19, rule 6, D1): what it
            // held is at the relays it names, and only there if it is lost
            // now.
            false if let Some(word) = carried_word_of(device) => {
                let (held, not_yet) = held_by_another(&word, seen);
                let mut said =
                    format!("has applied change {change}, and has sent what it held to {held}");
                if not_yet > 0 {
                    said.push_str(&format!(
                        "; not yet to {} that it is set up with (if it is lost now, what it held \
                         is at {held} alone)",
                        other_relays(not_yet)
                    ));
                }
                said
            }
            // A device that is lost in that state has left what it had
            // not sent: what it had sent before comes in by command
            // (§7.3, §8).
            false => format!(
                "has applied change {change}, and is still sending what it held (if it is \
                 lost now, what it had not sent is lost with it; `cordelia sync carry` brings \
                 in what it had sent before)"
            ),
        },
        // Not heard to have applied it. Just after this device took a
        // typed key, or added that one, that is all that is known: its
        // word may not have arrived yet, and nothing is advised.
        _ if too_soon_to_say(seen, device, own, now) => "not heard from yet".to_string(),
        _ => format!(
            "has not applied change {change} yet, as far as this device has heard: adding it \
             again from a device that has (`cordelia add-device`) hands it the change, and \
             `cordelia sync carry` brings in what it had sent to the relays"
        ),
    };
    let left = |device: &Value| match device["left"] == true {
        true => "; has said that it left",
        false => "",
    };
    // Past the line, what each device keeps at a relay (decision
    // 2026-10-19 §2, rule 5).
    let past = past_the_line(seen);
    let keeps = |device: &Value| match past {
        Some(filled) => format!("; keeps {} MiB there", mib(signed_by(filled, device))),
        None => String::new(),
    };
    if let Some(filled) = past {
        out.push(format!(
            "Your devices keep {} MiB of the {} MiB a relay holds for them (names: {} MiB)",
            mib(filled["total"].as_u64().unwrap_or(0)),
            MAX_ENTRY_CHANNEL_BYTES_AT_RELAY / MIB,
            mib(filled["words"].as_u64().unwrap_or(0)),
        ));
    }

    out.push(String::new());
    out.push("Devices of the last change:".into());
    for device in list(seen, "devices") {
        let made = match device["maker"] == true {
            true => "; the change was made on it",
            false => "",
        };
        out.push(format!(
            "  {}: {}{made}{}{}",
            shown(device),
            applied(device),
            left(device),
            keeps(device)
        ));
        out.push(format!("      {}", text(device, "key")));
    }
    let added: Vec<&Value> = list(seen, "added").collect();
    if !added.is_empty() {
        out.push(String::new());
        out.push("Added since:".into());
    }
    for device in added {
        let by = shown(&device["by"]);
        let at = device["at"].as_u64().map(time_of).unwrap_or_default();
        let says = match device["counted"] == true {
            true => format!("{}{}{}", applied(device), left(device), keeps(device)),
            false => format!(
                "not counted ({})",
                device["why_not"]
                    .as_str()
                    .unwrap_or("its record does not count")
            ),
        };
        out.push(format!(
            "  {}, added from {by} at {at}: {says}",
            shown(device)
        ));
        out.push(format!("      {}", text(device, "key")));
    }
    let removed: Vec<&Value> = list(seen, "removed").collect();
    if !removed.is_empty() {
        out.push(String::new());
        out.push("Removed keys:".into());
    }
    // A statement lists a removed key bare: it is shown by the label
    // that this device knew it by, where it knew it by one. That label,
    // or the first six words of the key's fingerprint, names it at
    // `cordelia sync carry <name> --from` (§7.3).
    for device in removed {
        out.push(format!("  {}  {}", shown(device), text(device, "key")));
    }
    let left_out: Vec<&Value> = list(seen, "left_out").collect();
    if !left_out.is_empty() {
        out.push(String::new());
        out.push("Not in the last change (each holds what your devices held before it):".into());
    }
    for device in left_out {
        out.push(match device["key"].as_str() {
            None => format!(
                "  {}: add it again, or it was meant to go. Its key is the one it prints \
                 (`cordelia id`).",
                shown(device)
            ),
            // A row that the recovery could not show, and asked nothing
            // of: it is shown with its key (decision 2026-10-04 §9).
            Some(key) => format!(
                "  {}  {key}: the recovery could not show it, and asked nothing of it. Nothing \
                 that it wrote was brought back.",
                shown(device)
            ),
        });
    }
    // Each head set aside, with what is said of it and its lists
    // (decision 2026-10-24 (removal), rules 10 and 11). A node that names
    // none of them names the one made apart, as before.
    let heads: Vec<&Value> = list(seen, "set_aside").collect();
    let apart: Vec<&Value> = match heads.is_empty() {
        true => seen
            .get("apart")
            .filter(|apart| apart.is_object())
            .into_iter()
            .collect(),
        false => heads,
    };
    for head in apart {
        out.push(String::new());
        out.push(format!(
            "The change made apart (change {}, made on {}):",
            head["number"].as_u64().unwrap_or(0),
            shown(&head["made_on"])
        ));
        if let Some(says) = head["says"].as_str() {
            out.push(format!("  {}.", capitalised(says)));
        }
        for device in head["devices"].as_array().into_iter().flatten() {
            out.push(format!("  {}", shown(device)));
        }
        for device in head["removed"].as_array().into_iter().flatten() {
            out.push(format!("  removed: ({})", text(device, "words")));
        }
    }
    out.push(String::new());
    out.push("Relays:".into());
    let relays: Vec<&Value> = list(seen, "relays").collect();
    if relays.is_empty() {
        out.push("  none is reached".into());
    }
    // A relay is listed once, by its name, and what waits to be sent
    // there is said on its line. A row of what waits is that relay's
    // where the node gives it the relay's name, or where the address it
    // is reached at is the name. A relay that is set up with no key is
    // given no name in its row: the row is its own where the address is
    // one that the relay's name is found at here.
    let waiting: Vec<&Value> = list(seen, "waiting").collect();
    let by_name = |waits: &Value, relay: &Value| {
        let name = text(relay, "relay");
        text(waits, "name") == name || text(waits, "relay") == name
    };
    let unnamed = |waits: &&Value| {
        waits["name"].is_null() && !relays.iter().any(|relay| by_name(waits, relay))
    };
    let found_at: Vec<Vec<String>> = match waiting.iter().any(unnamed) {
        true => addresses_within(
            relays
                .iter()
                .map(|relay| text(relay, "relay").to_string())
                .collect(),
            lookup.wait,
            lookup.by,
        ),
        false => vec![Vec::new(); relays.len()],
    };
    // Whether a row of what waits is that of the relay that is `n`th.
    let is_of = |waits: &Value, n: usize| {
        let found = |address: &String| text(waits, "relay") == address;
        by_name(waits, relays[n]) || (waits["name"].is_null() && found_at[n].iter().any(found))
    };
    let to_send = |waits: &Value| waits["waits"].as_u64().filter(|n| *n > 0);
    let woke_at = seen["woke_at"].as_i64();
    for (n, relay) in relays.iter().enumerate() {
        let holds = relay_says(relay, woke_at, seen["latest"].as_str(), now);
        let waits = waiting.iter().copied().filter(|waits| is_of(waits, n));
        let still = waits
            .filter_map(to_send)
            .max()
            .map(|n| format!("{n} of this device's channels still to send there"));
        // A line of sentences says what waits there on a line of its own.
        match still {
            Some(still) if holds.ends_with('.') => {
                out.push(format!("  {}: {holds}", text(relay, "relay")));
                out.push(format!("      {still}"));
            }
            Some(still) => out.push(format!("  {}: {holds}; {still}", text(relay, "relay"))),
            None => out.push(format!("  {}: {holds}", text(relay, "relay"))),
        }
        for more in [&relay["no_room"], &relay["refuses"]] {
            if let Some(more) = more.as_str() {
                out.push(format!("      {more}"));
            }
        }
        match relay["another_form"].as_u64().unwrap_or(0) {
            0 => {}
            1 => out.push(
                "      an entry of this device's own is there in another form: the file's \
                 next edit goes above both"
                    .into(),
            ),
            several => out.push(format!(
                "      {several} entries of this device's own are there in another form: each \
                 file's next edit goes above both"
            )),
        }
    }
    // What waits at a connection that no line above names is listed
    // after, and never by its address (decision 2026-10-24, rule 2).
    let of_no_relay = |waits: &&Value| !(0..relays.len()).any(|n| is_of(waits, n));
    for waits in waiting.iter().copied().filter(of_no_relay) {
        if let Some(n) = to_send(waits) {
            out.push(format!(
                "  {UNNAMED_RELAY}: {n} of this device's channels still to send there"
            ));
        }
    }
    out.extend(names_lines(seen));
    let accepting: Vec<&Value> = list(seen, "accepting").collect();
    if !accepting.is_empty() {
        out.push(String::new());
        out.push("Keys typed at `cordelia accept`:".into());
    }
    for typed in accepting {
        let became = match (typed["taken"] == true, typed["asking"] == true) {
            (true, _) => "taken",
            (false, true) => "asking",
            (false, false) => "its hour has gone, and nothing was taken",
        };
        let said = match typed["said"].as_str() {
            Some(said) if !said.is_empty() => format!(": {said}"),
            _ => String::new(),
        };
        out.push(format!("  ({}): {became}{said}", text(typed, "words")));
    }
    let notices: Vec<&Value> = list(seen, "notices").collect();
    if !notices.is_empty() {
        out.push(String::new());
        out.push("To be told, until a person clears it here (`cordelia devices --clear`):".into());
    }
    for notice in notices {
        out.push(format!("  - {}", text(notice, "says")));
    }
    out
}

/// What `cordelia devices` says of a relay, after its name (decision
/// 2026-10-19, rule 12), at `now`: `woke_at` is when the device last woke,
/// and `latest` the change entry it keeps, as the look names it. What the
/// node knows of its reach is read from the look, and nothing of it is
/// worked out again; what is known of it about another entry says nothing
/// of this one.
///
/// - **Out of reach, and lacks the change:** D4. **Out of reach, and holds
///   it:** D5. Each says first that it cannot be reached from here
///   (decision 2026-10-24, rule 7). What is known of a relay is kept across starts, so these
///   come before what is said of the wake: after a restart a relay that
///   holds the change and cannot be reached is D5, though it has not
///   answered since the start.
/// - **Not heard since the device woke:** D2 while it is not out of reach,
///   and D3 once it is: a relay in the third state, which neither holds
///   nor lacks the change.
/// - Otherwise the lines of before.
fn relay_says(relay: &Value, woke_at: Option<i64>, latest: Option<&str>, now: i64) -> String {
    use cordelia_api::look::{ReachLook, since, when};
    use cordelia_api::state::Holds;
    let reach: Option<ReachLook> = serde_json::from_value(relay["reach"].clone()).ok();
    // What is known of it about the change entry the device keeps.
    let of_latest = reach
        .as_ref()
        .filter(|reach| latest.is_some() && reach.about.as_deref() == latest);
    let out = of_latest.filter(|reach| reach.out_of_reach_since.is_some());
    let name = text(relay, "relay");
    let woke = woke_at
        .map(|at| format!(" at {}", when(at, now)))
        .unwrap_or_default();
    match out {
        Some(reach) if reach.holds == Holds::Lacks => {
            return format!(
                "cannot be reached from here, and is not known to hold the latest change: it {}. \
                 A device of yours that reaches only it may not have heard of that change. If \
                 you know that {name} is gone for good, take it out of the configuration of \
                 every device. Do not do so only because this machine cannot reach it: it may \
                 still serve a device that does.",
                since(reach, now)
            );
        }
        Some(reach) if reach.holds == Holds::Holds => {
            let said = reach
                .answered_at
                .map(|at| format!(" (as it said at {})", when(at, now)))
                .unwrap_or_default();
            return format!(
                "cannot be reached from here, and holds the latest change{said}: it {}",
                since(reach, now)
            );
        }
        _ => {}
    }
    // Whether it holds the change, as section 1 says it where the node
    // knows its reach of the kept entry: a relay given no key that lost its
    // connection lacks it, whatever its last answer said. Where it does
    // not, by the relay's last answer, as before.
    let holds = match of_latest.map(|reach| reach.holds) {
        Some(Holds::Holds) => Some(true),
        Some(Holds::Lacks) => Some(false),
        Some(Holds::Neither) => None,
        None => relay["holds_latest"].as_bool(),
    };
    match (relay["heard_since_woke"] == true, holds) {
        (false, _) if out.is_some() => format!(
            "has not answered since this device started or woke{woke}, and cannot be reached \
             from here. A change made while this device was off may be there, and not have \
             reached it."
        ),
        (false, _) => format!(
            "has not answered since this device started or woke{woke}. A change made while \
             this device was off may be there, and not have reached it."
        ),
        (true, Some(true)) => "holds the latest change".into(),
        (true, Some(false)) => "does not hold the latest change yet".into(),
        (true, None) => "has not said whether it holds the latest change".into(),
    }
}

/// What `cordelia devices` says of names (decision 2026-10-04 §7.3, §8):
/// what this device has still to send, by name; each name that a device
/// had listed before the last change and that no device lists yet, with
/// those that only a key which no longer counts had listed shown apart;
/// and the files whose record the last change could not carry.
fn names_lines(seen: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let to_go: Vec<&str> = list(&seen["names"], "to_go")
        .filter_map(|name| name.as_str())
        .collect();
    let sent = list(&seen["names"], "sent").count();
    if !to_go.is_empty() {
        out.push(String::new());
        out.push(format!(
            "Still to send from this device ({} sent, {} to go):",
            counted(sent, "name"),
            to_go.len()
        ));
        out.extend(to_go.iter().map(|name| format!("  {name}")));
    }
    let not_listed: Vec<&Value> = list(seen, "names_not_listed").collect();
    let by = |name: &Value, field: &str| -> Vec<String> { list(name, field).map(shown).collect() };
    let days = |name: &Value| {
        let days = name["days_left"].as_i64().unwrap_or(0);
        format!("{days} more day{}", if days == 1 { "" } else { "s" })
    };
    let (ours, gone): (Vec<&Value>, Vec<&Value>) = not_listed
        .into_iter()
        .partition(|name| list(name, "by").next().is_some());
    if !ours.is_empty() {
        out.push(String::new());
        out.push(
            "Names that no device lists yet since the last change (`cordelia sync carry \
             <name>` brings one in, and `cordelia sync map` does for a folder that comes to \
             sync it):"
                .into(),
        );
    }
    for name in ours {
        out.push(format!(
            "  {}: synced before by {}; what the relays hold of it can be brought in for {}",
            text(name, "name"),
            by(name, "by").join(", "),
            days(name)
        ));
    }
    if !gone.is_empty() {
        out.push(String::new());
        out.push(
            "Names that only a device which no longer counts had synced (they stay behind: \
             `cordelia sync carry <name> --from <device>` brings one in, with the recovery \
             phrase):"
                .into(),
        );
    }
    for name in gone {
        out.push(format!(
            "  {}: synced before by {}; it can be brought in for {}",
            text(name, "name"),
            by(name, "by_gone").join(", "),
            days(name)
        ));
    }
    // What a device lists as a name and is none: its number, and nothing
    // of what it holds (decision 2026-10-04 §16).
    if let Some(not_shown) = seen["names_not_shown"].as_u64().filter(|n| *n > 0) {
        out.push(String::new());
        out.push(cordelia_api::look::names_not_shown(not_shown as usize));
    }
    let not_carried: Vec<&Value> = list(seen, "not_carried").collect();
    if !not_carried.is_empty() {
        out.push(String::new());
        out.push(
            "Not carried at the last change (what this device held of each could not be read; \
             each meets its channel as a new file does):"
                .into(),
        );
    }
    for file in not_carried {
        out.push(format!(
            "  {} in {}",
            file_shown(text(file, "file")),
            file_shown(text(file, "name"))
        ));
    }
    out
}

/// `says` with a capital first letter: what the node says in the middle
/// of a line of a status begins a line of its own here.
fn capitalised(says: &str) -> String {
    let mut letters = says.chars();
    match letters.next() {
        Some(first) => first.to_uppercase().chain(letters).collect(),
        None => String::new(),
    }
}

/// A count with its noun: `1 name`, `3 names`.
pub(crate) fn counted(n: usize, noun: &str) -> String {
    match n {
        1 => format!("1 {noun}"),
        n => format!("{n} {noun}s"),
    }
}

/// Ask of each notice whether it is cleared on this device, and clear
/// those that a person says yes to.
fn clear_notices(config_path: &str, at: &Terminal, seen: &Value) -> anyhow::Result<()> {
    let notices: Vec<&Value> = list(seen, "notices").collect();
    if notices.is_empty() {
        println!("There is nothing to clear on this device.");
        return Ok(());
    }
    for (asked, notice) in notices.into_iter().enumerate() {
        // An empty line between one notice and the next, and none before
        // the first.
        if asked > 0 {
            println!();
        }
        let clears = at.yes(&format!(
            "{}.\nClearing it changes what this device shows, and nothing else.",
            capitalised(text(notice, "says"))
        ))?;
        if !clears {
            println!("It stays.");
            continue;
        }
        api_post(
            config_path,
            "/api/v1/devices/clear",
            json!({ "notice": text(notice, "id") }),
        )?;
        println!("Cleared on this device.");
    }
    Ok(())
}

// ── cordelia remove-device, renew, settle ───────────────────────────

/// Which change a command makes.
enum Which {
    /// `cordelia remove-device <key>`.
    Remove([u8; 32]),
    /// `cordelia renew`: a change that removes nothing.
    Renew,
    /// `cordelia settle`: the statement that joins changes made apart.
    /// Any change made where a head is set aside joins it too (decision
    /// 2026-10-24 (removal), rule 21).
    Settle,
}

/// `cordelia remove-device <key>` (decision 2026-10-04 §7.1). Given a
/// key that is in no list and was not added since, it removes the key
/// all the same, after saying what that means and a typed answer
/// ([`refuses_a_key_it_does_not_know`], §10).
pub fn remove_device(config_path: &str, key: &str) -> anyhow::Result<()> {
    made_at_a_terminal(config_path, || {
        let device = decode_public_key(key).map_err(|e| {
            anyhow::anyhow!("that is no device's key, as `cordelia devices` lists one: {e}")
        })?;
        Ok(Which::Remove(device))
    })
}

/// Make the change that `which` says, at the terminal of a command that
/// reads a recovery phrase: it is asked for first, before anything is
/// read, in a process that cannot be dumped or traced from then on
/// (decision 2026-10-04 §16).
fn made_at_a_terminal(
    config_path: &str,
    which: impl FnOnce() -> anyhow::Result<Which>,
) -> anyhow::Result<()> {
    let at = Terminal::for_a_phrase()?;
    refuse_before_a_phrase(config_path)?;
    change(config_path, &at, &which()?)
}

/// `cordelia renew`: a new secret for the devices that stay, with no
/// device removed but those added since that a person says go (decision
/// 2026-10-04 §6, §7.1).
pub fn renew(config_path: &str) -> anyhow::Result<()> {
    made_at_a_terminal(config_path, || Ok(Which::Renew))
}

/// `cordelia settle`: join the changes made apart that this device keeps
/// (decision 2026-10-04 §4.5; decision 2026-10-24 (removal), rule 21).
pub fn settle(config_path: &str) -> anyhow::Result<()> {
    made_at_a_terminal(config_path, || Ok(Which::Settle))
}

/// What the node hands a command that makes a change: read from the
/// signed bytes of each thing, and checked here.
struct Handed {
    /// This device's key, from its key file: never the node's word of it.
    this_device: [u8; 32],
    /// The statement the device has applied, and the change entry of it.
    applied: SignedStatement,
    held: CheckedEntry,
    /// What that entry is named by, in hex: worked out from the entry.
    over: String,
    /// Each head set aside, as the node handed it (decision 2026-10-24
    /// (removal), rule 21): its statement, its entry, and what the entry
    /// is named by, worked out from it. A change made here joins them all.
    heads: Vec<(SignedStatement, CheckedEntry, String)>,
    /// Every key that the device knows to be removed, on any branch, as
    /// the node handed them (rule 20): the change lists each as removed,
    /// and none as a device.
    removed: Vec<[u8; 32]>,
    /// The record of each device added since that counts, of a key that
    /// the statement lists in neither list: what the node says a person
    /// is asked about.
    added: Vec<SignedAddition>,
    /// The key of each device that has said that it left, as the node
    /// says it: a person is asked about each.
    left: Vec<[u8; 32]>,
    /// Each name that the personal channel lists, with the keys that
    /// list it, as this device holds that channel.
    names: Vec<(String, Vec<[u8; 32]>)>,
    /// What a device lists there that is no name as this version would
    /// map one (decision 2026-10-04 §16): the key of the device, and how
    /// many. Nothing of what they hold is kept here.
    names_not_shown: Vec<([u8; 32], usize)>,
    /// How many versions each key wrote that this device received, in
    /// the last day and in the last week. `None` with local history off.
    received: Option<Vec<([u8; 32], u64, u64)>>,
}

impl Handed {
    /// Read what the node handed, on a device whose key file holds `own`.
    ///
    /// Refused where the node names another key as this device. And a
    /// record of an addition is one that a person is asked about only
    /// where it names the statement applied, and its adder is a device of
    /// that statement or was added by one, by a record that names it too
    /// (decision 2026-10-04 §6, §16): a node hands no other, and one that
    /// is handed is refused, with nothing shown.
    fn of(handed: &Value, own: &[u8; 32]) -> anyhow::Result<Self> {
        names_this_device(handed, own)?;
        let applied = SignedStatement::from_bytes(&hex::decode(text(handed, "statement"))?)?;
        applied.verify()?;
        let mut heads = Vec::new();
        for head in list(handed, "heads") {
            let statement = SignedStatement::from_bytes(&hex::decode(text(head, "statement"))?)?;
            statement.verify()?;
            if statement.statement.phrase_key != applied.statement.phrase_key {
                anyhow::bail!(
                    "the node handed a change set aside under another phrase than the one this \
                     device follows. Nothing was done."
                );
            }
            let entry = entry_of(text(head, "entry"))?;
            // What it is named by is worked out here, from the entry.
            let named = hex::encode(entry.id());
            heads.push((statement, entry, named));
        }
        let mut removed: Vec<[u8; 32]> = Vec::new();
        for key in list(handed, "removed") {
            let key = decode_public_key(key.as_str().unwrap_or_default()).map_err(|e| {
                anyhow::anyhow!("the node handed a removed key that is no key: {e}")
            })?;
            if key == *own {
                anyhow::bail!(
                    "this device was removed: a change of the recovery phrase that it has seen \
                     removes it. `cordelia init --new-key` gives it a new key; it is then added \
                     as a new device."
                );
            }
            removed.push(key);
        }
        removed.sort_unstable();
        removed.dedup();
        // Each record, read from its signed bytes: its adder signed it,
        // and it names the statement that the device has applied.
        let under = applied.statement.link()?;
        let record_of = |kept: &Value| -> anyhow::Result<SignedAddition> {
            let record =
                SignedAddition::from_bytes(&hex::decode(kept.as_str().unwrap_or_default())?)?;
            record.verify()?;
            if record.addition.under != under {
                anyhow::bail!(
                    "the node handed a record of an addition that is made under another change \
                     than the one this device has applied. Nothing was done."
                );
            }
            Ok(record)
        };
        let asked_about: Vec<SignedAddition> = list(handed, "additions")
            .map(record_of)
            .collect::<anyhow::Result<_>>()?;
        let standing: Vec<SignedAddition> = list(handed, "standing")
            .map(record_of)
            .collect::<anyhow::Result<_>>()?;
        // The keys that a device of the statement added, by any of them.
        let added_by_a_listed: Vec<[u8; 32]> = asked_about
            .iter()
            .chain(&standing)
            .filter(|record| applied.statement.lists(&record.addition.adder))
            .map(|record| record.addition.device.key)
            .collect();
        let mut added: Vec<SignedAddition> = Vec::new();
        for record in asked_about {
            let adder = record.addition.adder;
            if !applied.statement.lists(&adder) && !added_by_a_listed.contains(&adder) {
                anyhow::bail!(
                    "the node handed a record of an addition whose adder is no device of the \
                     last change, and was added by none. Nothing was done."
                );
            }
            let key = record.addition.device.key;
            let known = applied.statement.lists(&key)
                || applied.statement.removes(&key)
                || added.iter().any(|other| other.addition.device.key == key);
            if !known {
                added.push(record);
            }
        }
        let left: Vec<[u8; 32]> = list(handed, "left")
            .filter_map(|key| decode_public_key(key.as_str()?).ok())
            .collect();
        // A name is shown at the prompt, just before the yes and the
        // phrase. Only what is a name as this version would map one is
        // read as one (decision 2026-10-04 §16): a node hands no other,
        // and one that is handed is counted for the keys that list it,
        // and not kept.
        let (mut names, mut names_not_shown) = (Vec::new(), Vec::new());
        for listed in list(handed, "names") {
            let by: Vec<[u8; 32]> = list(listed, "by")
                .filter_map(|key| decode_public_key(key.as_str()?).ok())
                .collect();
            match cordelia_api::names::is_a_name(text(listed, "name")) {
                true => names.push((text(listed, "name").to_string(), by)),
                false => names_not_shown.extend(by.into_iter().map(|key| (key, 1))),
            }
        }
        for listed in list(handed, "names_not_shown") {
            let key = listed["by"]
                .as_str()
                .and_then(|key| decode_public_key(key).ok());
            if let (Some(key), Some(words)) = (key, listed["words"].as_u64()) {
                names_not_shown.push((key, words as usize));
            }
        }
        let received = handed["received"].as_object().map(|by_device| {
            by_device
                .iter()
                .filter_map(|(key, n)| {
                    let key = decode_public_key(key).ok()?;
                    Some((key, n["day"].as_u64()?, n["week"].as_u64()?))
                })
                .collect()
        });
        // What the prompt is shown over is worked out here, from the
        // entry that was handed, and is not the node's word of it (§16).
        let held = entry_of(text(handed, "entry"))?;
        let over = hex::encode(held.id());
        Ok(Self {
            this_device: *own,
            applied,
            held,
            over,
            heads,
            removed,
            added,
            left,
            names,
            names_not_shown,
            received,
        })
    }

    /// How much the device whose key is `key` has written that this
    /// device received, in the last day and in the last week, in words
    /// (decision 2026-10-04 §7.1, step 2).
    fn received_from(&self, key: &[u8; 32]) -> String {
        let Some(received) = &self.received else {
            return "Local history is off on this device, so it cannot say how much that device \
                    wrote that arrived here."
                .into();
        };
        let (day, week) = received
            .iter()
            .find(|(device, _, _)| device == key)
            .map_or((0, 0), |(_, day, week)| (*day, *week));
        format!(
            "Of what it wrote, this device received {} in the last day, and {} in the last week.",
            counted(day as usize, "version"),
            counted(week as usize, "version")
        )
    }

    /// The names that only keys which `removed` says go have listed
    /// (decision 2026-10-04 §7.1, step 2): each stays behind, with what
    /// was written in it.
    fn names_only_of(&self, removed: impl Fn(&[u8; 32]) -> bool) -> Vec<&str> {
        self.names
            .iter()
            .filter(|(_, by)| !by.is_empty() && by.iter().all(&removed))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// How many things the keys which `removed` says go list as names
    /// that are no names (decision 2026-10-04 §16): they are said as a
    /// number, and never shown.
    fn names_not_shown_of(&self, removed: impl Fn(&[u8; 32]) -> bool) -> usize {
        self.names_not_shown
            .iter()
            .filter(|(key, _)| removed(key))
            .map(|(_, words)| words)
            .sum()
    }

    /// Whether the device knows `key` to be removed, on any branch: the
    /// node handed it as removed (decision 2026-10-24 (removal), rule 20).
    fn knows_removed(&self, key: &[u8; 32]) -> bool {
        self.removed.binary_search(key).is_ok()
    }

    /// The label that this device knows `key` by: the statement's, a
    /// head's, or that of the record that added it.
    fn label(&self, key: &[u8; 32]) -> String {
        let listed = |statement: &Statement| {
            statement
                .devices
                .iter()
                .find(|device| device.key == *key)
                .map(|device| device.label.clone())
        };
        listed(&self.applied.statement)
            .or_else(|| {
                self.heads
                    .iter()
                    .find_map(|(head, _, _)| listed(&head.statement))
            })
            .or_else(|| {
                let record = self.added.iter().find(|r| r.addition.device.key == *key)?;
                Some(record.addition.device.label.clone())
            })
            .unwrap_or_default()
    }
}

/// What a removal says of the things that a device being removed lists
/// as names and that are no names as this version would map one: how
/// many, and nothing of what they hold.
fn not_shown_stay_behind(how_many: usize) -> String {
    format!(
        "{} that cannot be shown {} behind too: a device that is removed listed {}, and what \
         {} called is not a name as this version writes one.",
        counted(how_many, "name"),
        if how_many == 1 { "stays" } else { "stay" },
        if how_many == 1 { "it" } else { "them" },
        if how_many == 1 { "it is" } else { "they are" },
    )
}

/// What a person answers of one device at a change.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Stays,
    Removed,
    /// In no list: only at a settlement.
    Neither,
}

/// What a command that makes a change asks a person, and what they type
/// ([`Terminal::answer`]): its questions are asked through this, so that a
/// test can answer them.
trait Answers {
    /// Ask, and read a line typed back: `None` where the input ended.
    fn answer(&self, asks: &str) -> anyhow::Result<Option<String>>;
}

impl Answers for Terminal {
    fn answer(&self, asks: &str) -> anyhow::Result<Option<String>> {
        Terminal::answer(self, asks)
    }
}

/// Ask whether a device stays or is removed. **No answer is suggested:
/// each is typed** (decision 2026-10-04 §6), and pressing Enter answers
/// nothing. `neither` says that the third answer is on offer: the device
/// is in no list.
///
/// Where the input ends at the question, the command is refused: nothing
/// is made of an answer that nobody typed.
fn asks_of(at: &impl Answers, says: &str, neither: bool) -> anyhow::Result<Answer> {
    let third = match neither {
        true => ", or `neither` (it is in no list, and is added again by hand)",
        false => "",
    };
    loop {
        let typed = at.answer(&format!("{says}\n  Type `stays` or `removed`{third}: "))?;
        match typed.as_deref() {
            Some("stays") => return Ok(Answer::Stays),
            Some("removed") => return Ok(Answer::Removed),
            Some("neither") if neither => return Ok(Answer::Neither),
            Some(_) => println!("  That is none of the answers. No answer is suggested: type one."),
            None => anyhow::bail!("the input ended before an answer was typed. Nothing was made."),
        }
    }
}

/// One device that a person is asked about at a removal or a renewal.
struct Question {
    /// The device, as the change lists it where it stays.
    device: Device,
    /// What is said of it before the answer is asked.
    says: String,
}

/// What is said of a device that has said that it left.
const SAID_IT_LEFT: &str = "It has said that it left, and started again under another phrase: \
                            it still holds what it held";

/// The devices that a person is asked about at a removal or a renewal,
/// in the order they are asked (decision 2026-10-04 §6, §7.1): each
/// device of the last change that has said that it left, and then each
/// device added since the last change, with who added it and when.
/// `goes` is the key that the change removes, where it removes one.
///
/// **A device is asked about before the devices that it added:** what a
/// person says of the one bears on what they say of the others. A chain
/// is two long at most, so those that a device of the statement added
/// come first, and those that such a device added after them, each in
/// the order the node handed them. This device and the one that goes
/// are asked about by neither.
fn questions(handed: &Handed, goes: Option<[u8; 32]>) -> Vec<Question> {
    let own = handed.this_device;
    let added_since = |key: &[u8; 32]| handed.added.iter().any(|r| r.addition.device.key == *key);
    let (first, after): (Vec<&SignedAddition>, Vec<&SignedAddition>) = handed
        .added
        .iter()
        .partition(|record| !added_since(&record.addition.adder));
    let mut asked = Vec::new();
    // A device of the last change that has said that it left is shown as
    // that: its word is kept across a change for as long as its key is
    // listed and nobody has cleared it.
    for device in &handed.applied.statement.devices {
        let key = device.key;
        let skip = key == own || Some(key) == goes || handed.knows_removed(&key);
        if skip || !handed.left.contains(&key) {
            continue;
        }
        asked.push(Question {
            device: device.clone(),
            says: format!(
                "\n{}, a device of the last change. {SAID_IT_LEFT}:",
                named(&device.label, &key)
            ),
        });
    }
    for record in first.into_iter().chain(after) {
        let added = &record.addition;
        let key = added.device.key;
        if key == own || Some(key) == goes || handed.knows_removed(&key) {
            continue;
        }
        let says = format!(
            "\n{}, added since the last change, from {} at {}{}{}:",
            named(&added.device.label, &key),
            named(&handed.label(&added.adder), &added.adder),
            time_of(added.at),
            match Some(added.adder) == goes {
                true => ". It was added by the device that is being removed",
                false => "",
            },
            match handed.left.contains(&key) {
                true => format!(". {SAID_IT_LEFT}"),
                false => String::new(),
            }
        );
        asked.push(Question {
            device: added.device.clone(),
            says,
        });
    }
    asked
}

/// The devices of the last change that stay with nothing asked: each but
/// the one that goes, but those that a person is asked about, and but
/// each that the device knows to be removed on another branch (decision
/// 2026-10-24 (removal), rule 20), which the change lists as removed.
fn stays_unasked(handed: &Handed, goes: Option<[u8; 32]>, asked: &[Question]) -> Vec<Device> {
    let is_asked = |key: &[u8; 32]| asked.iter().any(|question| question.device.key == *key);
    handed
        .applied
        .statement
        .devices
        .iter()
        .filter(|device| Some(device.key) != goes && !is_asked(&device.key))
        .filter(|device| !handed.knows_removed(&device.key))
        .cloned()
        .collect()
}

/// Make a change (see the module's documentation): what the node
/// prepared is shown, a person answers, the lists are shown from the
/// bytes that will be signed, and then the yes and the phrase. Where a
/// statement arrived meanwhile, nothing is made and it asks again.
fn change(config_path: &str, at: &Terminal, which: &Which) -> anyhow::Result<()> {
    let settles = matches!(which, Which::Settle);
    loop {
        println!(
            "Showing each relay the last change, and fetching what the relays hold (two \
             minutes at most)..."
        );
        let handed = api_post_told(
            config_path,
            "/api/v1/change/prepare",
            json!({ "settle": settles }),
            Some(Duration::from_secs(CHANGE_FETCH_MAX_SECS + 30)),
        )?;
        let handed = match handed {
            Told::Yes(handed) => handed,
            Told::No { message, .. } => anyhow::bail!("{message}"),
        };
        for line in list(&handed, "could_not_fetch") {
            println!("  Could not fetch: {}.", line.as_str().unwrap_or_default());
        }
        let handed = Handed::of(&handed, &own_key(config_path)?)?;
        let prepared = asked(at, &handed, which)?;

        // The lists, from the bytes that the phrase will sign.
        let signs = Statement::from_bytes(prepared.bytes())?;
        println!(
            "\nThe change that the recovery phrase will sign (change {}):",
            signs.number
        );
        for line in lists_shown(&signs, &handed)? {
            println!("{line}");
        }
        // Each name that only a device being removed syncs.
        let stay_behind = handed.names_only_of(|key| signs.removes(key));
        if !stay_behind.is_empty() {
            println!(
                "\nThese names stay behind, with what was written in them: {}.\nMap one on \
                 another device first if you want it; after the removal it is brought in only \
                 with the phrase.",
                stay_behind.join(", ")
            );
        }
        let not_shown = handed.names_not_shown_of(|key| signs.removes(key));
        if not_shown > 0 {
            println!("\n{}", not_shown_stay_behind(not_shown));
        }
        if !at.yes("\nMake this change?")? {
            println!("{NOT_A_YES}");
            return Ok(());
        }
        let entry = signed(at, prepared, &handed)?;

        // The phrase is dropped: the node is handed the entry.
        let made = api_post_told(
            config_path,
            "/api/v1/change/make",
            json!({
                "entry": hex::encode(entry.to_wire()),
                "over": handed.over,
                "heads": handed.heads.iter().map(|(_, _, id)| id.clone()).collect::<Vec<_>>(),
            }),
            Some(Duration::from_secs(60)),
        );
        // Where the answer was lost, the node may have made the change
        // all the same: it is asked again before anything is said of it
        // (§16).
        let made = match made {
            Ok(told) => told,
            Err(lost) => {
                println!("\n{lost}\nThe node's answer was lost. Asking it again...");
                match made_all_the_same(config_path, &entry.id()) {
                    true => Told::Yes(json!({ "change": signs.number })),
                    false => anyhow::bail!(
                        "it is not known whether the node made the change: it does not say \
                         that it has applied change {} so far, and it may still. Do not make \
                         it again, here or on another device, until `cordelia devices` shows \
                         the last change that this device has applied: two changes made apart \
                         have to be settled with the phrase.",
                        signs.number
                    ),
                }
            }
        };
        match made {
            Told::Yes(made) => {
                let number = made["change"].as_u64().unwrap_or(signs.number);
                for file in list(&made, "not_carried") {
                    println!(
                        "  What this device held of {} in {} could not be read, and was not \
                         carried: it meets its channel as a new file does.",
                        file_shown(text(file, "file")),
                        file_shown(text(file, "name"))
                    );
                }
                println!(
                    "\nThe change is made (change {number}). It must not be made again on \
                     another device, even if this command is stopped now: two changes made \
                     apart have to be settled with the phrase."
                );
                return stays_in_a_new_process(config_path, number, &entry.id());
            }
            // A statement arrived between the prompt and the phrase:
            // nothing was made, and it asks again.
            Told::No {
                status: 409,
                message,
            } => {
                println!(
                    "\n{message}\nA change reached this device while you were answering. \
                          This asks again, with what it holds now.\n"
                );
            }
            Told::No { message, .. } => anyhow::bail!("{message}\nNothing was made."),
        }
    }
}

/// Show what the node handed, ask of each device what a person has to
/// say of it, and prepare the statement, with no phrase.
///
/// **Every key that the device knows to be removed is listed as removed,
/// and none as a device** (decision 2026-10-24 (removal), rule 20): those
/// the node handed are shown, and are neither asked about nor kept. **A
/// change made where a head is set aside joins every head** (rule 21):
/// `remove-device` and `renew` there make a settlement, as `settle` does.
fn asked(at: &impl Answers, handed: &Handed, which: &Which) -> anyhow::Result<Prepared> {
    let own = handed.this_device;
    let applied = &handed.applied.statement;
    let mut stay: Vec<Device> = Vec::new();
    let mut removed: Vec<[u8; 32]> = Vec::new();

    // A removal names the key that goes, whatever else the change joins.
    let goes = match which {
        Which::Remove(key) => Some(*key),
        _ => None,
    };
    if let Some(goes) = goes {
        if goes == own {
            anyhow::bail!(
                "that is this device's own key. The device that makes a change is always among \
                 its devices: remove this device from another that stays."
            );
        }
        if applied.removes(&goes) || handed.knows_removed(&goes) {
            anyhow::bail!("that key was removed already, by an earlier change.");
        }
        let known = applied.lists(&goes)
            || handed
                .heads
                .iter()
                .any(|(head, _, _)| head.statement.lists(&goes))
            || handed.added.iter().any(|r| r.addition.device.key == goes);
        match known {
            true => {
                println!("\nTo be removed: {}.", named(&handed.label(&goes), &goes));
                println!("  {}", handed.received_from(&goes));
            }
            // A key that this device knows nothing of is removed by key
            // (decision 2026-10-04 §10): a key that is in no list is not
            // refused by anything, and could be added by the two
            // commands. A person who wants it refused removes it once.
            false => refuses_a_key_it_does_not_know(at, &goes)?,
        }
        removed.push(goes);
    }
    // The keys removed on another branch, which this change lists too.
    let elsewhere: Vec<&[u8; 32]> = handed
        .removed
        .iter()
        .filter(|key| !applied.removes(key))
        .collect();
    if !elsewhere.is_empty() {
        println!(
            "\nThis device knows {} to be removed by a change made apart from the one it \
             follows. The change lists {} as removed too, and no device that was removed is \
             in it:",
            counted(elsewhere.len(), "key"),
            if elsewhere.len() == 1 { "it" } else { "each" }
        );
        for key in &elsewhere {
            println!("  {}", named(&handed.label(key), key));
        }
    }
    removed.extend(handed.removed.iter().copied());

    if handed.heads.is_empty() {
        if let Which::Settle = which {
            anyhow::bail!("this device has seen no two changes made apart: nothing to settle.");
        }
        // A removal, or a renewal.
        let asked = questions(handed, goes);
        stay.extend(stays_unasked(handed, goes, &asked));
        if !applied.lists(&own) {
            // This device was added since: the device that makes a
            // statement is always among its devices, whoever added it.
            stay.push(own_listing(at, handed, false)?);
        }
        if !asked.is_empty() {
            println!(
                "\nOf each of these, say whether it stays or is removed. No answer is suggested \
                 for any of them: each is typed."
            );
        }
        for question in asked {
            match asks_of(at, &question.says, false)? {
                Answer::Stays => stay.push(question.device),
                Answer::Removed => removed.push(question.device.key),
                Answer::Neither => {}
            }
        }
        return Ok(prepare_change(&handed.applied, &own, stay, &removed)?);
    }

    // A settlement: the change followed and every head set aside.
    let heads: Vec<&Statement> = std::iter::once(applied)
        .chain(handed.heads.iter().map(|(head, _, _)| &head.statement))
        .collect();
    println!(
        "\n{} changes were made apart. Each is shown from its signed bytes.",
        heads.len()
    );
    for (n, statement) in heads.iter().enumerate() {
        let says = match n {
            0 => "this device follows",
            _ => "set aside",
        };
        println!("\nChange {} ({says}):", statement.number);
        for line in lists_shown(statement, handed)? {
            println!("{line}");
        }
    }
    println!(
        "\nThis change joins them: it is numbered above each, and undoes no removal: every key \
         that any removed stays removed. Of each other device of any, say whether it stays, is \
         removed, or is neither: one that is neither is in no list, and is added again by hand. \
         Each device added since under the change this device follows is asked about too. A \
         device added under a change set aside since it was made is not known here, and is in no \
         list."
    );
    let gone = |key: &[u8; 32]| {
        Some(*key) == goes
            || handed.knows_removed(key)
            || heads.iter().any(|statement| statement.removes(key))
    };
    let mut each: Vec<&Device> = Vec::new();
    for device in heads.iter().flat_map(|statement| statement.devices.iter()) {
        if !gone(&device.key) && !each.iter().any(|seen| seen.key == device.key) {
            each.push(device);
        }
    }
    for device in each {
        if device.key == own {
            stay.push(device.clone());
            continue;
        }
        let listing = heads
            .iter()
            .filter(|statement| statement.lists(&device.key));
        let of = match (listing.count(), applied.lists(&device.key)) {
            (n, _) if n == heads.len() => "every change shown",
            (_, true) => "the change this device follows",
            (_, false) => "a change set aside",
        };
        let says = format!(
            "\n{}, a device of {of}{}:",
            named(&device.label, &device.key),
            match handed.left.contains(&device.key) {
                true => format!(". {SAID_IT_LEFT}"),
                false => String::new(),
            }
        );
        match asks_of(at, &says, true)? {
            Answer::Stays => stay.push(device.clone()),
            Answer::Removed => removed.push(device.key),
            Answer::Neither => {}
        }
    }
    // Each device added since under the change followed, by a record that
    // counts, is asked about as at a renewal, with the third answer: no
    // change shown lists it, and a change made here would otherwise leave
    // it in no list.
    for question in questions(handed, goes) {
        let key = question.device.key;
        if gone(&key) || heads.iter().any(|statement| statement.lists(&key)) {
            continue;
        }
        match asks_of(at, &question.says, true)? {
            Answer::Stays => stay.push(question.device),
            Answer::Removed => removed.push(key),
            Answer::Neither => {}
        }
    }
    if !stay.iter().any(|device| device.key == own) {
        stay.insert(0, own_listing(at, handed, true)?);
    }
    let joined: Vec<SignedStatement> = handed
        .heads
        .iter()
        .map(|(head, _, _)| head.clone())
        .collect();
    Ok(prepare_settlement(
        &handed.applied,
        &joined,
        &own,
        stay,
        &removed,
    )?)
}

/// What `cordelia remove-device` says of a key that is in no list of the
/// last change and was not added since (decision 2026-10-04 §10).
const NO_DEVICE_IT_KNOWS: &str = "is no device of yours that this device knows of: it is in no \
    list of the last change, and was not added since (`cordelia devices` lists those, each with \
    its key).";

/// What removing such a key does, said before its answer is asked.
const REFUSED_FOR_GOOD: &str = "Removing it refuses that key for good: the change lists it among \
    its removed keys, no device of yours adds it after that, and no later change brings it back. \
    That is for a key that was one of your devices before every device was added again, and \
    that is not to be added.";

/// The answer that removes a key which this device does not know.
const REFUSES_THE_KEY: &str = "refuse";

/// `cordelia remove-device` was given the key `goes`, which this device
/// knows nothing of (decision 2026-10-04 §10): it says that this is no
/// device it knows of, and that removing it refuses that key for good,
/// and asks a typed answer before anything else. **No answer is
/// suggested:** pressing Enter answers nothing, and anything but the one
/// word stops the command, with nothing made.
///
/// The change then goes on as any removal: the key is among the removed
/// keys of the statement that is shown, before the yes and the phrase.
///
/// **A key that is no device's key at all is refused** (decision
/// 2026-10-04 §2.2): a point under which anyone can sign, and to which
/// nothing can be sealed, is added by nothing, so there is nothing of it
/// to refuse, and no statement lists it.
fn refuses_a_key_it_does_not_know(at: &impl Answers, goes: &[u8; 32]) -> anyhow::Result<()> {
    if !cordelia_crypto::identity::is_usable_public_key(goes) {
        anyhow::bail!(
            "that key is no device's key, and no device of yours: nothing is added under it, \
             so there is nothing to refuse. Nothing was done."
        );
    }
    println!(
        "\nThe key ({}) {NO_DEVICE_IT_KNOWS}",
        fingerprint::shown(goes)
    );
    println!("  {REFUSED_FOR_GOOD}");
    let typed = at.answer(&format!(
        "  Type `{REFUSES_THE_KEY}` to refuse this key for good, or anything else to stop: "
    ))?;
    match typed.as_deref() {
        Some(REFUSES_THE_KEY) => Ok(()),
        Some(_) => anyhow::bail!("That was not `{REFUSES_THE_KEY}`. Nothing was done."),
        None => anyhow::bail!("the input ended before an answer was typed. Nothing was made."),
    }
}

/// The answer that lists this device in the change it makes, where the
/// change it applied does not list it (decision 2026-10-24, rule 1).
const LISTS_THIS_MACHINE: &str = "list";

/// This device as a change will list it, where the statement applied
/// does not: it was added since (decision 2026-10-04 §6, §16). It is
/// shown as an addition is, from the record of its own addition, with who
/// added it and when, and a person confirms its listing by a typed
/// answer, told what a change is and what each answer does (decision
/// 2026-10-24, rule 1). The label it is listed under is the one in that
/// record. `settles` is whether the change is a settlement.
///
/// Refused where no record of its addition was handed: a device that is
/// in no list and was added by nobody makes no change. Any answer but the
/// one word stops the command, with nothing changed.
fn own_listing(at: &impl Answers, handed: &Handed, settles: bool) -> anyhow::Result<Device> {
    let (says, device) = own_addition(handed, settles)?;
    let typed = at.answer(&format!(
        "{says}\n  Type `{LISTS_THIS_MACHINE}` to list this machine and go on. Anything else \
         stops here, and nothing is changed: "
    ))?;
    match typed.as_deref() {
        Some(LISTS_THIS_MACHINE) => Ok(device),
        Some(_) => anyhow::bail!("You did not type `{LISTS_THIS_MACHINE}`. Nothing was changed."),
        None => anyhow::bail!("The input ended before you typed an answer. Nothing was changed."),
    }
}

/// The number of the change that this command makes (decision 2026-10-04
/// §4.5): one above the change applied for a renewal or a removal, and
/// one above the highest of the heads for a settlement (`settles`), which
/// any change made where a head is set aside is (decision 2026-10-24
/// (removal), rule 21). It is the number that "The change that the
/// recovery phrase will sign" shows next (decision 2026-10-24, rule 1).
fn next_change(handed: &Handed, settles: bool) -> u64 {
    let applied = handed.applied.statement.number;
    let highest = handed
        .heads
        .iter()
        .map(|(head, _, _)| head.statement.number)
        .fold(applied, u64::max);
    match settles && !handed.heads.is_empty() {
        true => highest + 1,
        false => applied + 1,
    }
}

/// What [`own_listing`] shows of this device, and the device as the
/// record of its addition has it: what a change is, why the last change,
/// or neither of the two of a settlement, does not list this machine, who
/// added it and when, and the change that this command makes, which lists
/// it (decision 2026-10-24, rule 1).
fn own_addition(handed: &Handed, settles: bool) -> anyhow::Result<(String, Device)> {
    let own = handed.this_device;
    let Some(record) = handed
        .added
        .iter()
        .find(|record| record.addition.device.key == own)
    else {
        anyhow::bail!(
            "this device is not in the last change, and no record of its addition counts \
             here: it makes no change. Add it again from a device that is in the last change."
        );
    };
    let added = &record.addition;
    let applied = &handed.applied.statement;
    let this = named(&added.device.label, &own);
    let new = next_change(handed, settles);
    let (signed_before, makes) = match (handed.heads.as_slice(), settles) {
        ([(apart, _, _)], true) => (
            format!(
                "Neither change {} nor change {} lists this machine: both were made without it.",
                applied.number, apart.statement.number
            ),
            format!("This command makes change {new}, which settles the two."),
        ),
        ([_, ..], true) => (
            format!(
                "None of the {} changes made apart lists this machine: each was made without \
                 it.",
                handed.heads.len() + 1
            ),
            format!("This command makes change {new}, which joins them."),
        ),
        _ => (
            format!(
                "Your last change (change {}, made on {}) was signed before this machine was \
                 added, so it does not list this machine.",
                applied.number,
                lists_of(applied)?.made_on.named()
            ),
            format!("This command makes change {new}."),
        ),
    };
    let says = format!(
        "\nA change is the list of your devices that your recovery phrase signs.\n\
         {signed_before} {} added this machine at {}, as {this}.\n\
         {makes} The machine that makes a change is always in it, so change {new} will list \
         this machine as {this}.",
        named(&handed.label(&added.adder), &added.adder),
        time_of(added.at)
    );
    Ok((says, added.device.clone()))
}

/// A statement's lists, a line each, read from the statement: each key
/// with the first four words of its fingerprint. A removed key is listed
/// bare in a statement, and is shown beside the label that this device
/// knew it by.
fn lists_shown(statement: &Statement, handed: &Handed) -> anyhow::Result<Vec<String>> {
    let lists = lists_of(statement)?;
    let mut out = vec![format!("  made on {}", lists.made_on.named())];
    out.push(format!("  devices ({}):", lists.devices.len()));
    for (device, listed) in lists.devices.iter().zip(&statement.devices) {
        let own = match listed.key == handed.this_device {
            true => "  (this device)",
            false => "",
        };
        out.push(format!("    {}{own}", device.named()));
    }
    let before = &handed.applied.statement;
    let newly: Vec<&[u8; 32]> = statement
        .removed
        .iter()
        .filter(|key| !before.removes(key) || statement.number <= before.number)
        .collect();
    let earlier = statement.removed.len() - newly.len();
    if !newly.is_empty() {
        out.push(format!("  removed keys ({}):", newly.len()));
    }
    for key in newly {
        let known = match handed.label(key) {
            label if label.is_empty() => String::new(),
            label => format!(", known here as {label:?}"),
        };
        out.push(format!("    ({}){known}", fingerprint::shown(key)));
    }
    if earlier > 0 {
        out.push(format!(
            "  and the {earlier} key{} that earlier changes removed",
            if earlier == 1 { "" } else { "s" }
        ));
    }
    Ok(out)
}

/// Ask for the recovery phrase at the terminal: twelve words, each asked
/// for by its number and typed with echo off. It is the one way that a
/// command reads a phrase that is to be proved.
///
/// **Nothing is said of any word but that it is a word of the list**
/// (decision 2026-10-04 §16): this has nothing to hold a word against,
/// and the phrase is judged only when all twelve are typed
/// ([`Terminal::phrase`]).
///
/// A mistyped phrase is told from a wrong one: words that are no
/// recovery phrase fail its checksum, and may be typed again, three times
/// in all. What is given back is overwritten when it is dropped.
pub(crate) fn typed_phrase(at: &Terminal) -> anyhow::Result<Phrase> {
    let mut tries = 0;
    loop {
        tries += 1;
        let typed = at.phrase(
            "\nType your recovery phrase, one word at a time. What you type is not shown.",
        )?;
        match Phrase::parse(&typed) {
            Ok(phrase) => return Ok(phrase),
            Err(e) if tries < PHRASE_TRIES => {
                let why = match e {
                    PhraseError::Checksum => {
                        "these words are not a recovery phrase: at least one of them is not \
                         the word it was"
                            .to_string()
                    }
                    other => other.to_string(),
                };
                println!("{why}. It was mistyped: nothing was made. Type it again.");
            }
            Err(e) => anyhow::bail!("{e}. It was mistyped: nothing was made."),
        }
    }
}

/// Ask for the recovery phrase, and sign and seal with it what was
/// shown. The phrase is in this function and nowhere else: it is typed
/// with echo off, signs the statement, seals the part of the change
/// entry that is for it, signs the entry, and is dropped, and
/// overwritten, as this returns.
///
/// A mistyped phrase is told from a wrong one: words that are no
/// recovery phrase fail its checksum, and may be typed again. A phrase
/// that is one, and not the one that this device follows, makes nothing.
fn signed(at: &Terminal, prepared: Prepared, handed: &Handed) -> anyhow::Result<CheckedEntry> {
    let phrase = typed_phrase(at)?;
    let joined: Vec<&CheckedEntry> = handed.heads.iter().map(|(_, entry, _)| entry).collect();
    match prepared.sign(&phrase, &handed.held, &joined) {
        Ok(entry) => Ok(entry),
        Err(PersonError::Statement(StatementError::AnotherPhrase)) => anyhow::bail!(
            "that is a recovery phrase, and it is not the one that this device follows: \
             nothing was made."
        ),
        Err(e) => anyhow::bail!("{e}: nothing was made."),
    }
}

/// The command that a change goes on to when it is made: [`stays`], in a
/// process of its own.
pub const STAYS_COMMAND: &str = "change-made";

/// The exit status of a command whose change is made, and is not known to
/// be at every relay (decision 2026-10-19 §4, rule 8): its wait ended not
/// done, or could not be started or go on, or the device has since
/// applied another change. 1 is what `main` gives for an error, and 2 what
/// the argument parser gives: neither is given once a change is made.
pub const NOT_AT_EVERY_RELAY_STATUS: i32 = 3;

/// Go on to the wait that follows a change ([`stays`]) in a new image of
/// this program, which takes the place of this one (decision 2026-10-04
/// §16): the memory that held the phrase, and signed with it, is gone
/// when the wait begins, and the process that waits never held it.
///
/// What this process has said is written out first. Where the program
/// cannot be run again (it was replaced where it lay, say), nothing waits
/// in this process: the command says where to look, and ends.
fn stays_in_a_new_process(config_path: &str, number: u64, made: &[u8; 32]) -> anyhow::Result<()> {
    use std::io::Write;
    // The change is made: a failure from here on gives the status of a
    // change not known to be at every relay, and never 1 (decision
    // 2026-10-19 §4, rule 8).
    if let Err(e) = std::io::stdout().flush() {
        eprintln!("{}", wait::could_not_go_on(number, &e.into()));
        std::process::exit(NOT_AT_EVERY_RELAY_STATUS);
    }
    #[cfg(unix)]
    let failed = {
        use std::os::unix::process::CommandExt;
        match std::env::current_exe() {
            Ok(program) => std::process::Command::new(program)
                .arg("--config")
                .arg(config_path)
                .arg(STAYS_COMMAND)
                .arg(number.to_string())
                .arg("--entry")
                .arg(hex::encode(made))
                .exec(),
            Err(e) => e,
        }
    };
    #[cfg(not(unix))]
    let failed = "it runs on a Unix system";
    let (said, status) = wait_not_started(&failed);
    println!("{said}");
    std::process::exit(status)
}

/// What a command says where its wait after a change cannot be started,
/// and its exit status: the change is made, and is not known to be at
/// every relay (decision 2026-10-19 §4, rule 8).
fn wait_not_started(failed: &dyn std::fmt::Display) -> (String, i32) {
    (
        format!(
            "This command could not go on to say what is still missing ({failed}). The node \
             goes on by itself: `cordelia devices` shows whether each relay holds the change, \
             and what this device has still to send. Keep this machine on until every relay \
             holds the change and nothing is left to send."
        ),
        NOT_AT_EVERY_RELAY_STATUS,
    )
}

/// How the wait after a change ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Waited {
    /// At one of its three ends (decision 2026-10-19 §4, rule 8).
    Ended(wait::End),
    /// The device has since applied another change: whether that one is
    /// at every relay is the business of the command that made it.
    Another,
    /// The device moved from this change, with no phrase, to a change made
    /// apart that is clear (decision 2026-10-24 (removal), rule 9).
    Moved,
    /// The device no longer stands in its phrase
    /// ([`wait::no_longer_stands`]).
    NoLongerStands,
}

/// The exit status of the wait after a change, as it ended (decision
/// 2026-10-19 §4, rule 8): 0 only at ends 1 and 2; 3 at end 3, where the
/// device has since applied another change, moved from this one (decision
/// 2026-10-24 (removal), rule 9) or no longer stands in its phrase, and on
/// any error during the wait.
fn status_of(waited: &anyhow::Result<Waited>) -> i32 {
    match waited {
        Ok(Waited::Ended(end)) => end.status(),
        Ok(Waited::Another | Waited::Moved | Waited::NoLongerStands) | Err(_) => {
            NOT_AT_EVERY_RELAY_STATUS
        }
    }
}

/// `cordelia change-made <number> --entry <id>`: what `remove-device`,
/// `renew` and `settle` go on to once the change numbered so, whose change
/// entry `made` names in hex, is made ([`stays`]). It asks nothing, and
/// holds no phrase. Gives the command's exit status ([`status_of`]): an
/// error during the wait is said on standard error first, with that the
/// change is made.
pub fn change_made(config_path: &str, number: u64, made: Option<&str>) -> i32 {
    let waited = stays(config_path, number, made);
    if let Err(e) = &waited {
        eprintln!("{}", wait::could_not_go_on(number, e));
    }
    status_of(&waited)
}

/// What a look says after the change numbered `number`, in lines, as the
/// wait after it goes on (decision 2026-10-04 §7.1, step 4; §8; decision
/// 2026-10-19 §5). `now` is the time of day, for what is said of a relay
/// out of reach. The wait ends by the classes of its relays
/// ([`wait::end_of`]), not by these lines: each says what is missing.
///
/// - **For each relay,** whether it holds the change, as the node knows it
///   (decision 2026-10-19 §1). One that is out of reach says so, and
///   since when (S2, S3). One that is waited out says each minute for how
///   long (decision 2026-10-24, rule 4: [`wait::count_line`]).
/// - **What waits to be sent there** is known only while the node is
///   connected to it: a relay that is not reached, and is not out of
///   reach, is said to be missing, whatever it last said it holds. That is
///   each relay that the node names as not reached, and any relay for
///   which there is no row of what waits.
/// - **What this device has still to send,** as names, and its own word
///   that it has sent what it carried: it writes that once nothing that it
///   carried waits at any relay it is set up with, with every one of them
///   connected.
/// - **Each other device,** and whether it has applied the change.
fn after_a_change(seen: &Value, number: u64, own: &[u8; 32], now_at: i64) -> Vec<String> {
    let mut now: Vec<String> = Vec::new();
    // A look whose relays cannot be read ends the wait as an error before
    // its lines are said ([`wait::end_of_look`]).
    let mut relays = wait::relays_of(seen).unwrap_or_default();
    // What is known of a relay from before the change says nothing of it.
    for relay in &mut relays {
        if !wait::is_about_the_kept_entry(relay, seen) {
            relay.reach = None;
        }
    }
    let set_up = relays.len();
    if relays.is_empty() {
        now.push("keep this machine on: no relay is reached yet".into());
    }
    for relay in &relays {
        let name = &relay.name;
        now.push(match (relay.out_of_reach(), relay.holds()) {
            (true, _) => wait::out_of_reach_line(relay, now_at),
            (false, true) => format!("{name} holds the change"),
            (false, false) => format!("keep this machine on: {name} does not hold the change yet"),
        });
        // The count while it is waited out (decision 2026-10-24, rule 4).
        now.extend(wait::count_line(relay, now_at));
    }
    let out_of_reach = |name: &str| {
        relays
            .iter()
            .any(|relay| relay.name == name && relay.out_of_reach())
    };
    let not_reached: Vec<&str> = list(seen, "not_reached")
        .filter_map(Value::as_str)
        .collect();
    // A relay out of reach is said so by its own line (S2, S3).
    for relay in not_reached.iter().filter(|name| !out_of_reach(name)) {
        now.push(format!(
            "keep this machine on: {relay} is not connected, and what is still to send \
             there is not known until it is"
        ));
    }
    // A row of what waits for each relay that the device is set up with,
    // or one of them is not reached, whether or not it was named so.
    let rows = list(seen, "waiting").count();
    if not_reached.is_empty() && rows < set_up {
        now.push(
            "keep this machine on: a relay that this device is set up with is not connected, \
             and what is still to send there is not known until it is"
                .into(),
        );
    }
    // Every relay that is not reached is out of reach: what is sent is
    // counted over those that are (decision 2026-10-19 §3).
    let all_reached = not_reached.iter().all(|name| out_of_reach(name))
        && (rows >= set_up || !not_reached.is_empty());
    for waits in list(seen, "waiting") {
        if let Some(n) = waits["waits"].as_u64().filter(|n| *n > 0) {
            now.push(format!(
                "keep this machine on: {n} of this device's channels still to send to {}",
                relay_of_row(waits)
            ));
        }
    }
    // What this device has still to send: what it carried, as names
    // sent and names to go. A name is said to be sent only while every
    // relay is reached, or out of reach: it is counted over those that
    // are reached.
    let to_go = list(&seen["names"], "to_go").count();
    let sent = list(&seen["names"], "sent").count();
    if to_go > 0 {
        now.push(format!(
            "keep this machine on: {} still to send ({sent} sent)",
            counted(to_go, "name")
        ));
    } else if sent > 0 && all_reached {
        now.push(format!("{} sent", counted(sent, "name")));
    }
    // Its own word that it has sent what it carried, under this change.
    let said_sent = list(seen, "devices")
        .filter(|device| is_own(device, own))
        .any(|device| device["applied"].as_u64() == Some(number) && device["sent"] == true);
    // Its carried word under this change (decision 2026-10-19, rule 7,
    // S4): where it sent what it carried, and where not yet.
    let own_word = list(seen, "devices")
        .chain(list(seen, "added"))
        .filter(|device| is_own(device, own))
        .any(|device| {
            device["applied"].as_u64() == Some(number) && carried_word_of(device).is_some()
        });
    if !said_sent {
        now.push(match own_word.then(|| own_carried_line(seen)).flatten() {
            Some(line) => line,
            None => "keep this machine on: this device has not yet sent every relay what it \
                     carried"
                .into(),
        });
    }
    for device in list(seen, "devices").filter(|device| !is_own(device, own)) {
        let applied = device["applied"].as_u64() == Some(number);
        now.push(match (applied, device["sent"] == true) {
            (true, true) => format!(
                "{} has applied the change, and has sent what it held",
                shown(device)
            ),
            // Its carried word (decision 2026-10-19, rule 6, S5).
            (true, false) if let Some(word) = carried_word_of(device) => {
                let (held, not_yet) = held_by_another(&word, seen);
                let mut said = format!(
                    "{} has applied the change, and has sent what it held to {held}",
                    shown(device)
                );
                if not_yet > 0 {
                    said.push_str(&format!("; not yet to {}", other_relays(not_yet)));
                }
                said
            }
            (true, false) => format!(
                "{} has applied the change, and is still sending what it held",
                shown(device)
            ),
            (false, _) => format!("{} has not applied the change yet", shown(device)),
        });
    }
    now
}

/// A relay of a row of what waits that names none, as a line says it
/// (decision 2026-10-24, rule 2): a personal node that dials only the
/// relays of its configuration never makes one.
const UNNAMED_RELAY: &str = "a relay that this device is connected to and that no line above names";

/// The relay that a row of what waits is of, as a line names it (decision
/// 2026-10-24, rule 2): by the name that the configuration gives it, and
/// never by the address it was reached at. A connection that two relays
/// given no key share is named by both.
fn relay_of_row(waits: &Value) -> String {
    if let Some(name) = waits["name"].as_str() {
        return name.to_string();
    }
    let names: Vec<String> = list(waits, "names")
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    match names.is_empty() {
        true => UNNAMED_RELAY.to_string(),
        false => joined(&names),
    }
}

/// The relays that what this device leaves behind is still to be sent to,
/// as `cordelia init --new-key` names them, from what the node answered
/// (`/api/v1/devices/leave/sent`): each row at which something waits, by
/// [`relay_of_row`].
fn still_to_send_to(sent: &Value) -> Vec<String> {
    list(sent, "waiting")
        .filter(|relay| relay["waits"].as_u64().unwrap_or(0) > 0)
        .map(relay_of_row)
        .collect()
}

/// After a change: stay, and show as they come whether each relay holds
/// the change, what this device has still to send, and which of the
/// remaining devices have applied it (decision 2026-10-04 §7.1, step 4).
/// It ends at the first of the three ends that holds (decision 2026-10-19
/// §4, rule 8: [`wait::end_of`]), by each relay's class and the node's
/// `word_to_come` as its look gives them, and says what that end says.
fn stays(config_path: &str, number: u64, made: Option<&str>) -> anyhow::Result<Waited> {
    waits_after(number, made, &TheNode(config_path), |line| {
        println!("{line}")
    })
}

/// What the wait after a change asks of the node, and the clock it goes
/// by (decision 2026-10-24, rule 3).
trait AfterAChange {
    /// This device's key, from its key file.
    fn own(&self) -> anyhow::Result<[u8; 32]>;
    /// What the device holds of its person, and where it stands at each
    /// relay, with what waits to be sent.
    fn look(&self) -> anyhow::Result<Value>;
    /// Why the node is of another version than this command, where it is
    /// ([`crate::node_of_another_version`]).
    fn another_version(&self) -> anyhow::Result<Option<String>>;
    /// The time between two askings.
    fn pause(&self);
    /// The time of day, in seconds, that each line is said at: the wall
    /// clock, or one that a test moves.
    fn now(&self) -> i64;
}

/// The node of the configuration at the path it holds.
struct TheNode<'a>(&'a str);

impl AfterAChange for TheNode<'_> {
    fn own(&self) -> anyhow::Result<[u8; 32]> {
        own_key(self.0)
    }

    fn look(&self) -> anyhow::Result<Value> {
        look(self.0)
    }

    fn another_version(&self) -> anyhow::Result<Option<String>> {
        crate::node_of_another_version(self.0)
    }

    fn pause(&self) {
        std::thread::sleep(ASK_EVERY);
    }

    fn now(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

/// [`stays`], of what `node` says, with each line said by `say`: S1, then
/// each line of each look that was not in the last, with its time, and
/// once a minute where none comes ([`wait::Told`], decision 2026-10-24,
/// rule 3); then the line that each end begins with, and what that end
/// says.
///
/// **A device that moves from the change ends the wait with status 3**
/// (decision 2026-10-24 (removal), rule 9), and says why: a change made
/// apart removed a device that this change lists, and the device follows
/// that change now. `made` names the change's entry, in hex, so that a
/// move at the same number is known as one; a look that keeps another
/// entry than it after the device stopped is another change.
fn waits_after(
    number: u64,
    made: Option<&str>,
    node: &impl AfterAChange,
    mut say: impl FnMut(String),
) -> anyhow::Result<Waited> {
    say(wait::first_line());
    let mut told = wait::Told::from(node.now());
    // Which row is this device's goes by its key file, as the prompts
    // go, and not by the node's word (decision 2026-10-04 §16).
    let own = node.own()?;
    loop {
        node.pause();
        // A node of another version, put in this one's place during the
        // wait, may say what this command reads otherwise.
        if let Some(note) = node.another_version()? {
            anyhow::bail!(note);
        }
        let seen = node.look()?;
        let at = node.now();
        if let Some(says) = made.and_then(|made| wait::moved_from(&seen, made)) {
            say(wait::Told::ended(at));
            say(says);
            return Ok(Waited::Moved);
        }
        if seen["change"].as_u64() != Some(number) {
            say(wait::Told::ended(at));
            say("This device has since applied another change: `cordelia devices` says.".into());
            return Ok(Waited::Another);
        }
        if let Some(line) = wait::no_longer_stands(&seen) {
            say(wait::Told::ended(at));
            say(line);
            return Ok(Waited::NoLongerStands);
        }
        if made.is_some_and(|made| seen["latest"].as_str() != Some(made)) {
            say(wait::Told::ended(at));
            say("This device has since applied another change: `cordelia devices` says.".into());
            return Ok(Waited::Another);
        }
        let (relays, word, end) = wait::end_of_look(&seen, number, &own)?;
        let lines = after_a_change(&seen, number, &own, at);
        for line in told.of_look(lines, at, end.is_some()) {
            say(line);
        }
        if let Some(end) = end {
            say(wait::Told::ended(at));
            for line in wait::end_lines(end, &relays, word, at) {
                say(line);
            }
            return Ok(Waited::Ended(end));
        }
    }
}

// ── cordelia init --new-key ─────────────────────────────────────────

/// `cordelia init --new-key`: give this device a new key (decision
/// 2026-10-04 §5.2). Where it is one of several it first says that it
/// has left. It keeps its memory folders and their mappings, and forgets
/// everything else that it held of its person. It then follows no
/// phrase.
pub fn new_key(config_path: &str) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let config_file = config::expand_tilde(config_path);
    let mut config = Config::load(&config_file)?;
    // The configuration as its file has it, to write back with the new
    // key: what the environment sets is not written into the file.
    let mut written = config.clone();
    config.apply_env_overrides();
    let key_path = config.data_dir().join(cordelia_api::commands::KEY_FILE);
    if !key_path.exists() {
        anyhow::bail!("this device has no key yet: `cordelia init` gives it one.");
    }
    let seen = look_with_what_waits(config_path)?;
    names_this_device(&seen, &NodeIdentity::from_file(&key_path)?.public_key())?;
    let leaves = match (text(&seen, "among"), seen["others"].as_u64().unwrap_or(0)) {
        ("several", others) => format!(
            "It leaves the {others} device{} it is with, and says so to {} first. It still \
             holds what it held, and its old key is still listed there: removing that key, \
             with the phrase, is what cuts it off.",
            if others == 1 { "" } else { "s" },
            if others == 1 { "it" } else { "them" },
        ),
        ("alone", _) => "The recovery phrase that it follows stops working here, and what the \
                         relays hold under it is left behind."
            .into(),
        ("no_phrase", _) => "It follows no recovery phrase, and has nothing to leave.".into(),
        _ => "It has stopped, and says nothing to the devices it was with.".into(),
    };
    if let Some(waits) = waits_says(&seen) {
        println!("{waits}");
    }
    let agreed = at.yes(&format!(
        "This gives this device a new key. {leaves}\nIt keeps its memory folders and their \
         mappings, and forgets everything else that it held of your devices: the phrase it \
         followed, every secret, and what its folders had agreed. It then follows no recovery \
         phrase, and is added as a new device."
    ))?;
    if !agreed {
        println!("{NOT_A_YES}");
        return Ok(());
    }

    // What it owes the devices it leaves is written while it is still
    // one of them, and under the key they know: it waits to be sent.
    let begun = api_post(config_path, "/api/v1/devices/leave", json!({}))?;
    if begun["said"] == true || begun["written_over"].as_u64().unwrap_or(0) > 0 {
        println!("\nTelling the relays what this device leaves behind...");
        let ends = Instant::now() + Duration::from_secs(LEAVING_SEND_WAIT_SECS);
        let not_sent = loop {
            std::thread::sleep(ASK_EVERY);
            let sent = api_post(config_path, "/api/v1/devices/leave/sent", json!({}))?;
            let waiting = still_to_send_to(&sent);
            let reached = list(&sent, "waiting").count();
            if reached > 0 && waiting.is_empty() {
                break Vec::new();
            }
            if Instant::now() >= ends {
                break match reached {
                    0 => vec!["any relay: none is reached".to_string()],
                    _ => waiting,
                };
            }
        };
        for relay in &not_sent {
            println!(
                "  Could not send it to {relay}: the devices that this one leaves may not be \
                 told that it left."
            );
        }
        if !not_sent.is_empty() {
            let goes_on = at.yes(
                "Under a new key nothing more can be sent in the old one's name. Go on \
                 without having told them?",
            )?;
            if !goes_on {
                // It leaves nobody: its word that it left is taken back,
                // by a delete over it (§16). Where no relay was sent the
                // word, none is sent it.
                let back = api_post(config_path, "/api/v1/devices/leave/back", json!({}))?;
                let word = match back["taken_back"] == true {
                    true => ", and has taken back its word that it left",
                    false => "",
                };
                println!(
                    "Stopped. This device keeps its key and what it holds{word}: run `cordelia \
                     init --new-key` again when a relay is reached."
                );
                return Ok(());
            }
        }
    }
    // The new key is written beside the old one first, then the node
    // forgets, and only then does the new key take the old one's place:
    // a device never has a node that has forgotten and no new key on the
    // disk to go on with.
    let identity = NodeIdentity::generate()?;
    give_new_key(&key_path, identity.seed(), || {
        let asked = api_post_told(
            config_path,
            "/api/v1/devices/forget",
            json!({}),
            Some(Duration::from_secs(30)),
        );
        match asked {
            Ok(Told::Yes(_)) => Forgot::Yes,
            Ok(Told::No { message, .. }) => Forgot::No(message),
            Err(lost) => Forgot::NotKnown(lost.to_string()),
        }
    })?;
    let key = encode_public_key(&identity.public_key())?;
    let was = written.identity.entity_id.clone();
    let name = was.rsplit_once('_').map_or(was.as_str(), |(name, _)| name);
    written.identity.entity_id = format!("{name}_{}", identity.entity_id_suffix());
    written.identity.public_key = key.clone();
    if config_file.exists() {
        written.save(&config_file)?;
    }
    println!("\nThis device has a new key:\n  {key}");
    println!("{}", after_a_new_key_says(std::env::consts::OS));
    Ok(())
}

/// What `cordelia init --new-key` ends with, on the system named
/// (decision 2026-10-04 §5.2): where the device stands, and that the
/// node, which still runs under the old key, is restarted before
/// anything else ([`cordelia_api::commands::restart_says`]). The status
/// of the node, once it is restarted, names the ways on for a device
/// that follows no phrase.
fn after_a_new_key_says(os: &str) -> String {
    format!(
        "It follows no recovery phrase. Its memory folders and their mappings are as they \
         were.\nThe node still runs under the old key. Before anything else, restart the \
         node:\n{}\nThe status then names the ways on.",
        cordelia_api::commands::restart_says(os)
    )
}

/// What the node answered when it was asked to forget what it holds of
/// its person.
enum Forgot {
    /// It forgot.
    Yes,
    /// It refused, and says why: it holds what it held.
    No(String),
    /// Its answer was lost: it may have forgotten.
    NotKnown(String),
}

/// Give the device whose key file is at `path` the key of `seed`, in
/// three steps, and say what state the device is in where any of them
/// fails (decision 2026-10-04 §5.2, §16):
///
/// 1. **the new key is written beside the old one** ([`write_beside`]).
///    Where that fails nothing was changed;
/// 2. **the node forgets** what it holds of its person (`forget`). Where
///    it refuses, the device keeps its key and what it holds; where its
///    answer is lost, the device keeps its key, and `cordelia devices`
///    says whether the node forgot;
/// 3. **the new key takes the old one's place,** by a rename, so that the
///    key file holds the old key or the new one, whole. Where that fails
///    the node has forgotten and the device keeps the key it had: it
///    follows no phrase, and the command is run again.
///
/// The node forgets only once the new key is on the disk: a device is
/// never left with a node that has forgotten and no new key to take.
/// What was written beside the key file is removed wherever the new key
/// does not take its place.
fn give_new_key(
    path: &std::path::Path,
    seed: &[u8; 32],
    forget: impl FnOnce() -> Forgot,
) -> anyhow::Result<()> {
    let beside = write_beside(path, seed).map_err(|e| {
        anyhow::anyhow!(
            "could not write the new key ({e}): nothing was changed. The key file is as it \
             was, and this device keeps the key it had and what it holds of your devices."
        )
    })?;
    let discarded = || {
        let _ = std::fs::remove_file(&beside);
    };
    match forget() {
        Forgot::Yes => {}
        Forgot::No(why) => {
            discarded();
            anyhow::bail!(
                "{why}\nThe node did not forget what it holds of your devices, and the new key \
                 was discarded: this device keeps the key it had and what it holds. Where it \
                 said that it left, that word stands. Run `cordelia init --new-key` again."
            );
        }
        Forgot::NotKnown(why) => {
            discarded();
            anyhow::bail!(
                "{why}\nIt is not known whether the node forgot what it holds of your devices: \
                 its answer was lost. The new key was discarded, and this device keeps the key \
                 it had. `cordelia devices` says where it stands: if it follows no recovery \
                 phrase, the node has forgotten. Either way, run `cordelia init --new-key` \
                 again to give it a new key."
            );
        }
    }
    if let Err(e) = std::fs::rename(&beside, path) {
        discarded();
        anyhow::bail!(
            "the node has forgotten what it held of your devices, and the new key could not be \
             put in the place of the old one ({e}): this device keeps the key it had, and \
             follows no recovery phrase. Run `cordelia init --new-key` again."
        );
    }
    // The name is flushed too, as far as the volume can.
    if let Some(folder) = path.parent()
        && let Ok(folder) = std::fs::File::open(folder)
    {
        let _ = folder.sync_all();
    }
    Ok(())
}

/// Write `seed` to a file beside the key file at `path`, flushed, and
/// return where (decision 2026-10-04 §16). The file is the device's alone
/// to read from the moment it is made, and is made anew each time: never
/// written through whatever was left under that name. Where it cannot be
/// written, nothing is left beside the key file.
fn write_beside(path: &std::path::Path, seed: &[u8; 32]) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    let mut beside = path.as_os_str().to_owned();
    beside.push(".new");
    let beside = std::path::PathBuf::from(beside);
    let _ = std::fs::remove_file(&beside);
    let mut made = std::fs::OpenOptions::new();
    made.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        made.mode(0o600);
    }
    let written = made.open(&beside).and_then(|mut file| {
        file.write_all(seed)?;
        file.sync_all()
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&beside);
        return Err(e);
    }
    Ok(beside)
}

#[cfg(test)]
mod tests {
    use super::*;

    use cordelia_crypto::addition::Addition;
    use cordelia_crypto::change_entry::open_statement;

    const WORDS: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const OTHER_PHRASE: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

    /// A device under a phrase, at its second statement, which lists it
    /// and one other device and removes one key: the statement, its
    /// change entry, and what a node hands a command of them, with the
    /// records in `additions`.
    struct Fixture {
        own: NodeIdentity,
        listed: [u8; 32],
        removed: [u8; 32],
        statement: SignedStatement,
        entry: CheckedEntry,
    }

    impl Fixture {
        fn new() -> Self {
            let phrase = Phrase::parse(WORDS).unwrap();
            let own = NodeIdentity::from_seed([1; 32]).unwrap();
            let removed = NodeIdentity::from_seed([2; 32]).unwrap().public_key();
            let listed = NodeIdentity::from_seed([3; 32]).unwrap().public_key();
            let first = first_entry(&phrase, &own.public_key(), "laptop").unwrap();
            let read = |entry: &CheckedEntry| {
                open_statement(
                    entry,
                    &phrase.public_key().unwrap(),
                    &entry.channel,
                    &phrase.statement_key().unwrap(),
                )
                .unwrap()
            };
            let one = read(&first.entry);
            let mut stay = one.statement.devices.clone();
            stay.push(Device::new(listed, "phone").unwrap());
            let entry = prepare_change(&one, &own.public_key(), stay, &[removed])
                .unwrap()
                .sign(&phrase, &first.entry, &[])
                .unwrap();
            Self {
                listed,
                removed,
                statement: read(&entry),
                entry,
                own,
            }
        }

        /// A change made apart from this one, under the same phrase: from a
        /// first change of its own, renewed `renewals` times, so that it is
        /// numbered `renewals + 1`. Its statement, and its change entry.
        fn apart(&self, renewals: usize) -> (SignedStatement, CheckedEntry) {
            let phrase = Phrase::parse(WORDS).unwrap();
            let own = self.own.public_key();
            let read = |entry: &CheckedEntry| {
                open_statement(
                    entry,
                    &phrase.public_key().unwrap(),
                    &entry.channel,
                    &phrase.statement_key().unwrap(),
                )
                .unwrap()
            };
            let mut entry = first_entry(&phrase, &own, "laptop").unwrap().entry;
            for _ in 0..renewals {
                let statement = read(&entry);
                let stay = statement.statement.devices.clone();
                entry = prepare_change(&statement, &own, stay, &[])
                    .unwrap()
                    .sign(&phrase, &entry, &[])
                    .unwrap();
            }
            (read(&entry), entry)
        }

        /// The record in which this device adds `key` under `label`.
        fn adds(&self, key: [u8; 32], label: &str) -> SignedAddition {
            self.added_by(&self.own, key, label)
        }

        /// The record in which the device `adder` adds `key` under
        /// `label`, under the statement that this device has applied.
        fn added_by(&self, adder: &NodeIdentity, key: [u8; 32], label: &str) -> SignedAddition {
            let device = Device::new(key, label).unwrap();
            Addition::under(&self.statement.statement, device, adder.public_key(), 7)
                .unwrap()
                .sign(adder)
                .unwrap()
        }

        /// What a node hands, read on this device: its key is the one in
        /// its key file.
        fn read(&self, handed: &Value) -> anyhow::Result<Handed> {
            Handed::of(handed, &self.own.public_key())
        }

        fn handed(&self, statement: &SignedStatement, additions: &[SignedAddition]) -> Value {
            let additions: Vec<String> = additions
                .iter()
                .map(|record| hex::encode(record.to_bytes().unwrap()))
                .collect();
            json!({
                "this_device": encode_public_key(&self.own.public_key()).unwrap(),
                "statement": hex::encode(statement.to_bytes().unwrap()),
                "over": hex::encode(self.entry.id()),
                "entry": hex::encode(self.entry.to_wire()),
                "additions": additions,
            })
        }
    }

    /// What a command is handed is read from the signed bytes of each
    /// thing, and each signature is checked before anything is shown: a
    /// statement or a record that its key did not sign is refused. Of
    /// the records, a person is asked about each key once, and about no
    /// key that the statement lists, in either list.
    #[test]
    fn what_a_command_is_handed_is_checked_before_anything_is_shown() {
        let f = Fixture::new();
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let (desktop, tablet) = (f.adds(key(5), "desktop"), f.adds(key(6), "tablet"));
        let records = [
            desktop.clone(),
            f.adds(f.listed, "the phone again"),
            f.adds(f.removed, "a removed key"),
            tablet.clone(),
            f.adds(key(5), "the desktop again"),
        ];
        let handed = f.read(&f.handed(&f.statement, &records)).unwrap();
        assert_eq!(handed.this_device, f.own.public_key());
        assert_eq!(handed.applied, f.statement);
        assert_eq!(handed.held, f.entry);
        // What the prompt is shown over is worked out from the entry
        // that was handed, whatever the node says it is named by.
        assert_eq!(handed.over, hex::encode(f.entry.id()));
        let mut says_another = f.handed(&f.statement, &records);
        says_another["over"] = hex::encode([7u8; 32]).into();
        assert_eq!(
            f.read(&says_another).unwrap().over,
            hex::encode(f.entry.id())
        );
        says_another["over"] = Value::Null;
        assert_eq!(
            f.read(&says_another).unwrap().over,
            hex::encode(f.entry.id())
        );
        assert!(handed.heads.is_empty() && handed.removed.is_empty());
        assert_eq!(handed.added, [desktop.clone(), tablet]);
        // The labels that the device knows a key by.
        assert_eq!(handed.label(&f.own.public_key()), "laptop");
        assert_eq!(handed.label(&f.listed), "phone");
        assert_eq!(handed.label(&key(5)), "desktop");
        assert_eq!(handed.label(&key(9)), "");

        // A statement that its phrase did not sign.
        let mut forged = f.statement.clone();
        forged.signature[0] ^= 1;
        assert!(f.read(&f.handed(&forged, &[])).is_err());
        // A record that its adder did not sign.
        let mut forged = desktop.clone();
        forged.signature[0] ^= 1;
        assert!(f.read(&f.handed(&f.statement, &[forged])).is_err());
        // Each head set aside, where there is one, likewise: what it is
        // named by is worked out from its entry, whatever the node says.
        let mut with_apart = f.handed(&f.statement, &[]);
        with_apart["heads"] = json!([{
            "statement": with_apart["statement"].clone(),
            "entry": with_apart["entry"].clone(),
            "id": hex::encode([7u8; 32]),
        }]);
        let handed = f.read(&with_apart).unwrap();
        let (statement, _, named) = &handed.heads[0];
        assert_eq!(*statement, f.statement);
        assert_eq!(*named, hex::encode(f.entry.id()));
        let mut forged = f.statement.clone();
        forged.signature[0] ^= 1;
        with_apart["heads"][0]["statement"] = hex::encode(forged.to_bytes().unwrap()).into();
        assert!(f.read(&with_apart).is_err());
        // A head under another phrase is refused.
        let other = Phrase::parse(OTHER_PHRASE).unwrap();
        let theirs = first_entry(&other, &f.own.public_key(), "laptop")
            .unwrap()
            .entry;
        let theirs_read = open_statement(
            &theirs,
            &other.public_key().unwrap(),
            &theirs.channel,
            &other.statement_key().unwrap(),
        )
        .unwrap();
        with_apart["heads"][0]["statement"] = hex::encode(theirs_read.to_bytes().unwrap()).into();
        with_apart["heads"][0]["entry"] = hex::encode(theirs.to_wire()).into();
        assert!(f.read(&with_apart).is_err());
        // The removed keys the node hands are read in order, each once;
        // one that is no key, and this device's own, are refused.
        let mut with_removed = f.handed(&f.statement, &[]);
        with_removed["removed"] = json!([
            encode_public_key(&key(8)).unwrap(),
            encode_public_key(&key(7)).unwrap(),
            encode_public_key(&key(8)).unwrap(),
        ]);
        let mut both = vec![key(7), key(8)];
        both.sort_unstable();
        assert_eq!(f.read(&with_removed).unwrap().removed, both);
        with_removed["removed"] = json!(["no key"]);
        assert!(f.read(&with_removed).is_err());
        with_removed["removed"] = json!([encode_public_key(&f.own.public_key()).unwrap()]);
        assert!(f.read(&with_removed).is_err());
        // And what is no entry at all.
        let mut no_entry = f.handed(&f.statement, &[]);
        no_entry["entry"] = "00".into();
        assert!(f.read(&no_entry).is_err());
    }

    /// What a command shows as this device is its own reading of the key
    /// file (decision 2026-10-04 §16): where the node names another key
    /// as this device, or none, nothing that it handed is read, whatever
    /// record it hands for that key.
    #[test]
    fn a_node_that_names_another_key_as_this_device_is_refused() {
        let f = Fixture::new();
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let own = f.own.public_key();
        // Another key as this device, with a record that adds it.
        let mut handed = f.handed(&f.statement, &[f.adds(key(5), "laptop")]);
        handed["this_device"] = encode_public_key(&key(5)).unwrap().into();
        let refused = Handed::of(&handed, &own).err().unwrap().to_string();
        assert!(
            refused.contains("does not name this device's key"),
            "{refused}"
        );
        assert!(refused.contains(&fingerprint::shown(&own)), "{refused}");
        // The control: the device whose key that is reads the same answer.
        assert!(Handed::of(&handed, &key(5)).is_ok());
        // An answer that names no key at all.
        handed["this_device"] = Value::Null;
        assert!(Handed::of(&handed, &own).is_err());
        assert!(names_this_device(&json!({}), &own).is_err());
        let named = json!({ "this_device": encode_public_key(&own).unwrap() });
        assert!(names_this_device(&named, &own).is_ok());
        assert!(names_this_device(&named, &key(5)).is_err());
    }

    /// A record of an addition is asked about only where it names the
    /// statement that the device has applied, and its adder is a device
    /// of that statement or was added by one (decision 2026-10-04 §6,
    /// §16). A record that is handed and is neither is refused, with
    /// nothing shown.
    #[test]
    fn a_record_is_asked_about_only_under_the_applied_statement_and_from_one_that_may_add() {
        let f = Fixture::new();
        let id = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap();
        let key = |n: u8| id(n).public_key();
        // A chain of two: this device adds one, and that one adds another.
        let five = f.adds(key(5), "desktop");
        let six = f.added_by(&id(5), key(6), "tablet");
        let handed = f
            .read(&f.handed(&f.statement, &[five.clone(), six.clone()]))
            .unwrap();
        assert_eq!(handed.added, [five.clone(), six.clone()]);
        // In whichever order the node hands them.
        let handed = f
            .read(&f.handed(&f.statement, &[six.clone(), five.clone()]))
            .unwrap();
        assert_eq!(handed.added, [six.clone(), five.clone()]);

        // An adder that no device of the statement added.
        assert!(
            f.read(&f.handed(&f.statement, std::slice::from_ref(&six)))
                .is_err()
        );
        // A chain of three.
        let seven = f.added_by(&id(6), key(7), "phone two");
        let chain = [five.clone(), six.clone(), seven];
        assert!(f.read(&f.handed(&f.statement, &chain)).is_err());
        // The adder's standing may come by a record that nothing is asked
        // about: it counts by another.
        let mut with_standing = f.handed(&f.statement, std::slice::from_ref(&six));
        with_standing["standing"] = json!([hex::encode(five.to_bytes().unwrap())]);
        assert_eq!(
            f.read(&with_standing).unwrap().added,
            std::slice::from_ref(&six)
        );
        // Such a record is checked as any other is.
        let mut forged = five.clone();
        forged.signature[0] ^= 1;
        with_standing["standing"] = json!([hex::encode(forged.to_bytes().unwrap())]);
        assert!(f.read(&with_standing).is_err());

        // A record made under another statement than the one applied.
        let mut under_another = five.addition.clone();
        under_another.under.number += 1;
        let under_another = under_another.sign(&f.own).unwrap();
        let refused = f
            .read(&f.handed(&f.statement, &[under_another]))
            .err()
            .unwrap()
            .to_string();
        assert!(refused.contains("under another change"), "{refused}");
    }

    /// At a removal or a renewal a person is asked about each device added
    /// since the last change, a device before the devices that it added,
    /// in whichever order the node handed the records (decision
    /// 2026-10-04 §6): and never about this device, or the one that goes.
    #[test]
    fn a_device_is_asked_about_before_the_devices_that_it_added() {
        let f = Fixture::new();
        let id = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap();
        let key = |n: u8| id(n).public_key();
        // This device added 5 and 8; 5 added 6 and 7.
        let records = [
            f.added_by(&id(5), key(6), "tablet"),
            f.adds(key(8), "watch"),
            f.added_by(&id(5), key(7), "phone two"),
            f.adds(key(5), "desktop"),
        ];
        let handed = f.read(&f.handed(&f.statement, &records)).unwrap();
        let asked = questions(&handed, None);
        let keys: Vec<[u8; 32]> = asked.iter().map(|asked| asked.device.key).collect();
        assert_eq!(keys, [key(8), key(5), key(6), key(7)]);
        assert_eq!(asked[1].device, Device::new(key(5), "desktop").unwrap());
        assert_eq!(
            asked[2].says,
            format!(
                "\n{}, added since the last change, from {} at {}:",
                named("tablet", &key(6)),
                named("desktop", &key(5)),
                time_of(7)
            )
        );
        // Where the device that added one is the one that goes, that is
        // said, and the one that goes is not asked about.
        let asked = questions(&handed, Some(key(5)));
        let keys: Vec<[u8; 32]> = asked.iter().map(|asked| asked.device.key).collect();
        assert_eq!(keys, [key(8), key(6), key(7)]);
        assert!(
            !asked[0].says.contains("being removed"),
            "{}",
            asked[0].says
        );
        for by_the_one_that_goes in &asked[1..] {
            assert!(
                by_the_one_that_goes
                    .says
                    .ends_with(". It was added by the device that is being removed:"),
                "{}",
                by_the_one_that_goes.says
            );
        }
        // This device is asked about by nobody: its listing is confirmed
        // apart.
        let mut handed = f.handed(&f.statement, &records);
        handed["this_device"] = encode_public_key(&key(8)).unwrap().into();
        let read = Handed::of(&handed, &key(8)).unwrap();
        let keys: Vec<[u8; 32]> = questions(&read, None)
            .iter()
            .map(|asked| asked.device.key)
            .collect();
        assert_eq!(keys, [key(5), key(6), key(7)]);
    }

    /// A device that has said that it left is asked about at a change
    /// (decision 2026-10-04 §7.1): one that the last change lists is asked
    /// about first, as that, and stays only where a person says so; one
    /// that was added since is asked about as an addition, and that it
    /// left is said. The device that goes, and this one, are asked about
    /// by neither.
    #[test]
    fn a_device_that_has_said_it_left_is_asked_about_at_a_change() {
        let f = Fixture::new();
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let own = f.own.public_key();
        let written = |key: &[u8; 32]| encode_public_key(key).unwrap();
        let mut handed = f.handed(&f.statement, &[f.adds(key(5), "desktop")]);
        // Nobody has left: the devices of the last change stay, unasked.
        let read = f.read(&handed).unwrap();
        let asked = questions(&read, None);
        assert_eq!(asked.len(), 1);
        let stay: Vec<[u8; 32]> = stays_unasked(&read, None, &asked)
            .iter()
            .map(|device| device.key)
            .collect();
        assert_eq!(stay, [own, f.listed]);

        // The phone, which the last change lists, and the desktop, added
        // since, have each said that they left. So has this device, by
        // the node's word, which asks nothing of it.
        handed["left"] = json!([
            written(&key(5)),
            written(&f.listed),
            written(&own),
            "no key"
        ]);
        let read = f.read(&handed).unwrap();
        assert_eq!(read.left, [key(5), f.listed, own]);
        let asked = questions(&read, None);
        let keys: Vec<[u8; 32]> = asked.iter().map(|asked| asked.device.key).collect();
        assert_eq!(keys, [f.listed, key(5)]);
        assert_eq!(
            asked[0].says,
            format!(
                "\n{}, a device of the last change. It has said that it left, and started \
                 again under another phrase: it still holds what it held:",
                named("phone", &f.listed)
            )
        );
        assert!(
            asked[1]
                .says
                .ends_with(&format!("at {}. {SAID_IT_LEFT}:", time_of(7))),
            "{}",
            asked[1].says
        );
        // It stays only where a person says so: unasked, this device
        // alone.
        let stay: Vec<[u8; 32]> = stays_unasked(&read, None, &asked)
            .iter()
            .map(|device| device.key)
            .collect();
        assert_eq!(stay, [own]);
        // Where it is the device that goes, nothing is asked of it.
        let asked = questions(&read, Some(f.listed));
        let keys: Vec<[u8; 32]> = asked.iter().map(|asked| asked.device.key).collect();
        assert_eq!(keys, [key(5)]);
        assert_eq!(stays_unasked(&read, Some(f.listed), &asked).len(), 1);
    }

    /// A device that the applied statement does not list was added since.
    /// Before a change lists it, it is shown as an addition is, from the
    /// record of its own addition: who added it, when, and the words of
    /// its key (decision 2026-10-04 §16). With no such record it makes no
    /// change.
    #[test]
    fn a_device_added_since_is_shown_its_own_addition_before_a_change_lists_it() {
        let f = Fixture::new();
        let five = NodeIdentity::from_seed([5; 32]).unwrap().public_key();
        let mut handed = f.handed(&f.statement, &[f.adds(five, "desktop")]);
        handed["this_device"] = encode_public_key(&five).unwrap().into();
        let read = Handed::of(&handed, &five).unwrap();
        let (says, device) = own_addition(&read, false).unwrap();
        assert_eq!(device, Device::new(five, "desktop").unwrap());
        let shown = format!(
            "{} added this machine at {}, as {}.",
            named("laptop", &f.own.public_key()),
            time_of(7),
            named("desktop", &five),
        );
        assert!(says.contains(&shown), "{says}");

        let mut handed = f.handed(&f.statement, &[]);
        handed["this_device"] = encode_public_key(&five).unwrap().into();
        let read = Handed::of(&handed, &five).unwrap();
        let refused = own_addition(&read, false).err().unwrap().to_string();
        assert!(refused.contains("it makes no change"), "{refused}");
    }

    /// **The question to a device added since the last change says what a
    /// change is, and the change it makes** (decision 2026-10-24, rule 1),
    /// word for word: for a renewal or a removal, the last change and who
    /// made it; for a settlement, the two changes that neither lists it.
    #[test]
    fn a_device_added_since_is_told_the_change_that_will_list_it() {
        let f = Fixture::new();
        let five = NodeIdentity::from_seed([5; 32]).unwrap().public_key();
        let own = f.own.public_key();
        let mut handed = f.handed(&f.statement, &[f.adds(five, "desktop")]);
        handed["this_device"] = encode_public_key(&five).unwrap().into();
        let read = Handed::of(&handed, &five).unwrap();
        let (desktop, laptop) = (named("desktop", &five), named("laptop", &own));
        let (says, _) = own_addition(&read, false).unwrap();
        assert_eq!(
            says,
            format!(
                "\nA change is the list of your devices that your recovery phrase signs.\nYour \
                 last change (change 2, made on {laptop}) was signed before this machine was \
                 added, so it does not list this machine. {laptop} added this machine at {}, as \
                 {desktop}.\nThis command makes change 3. The machine that makes a change is \
                 always in it, so change 3 will list this machine as {desktop}.",
                time_of(7)
            )
        );
        // In a fork, a settlement: the two changes, and the one above both.
        let (apart, apart_entry) = f.apart(2);
        handed["heads"] = json!([{
            "statement": hex::encode(apart.to_bytes().unwrap()),
            "entry": hex::encode(apart_entry.to_wire()),
        }]);
        let read = Handed::of(&handed, &five).unwrap();
        let (says, _) = own_addition(&read, true).unwrap();
        assert_eq!(
            says,
            format!(
                "\nA change is the list of your devices that your recovery phrase signs.\n\
                 Neither change 2 nor change 3 lists this machine: both were made without it. \
                 {laptop} added this machine at {}, as {desktop}.\nThis command makes change 4, \
                 which settles the two. The machine that makes a change is always in it, so \
                 change 4 will list this machine as {desktop}.",
                time_of(7)
            )
        );
    }

    /// What a person types, a line for each question in turn, and each
    /// question that was asked.
    struct Typed {
        answers: std::cell::RefCell<Vec<&'static str>>,
        asked: std::cell::RefCell<Vec<String>>,
    }

    impl Typed {
        fn of(answers: &[&'static str]) -> Self {
            Self {
                answers: std::cell::RefCell::new(answers.to_vec()),
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl Answers for Typed {
        fn answer(&self, asks: &str) -> anyhow::Result<Option<String>> {
            self.asked.borrow_mut().push(asks.to_string());
            let mut answers = self.answers.borrow_mut();
            Ok((!answers.is_empty()).then(|| answers.remove(0).to_string()))
        }
    }

    /// **A settlement on a machine that neither change lists asks it to
    /// list itself in the settlement** (decision 2026-10-24, rule 1): the
    /// question names the two changes and the change above both, and that
    /// is the change that is prepared. The machine was added under change
    /// 2; change 3 was made apart from it.
    #[test]
    fn a_settlement_on_a_machine_that_neither_change_lists_names_the_settlement() {
        let f = Fixture::new();
        let five = NodeIdentity::from_seed([5; 32]).unwrap().public_key();
        let mut handed = f.handed(&f.statement, &[f.adds(five, "desktop")]);
        handed["this_device"] = encode_public_key(&five).unwrap().into();
        let (apart, apart_entry) = f.apart(2);
        handed["heads"] = json!([{
            "statement": hex::encode(apart.to_bytes().unwrap()),
            "entry": hex::encode(apart_entry.to_wire()),
        }]);
        let read = Handed::of(&handed, &five).unwrap();
        // The laptop, of both changes, and the phone stay; then this
        // machine is listed.
        let typed = Typed::of(&["stays", "stays", "list"]);
        let prepared = asked(&typed, &read, &Which::Settle).unwrap();
        let asked = typed.asked.borrow();
        let listing = asked.last().unwrap();
        assert!(
            listing.contains(
                "Neither change 2 nor change 3 lists this machine: both were made without it."
            ),
            "{listing}"
        );
        assert!(
            listing.contains("This command makes change 4, which settles the two."),
            "{listing}"
        );
        let signs = Statement::from_bytes(prepared.bytes()).unwrap();
        assert_eq!(signs.number, 4);
        assert!(signs.lists(&five));
        // Any other word stops it, with nothing prepared.
        let typed = Typed::of(&["stays", "stays", "stays"]);
        let refused = asked_err(&typed, &read);
        assert_eq!(refused, "You did not type `list`. Nothing was changed.");
    }

    /// What [`asked`] refuses of a settlement, as it says it.
    fn asked_err(typed: &Typed, read: &Handed) -> String {
        match asked(typed, read, &Which::Settle) {
            Ok(_) => panic!("a settlement was prepared"),
            Err(e) => e.to_string(),
        }
    }

    /// **Every key that the device knows to be removed is listed as
    /// removed, and none as a device** (decision 2026-10-24 (removal),
    /// rule 20): a renewal and a removal list each key that the node
    /// handed, a device of the last change among them is neither kept nor
    /// asked about, and a key that is removed already is not removed again.
    #[test]
    fn a_change_lists_every_key_the_node_hands_as_removed() {
        let f = Fixture::new();
        let own = f.own.public_key();
        let stranger = NodeIdentity::from_seed([9; 32]).unwrap().public_key();
        let mut handed = f.handed(&f.statement, &[]);
        // The phone, a device of the last change, was removed on another
        // branch; so was a key that this device never knew.
        handed["removed"] = json!([
            encode_public_key(&f.listed).unwrap(),
            encode_public_key(&stranger).unwrap(),
        ]);
        let read = f.read(&handed).unwrap();
        // Nothing is asked: the phone is not asked about.
        let typed = Typed::of(&[]);
        let prepared = asked(&typed, &read, &Which::Renew).unwrap();
        assert!(typed.asked.borrow().is_empty());
        let signs = Statement::from_bytes(prepared.bytes()).unwrap();
        assert_eq!(
            signs.devices.iter().map(|d| d.key).collect::<Vec<_>>(),
            [own]
        );
        for key in [f.listed, stranger, f.removed] {
            assert!(signs.removes(&key));
        }
        // A removal of another key lists them too.
        let other = NodeIdentity::from_seed([8; 32]).unwrap().public_key();
        let typed = Typed::of(&["refuse"]);
        let prepared = asked(&typed, &read, &Which::Remove(other)).unwrap();
        let signs = Statement::from_bytes(prepared.bytes()).unwrap();
        for key in [f.listed, stranger, f.removed, other] {
            assert!(signs.removes(&key));
        }
        assert!(!signs.lists(&f.listed));
        // A key the node handed as removed is not removed again.
        for goes in [stranger, f.listed] {
            let refused = asked(&Typed::of(&[]), &read, &Which::Remove(goes));
            assert_eq!(
                refused.err().unwrap().to_string(),
                "that key was removed already, by an earlier change."
            );
        }
    }

    /// **A device added since that the node knows to be removed is not
    /// asked about,** and the change lists it as removed and not as a
    /// device (decision 2026-10-24 (removal), rule 20): a key removed on
    /// another branch after this device's record of it counted.
    #[test]
    fn a_device_added_since_that_the_node_knows_removed_is_not_asked_about() {
        let f = Fixture::new();
        let desktop = NodeIdentity::from_seed([5; 32]).unwrap().public_key();
        let mut handed = f.handed(&f.statement, &[f.adds(desktop, "desktop")]);
        handed["removed"] = json!([encode_public_key(&desktop).unwrap()]);
        let read = f.read(&handed).unwrap();
        let typed = Typed::of(&[]);
        let prepared = asked(&typed, &read, &Which::Renew).unwrap();
        assert!(typed.asked.borrow().is_empty(), "{:?}", typed.asked);
        let signs = Statement::from_bytes(prepared.bytes()).unwrap();
        assert!(signs.removes(&desktop) && !signs.lists(&desktop));
    }

    /// **A change made where a head is set aside joins every head**
    /// (decision 2026-10-24 (removal), rule 21): `remove-device` and
    /// `renew` there make a settlement, as `settle` does, numbered above
    /// each head, with each on its chain; a removal there removes its key.
    /// With two heads set aside, the settlement joins all three changes.
    #[test]
    fn a_change_made_where_a_head_is_set_aside_joins_every_head() {
        let f = Fixture::new();
        let mut handed = f.handed(&f.statement, &[]);
        let (apart, apart_entry) = f.apart(2);
        handed["heads"] = json!([{
            "statement": hex::encode(apart.to_bytes().unwrap()),
            "entry": hex::encode(apart_entry.to_wire()),
        }]);
        let read = f.read(&handed).unwrap();
        let joins = |signs: &Statement, heads: &[&SignedStatement]| {
            for head in heads {
                assert!(signs.has_on_chain(&head.statement.link().unwrap()));
                assert!(signs.number > head.statement.number);
            }
        };
        // A removal of the phone: nothing is asked of it, and of the
        // laptop, this device, nothing either.
        let typed = Typed::of(&[]);
        let prepared = asked(&typed, &read, &Which::Remove(f.listed)).unwrap();
        let signs = Statement::from_bytes(prepared.bytes()).unwrap();
        assert_eq!(signs.number, 4);
        joins(&signs, &[&f.statement, &apart]);
        assert!(signs.removes(&f.listed));
        // A renewal asks of the phone, as `cordelia settle` asks.
        let typed = Typed::of(&["stays"]);
        let prepared = asked(&typed, &read, &Which::Renew).unwrap();
        let signs = Statement::from_bytes(prepared.bytes()).unwrap();
        joins(&signs, &[&f.statement, &apart]);
        assert!(signs.lists(&f.listed));
        assert!(typed.asked.borrow()[0].contains("a device of the change this device follows"));
        // A device added since under the change followed is asked about
        // too, with the third answer: it is not left out unasked.
        let desktop = NodeIdentity::from_seed([5; 32]).unwrap().public_key();
        let mut with_added = f.handed(&f.statement, &[f.adds(desktop, "desktop")]);
        with_added["heads"] = handed["heads"].clone();
        let read_added = f.read(&with_added).unwrap();
        for (answer, kept) in [("stays", true), ("neither", false)] {
            let typed = Typed::of(&["stays", answer]);
            let prepared = asked(&typed, &read_added, &Which::Renew).unwrap();
            let signs = Statement::from_bytes(prepared.bytes()).unwrap();
            joins(&signs, &[&f.statement, &apart]);
            assert_eq!(signs.lists(&desktop), kept, "{answer}");
            let asked = typed.asked.borrow();
            assert!(
                asked[1].contains("added since the last change"),
                "{}",
                asked[1]
            );
        }

        // Two heads set aside: the settlement joins all three.
        let (third, third_entry) = f.apart(3);
        handed["heads"] = json!([
            {
                "statement": hex::encode(third.to_bytes().unwrap()),
                "entry": hex::encode(third_entry.to_wire()),
            },
            {
                "statement": hex::encode(apart.to_bytes().unwrap()),
                "entry": hex::encode(apart_entry.to_wire()),
            },
        ]);
        let read = f.read(&handed).unwrap();
        for which in [Which::Renew, Which::Settle] {
            let typed = Typed::of(&["stays"]);
            let prepared = asked(&typed, &read, &which).unwrap();
            let signs = Statement::from_bytes(prepared.bytes()).unwrap();
            assert_eq!(signs.number, 5);
            assert_eq!(next_change(&read, true), 5);
            joins(&signs, &[&f.statement, &apart, &third]);
        }
    }

    /// **The change that the question names is the one that is signed**
    /// (decision 2026-10-24, rule 1): the number it says is the number of
    /// the statement that is prepared, for a renewal, a removal and a
    /// settlement.
    #[test]
    fn the_change_that_the_question_names_is_the_one_signed() {
        let f = Fixture::new();
        let own = f.own.public_key();
        let mut handed = f.handed(&f.statement, &[]);
        let read = f.read(&handed).unwrap();
        let stay = f.statement.statement.devices.clone();
        let signs = |prepared: Prepared| Statement::from_bytes(prepared.bytes()).unwrap().number;
        let renewal = prepare_change(&f.statement, &own, stay.clone(), &[]).unwrap();
        assert_eq!(next_change(&read, false), signs(renewal));
        let mut stays = stay.clone();
        stays.retain(|device| device.key != f.listed);
        let removal = prepare_change(&f.statement, &own, stays, &[f.listed]).unwrap();
        assert_eq!(next_change(&read, false), signs(removal));
        // Made apart: the other change is numbered above this one.
        let (apart, apart_entry) = f.apart(2);
        handed["heads"] = json!([{
            "statement": hex::encode(apart.to_bytes().unwrap()),
            "entry": hex::encode(apart_entry.to_wire()),
        }]);
        let read = f.read(&handed).unwrap();
        let mut both = stay.clone();
        both.extend(
            apart
                .statement
                .devices
                .iter()
                .filter(|device| !stay.iter().any(|listed| listed.key == device.key))
                .cloned(),
        );
        let settlement =
            prepare_settlement(&f.statement, std::slice::from_ref(&apart), &own, both, &[])
                .unwrap();
        assert_eq!(next_change(&read, true), signs(settlement));
        assert_eq!(next_change(&read, true), 4);
    }

    /// A statement's lists are shown from the statement: each device by
    /// its label and the first four words of its key's fingerprint, and
    /// each key that it removes beyond those of the statement before, by
    /// its words.
    #[test]
    fn the_lists_that_are_shown_are_read_from_the_statement() {
        let f = Fixture::new();
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let handed = f
            .read(&f.handed(&f.statement, &[f.adds(key(5), "desktop")]))
            .unwrap();
        let own = f.own.public_key();
        // The next statement: the desktop stays, and a key is removed.
        let mut stay = f.statement.statement.devices.clone();
        stay.push(Device::new(key(5), "desktop").unwrap());
        let prepared = prepare_change(&f.statement, &own, stay, &[key(6)]).unwrap();
        let signs = Statement::from_bytes(prepared.bytes()).unwrap();
        let shown = lists_shown(&signs, &handed).unwrap();
        assert_eq!(
            shown,
            [
                format!("  made on ({}) \"laptop\"", fingerprint::shown(&own)),
                "  devices (3):".to_string(),
                format!(
                    "    ({}) \"laptop\"  (this device)",
                    fingerprint::shown(&own)
                ),
                format!("    ({}) \"phone\"", fingerprint::shown(&f.listed)),
                format!("    ({}) \"desktop\"", fingerprint::shown(&key(5))),
                "  removed keys (1):".to_string(),
                format!("    ({})", fingerprint::shown(&key(6))),
                "  and the 1 key that earlier changes removed".to_string(),
            ]
        );
        // The statement that the device has applied, shown as it is: its
        // one removed key is its own.
        let shown = lists_shown(&f.statement.statement, &handed).unwrap();
        assert_eq!(shown.len(), 6);
        assert_eq!(shown[4], "  removed keys (1):");
        assert_eq!(
            shown[5],
            format!("    ({})", fingerprint::shown(&f.removed))
        );
    }

    /// A new key takes the place of the old one whole (decision
    /// 2026-10-04 §16): it is written beside the key file and renamed
    /// over it, is the device's alone to read, and leaves nothing beside
    /// it. Where it cannot be written, the key file is as it was.
    #[test]
    fn a_new_key_is_written_beside_the_key_file_and_renamed_over_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let beside = dir.path().join("identity.key.new");
        std::fs::write(&path, [1u8; 32]).unwrap();
        // What an earlier run left beside it is not written through.
        std::fs::write(&beside, b"left by a run that was stopped").unwrap();
        give_new_key(&path, &[2u8; 32], || Forgot::Yes).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), [2u8; 32]);
        assert!(!beside.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // It is another file than the one that was there: the old one was
        // not written into.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let before = std::fs::metadata(&path).unwrap().ino();
            let kept_open = std::fs::File::open(&path).unwrap();
            give_new_key(&path, &[3u8; 32], || Forgot::Yes).unwrap();
            assert_ne!(std::fs::metadata(&path).unwrap().ino(), before);
            let mut still = Vec::new();
            std::io::Read::read_to_end(&mut &kept_open, &mut still).unwrap();
            assert_eq!(still, [2u8; 32], "the old file was written into");
        }
    }

    /// `cordelia init --new-key` writes the new key beside the old one
    /// first, then has the node forget, and only then puts the new key in
    /// the old one's place (decision 2026-10-04 §5.2, §16). Where any of
    /// the three fails it says what state the device is in, and nothing
    /// is left beside the key file.
    #[test]
    fn a_new_key_is_on_the_disk_before_the_node_forgets_and_each_failure_says_the_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let beside = dir.path().join("identity.key.new");
        std::fs::write(&path, [1u8; 32]).unwrap();
        let as_it_was = || {
            assert_eq!(std::fs::read(&path).unwrap(), [1u8; 32]);
            assert!(!beside.exists(), "something was left beside the key file");
        };

        // When the node is asked to forget, the new key is on the disk
        // beside the old one, whole, and the key file is the old one.
        let asked = std::cell::Cell::new(0);
        give_new_key(&path, &[2u8; 32], || {
            asked.set(asked.get() + 1);
            assert_eq!(std::fs::read(&beside).unwrap(), [2u8; 32]);
            assert_eq!(std::fs::read(&path).unwrap(), [1u8; 32]);
            Forgot::Yes
        })
        .unwrap();
        assert_eq!(asked.get(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), [2u8; 32]);
        assert!(!beside.exists());
        std::fs::write(&path, [1u8; 32]).unwrap();

        // The new key cannot be written: the node is not asked to forget,
        // and nothing was changed.
        let nowhere = dir.path().join("no-such-folder").join("identity.key");
        let refused = give_new_key(&nowhere, &[4u8; 32], || {
            panic!("the node was asked to forget before the new key was written")
        })
        .unwrap_err()
        .to_string();
        assert!(refused.contains("could not write the new key"), "{refused}");
        assert!(refused.contains("nothing was changed"), "{refused}");
        assert!(refused.contains("keeps the key it had"), "{refused}");

        // The node refuses to forget: the device keeps its key and what
        // it holds.
        let refused = give_new_key(&path, &[2u8; 32], || Forgot::No("the node is busy".into()))
            .unwrap_err()
            .to_string();
        assert!(refused.starts_with("the node is busy\n"), "{refused}");
        assert!(
            refused.contains("keeps the key it had and what it holds"),
            "{refused}"
        );
        as_it_was();

        // The node's answer is lost: the device keeps its key, and is
        // told where to look.
        let lost = give_new_key(&path, &[2u8; 32], || {
            Forgot::NotKnown("the answer was lost".into())
        })
        .unwrap_err()
        .to_string();
        assert!(lost.starts_with("the answer was lost\n"), "{lost}");
        assert!(
            lost.contains("It is not known whether the node forgot"),
            "{lost}"
        );
        assert!(lost.contains("`cordelia devices` says"), "{lost}");
        as_it_was();

        // The node forgot, and the new key cannot take the old one's
        // place: where the key file is, there is a folder that holds
        // something.
        let folder = dir.path().join("a-folder.key");
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("held"), "x").unwrap();
        let not_placed = give_new_key(&folder, &[2u8; 32], || Forgot::Yes)
            .unwrap_err()
            .to_string();
        assert!(
            not_placed.contains("the node has forgotten what it held"),
            "{not_placed}"
        );
        assert!(
            not_placed.contains("keeps the key it had, and follows no recovery phrase"),
            "{not_placed}"
        );
        assert!(!dir.path().join("a-folder.key.new").exists());
        assert!(folder.join("held").exists());
    }

    /// The command that a change goes on to is one that this program
    /// runs, with the change's number and nothing else (decision
    /// 2026-10-04 §16).
    #[test]
    fn the_wait_that_follows_a_change_is_a_command_of_this_program() {
        use clap::Parser;
        let read = crate::Cli::try_parse_from(["cordelia", STAYS_COMMAND, "3"]);
        let Ok(read) = read else {
            panic!("`cordelia {STAYS_COMMAND} 3` is no command");
        };
        assert!(matches!(
            read.command,
            Some(crate::Commands::ChangeMade { number: 3, .. })
        ));
        // It is not among the commands that the help lists.
        use clap::CommandFactory;
        let help = crate::Cli::command().render_long_help().to_string();
        assert!(!help.contains(STAYS_COMMAND), "{help}");
        assert!(help.contains("remove-device"), "{help}");
    }

    /// Wherever a device is shown, the words of its key's fingerprint
    /// come first and its label after them, quoted (decision 2026-10-04
    /// §16). A label that holds brackets, words of the list and a quote
    /// shows no counterfeit words ahead of the real ones, and does not
    /// end its own quotes.
    #[test]
    fn the_words_of_a_fingerprint_come_first_and_the_label_after_them_quoted() {
        let key = NodeIdentity::from_seed([9; 32]).unwrap().public_key();
        let words = fingerprint::shown(&key);
        assert_eq!(named("laptop", &key), format!("({words}) \"laptop\""));
        assert_eq!(named("", &key), format!("the device ({words})"));
        let forged = "laptop (acid acid acid acid)\" (zoo";
        assert_eq!(
            named(forged, &key),
            format!("({words}) \"laptop (acid acid acid acid)\\\" (zoo\"")
        );
        // A device that the node shows is shown likewise.
        let from_the_node = json!({ "label": forged, "words": words });
        assert_eq!(shown(&from_the_node), named(forged, &key));
        assert_eq!(
            shown(&json!({ "label": "", "words": words })),
            named("", &key)
        );
    }

    /// What `cordelia status` says of a device and its person in a few
    /// words: the words that the node gives where it has any, and
    /// otherwise how many devices there are, counting those added since
    /// that count.
    #[test]
    fn status_says_in_a_few_words_where_a_device_stands() {
        let (short, says) = status_lines(&json!({
            "short": "not added yet",
            "says": ["no recovery phrase yet: memory stays on this machine."],
        }));
        assert_eq!(short, "not added yet");
        assert_eq!(
            says,
            ["no recovery phrase yet: memory stays on this machine."]
        );
        let (short, says) = status_lines(&json!({ "change": 1, "devices": [{}], "says": [] }));
        assert_eq!(
            short,
            "this device alone, under a recovery phrase (change 1)"
        );
        assert!(says.is_empty());
        let (short, _) = status_lines(&json!({
            "change": 4,
            "devices": [{}, {}],
            "added": [{ "counted": true }, { "counted": false }],
        }));
        assert_eq!(short, "3 devices under a recovery phrase (change 4)");
    }

    /// What a removal shows of names and of the device that goes
    /// (decision 2026-10-04 §7.1, step 2): each name that only the keys
    /// which the change removes sync, and how much that device wrote that
    /// this one received in the last day and the last week.
    #[test]
    fn a_removal_shows_the_names_only_that_device_syncs_and_what_arrived_from_it() {
        let f = Fixture::new();
        let own = f.own.public_key();
        let key = |key: &[u8; 32]| encode_public_key(key).unwrap();
        let mut handed = f.handed(&f.statement, &[]);
        handed["names"] = json!([
            { "name": "both", "by": [key(&own), key(&f.listed)] },
            { "name": "only-its", "by": [key(&f.listed)] },
            { "name": "mine", "by": [key(&own)] },
            { "name": "nobodys", "by": [] },
        ]);
        handed["received"] = json!({ key(&f.listed): { "day": 1, "week": 12 } });
        let read = f.read(&handed).unwrap();

        // The names that stay behind where the other device is removed.
        let goes = f.listed;
        assert_eq!(read.names_only_of(|key| *key == goes), ["only-its"]);
        // Where nobody is removed, none does: a renewal.
        assert!(read.names_only_of(|_| false).is_empty());
        // Where both keys that list a name go, it stays behind too.
        assert_eq!(read.names_only_of(|_| true), ["both", "only-its", "mine"]);

        assert_eq!(
            read.received_from(&goes),
            "Of what it wrote, this device received 1 version in the last day, and 12 versions \
             in the last week."
        );
        // A device from which nothing arrived.
        assert_eq!(
            read.received_from(&f.removed),
            "Of what it wrote, this device received 0 versions in the last day, and 0 versions \
             in the last week."
        );
        // With local history off, it cannot be said, and that is said.
        handed["received"] = Value::Null;
        let read = f.read(&handed).unwrap();
        assert!(
            read.received_from(&goes)
                .starts_with("Local history is off")
        );
    }

    /// What is handed as a name and is none is not shown at the prompt of
    /// a removal, whoever handed it: it is counted for the device that
    /// lists it, and said as a number (decision 2026-10-04 §16).
    #[test]
    fn what_is_handed_as_a_name_and_is_none_is_counted_and_not_shown() {
        let f = Fixture::new();
        let own = f.own.public_key();
        let key = |key: &[u8; 32]| encode_public_key(key).unwrap();
        let mut handed = f.handed(&f.statement, &[]);
        let long = "x".repeat(60_000);
        handed["names"] = json!([
            { "name": "only-its", "by": [key(&f.listed)] },
            { "name": "\u{1b}[2J\u{1b}[31mMake this change?", "by": [key(&f.listed)] },
            { "name": "two\nlines", "by": [key(&f.listed)] },
            { "name": long, "by": [key(&f.listed)] },
            { "name": "In-Capitals", "by": [key(&f.listed)] },
            { "name": "spelled.git", "by": [key(&own), key(&f.listed)] },
        ]);
        // And what the node says it has counted itself.
        handed["names_not_shown"] = json!([
            { "by": key(&f.listed), "words": 3 },
            { "by": key(&own), "words": 1 },
            { "by": "no key", "words": 9 },
        ]);
        let read = f.read(&handed).unwrap();
        assert_eq!(read.names_only_of(|_| true), ["only-its"]);
        let goes = f.listed;
        assert_eq!(read.names_not_shown_of(|key| *key == goes), 5 + 3);
        assert_eq!(read.names_not_shown_of(|key| *key == own), 1 + 1);
        assert_eq!(read.names_not_shown_of(|_| false), 0);
        assert_eq!(
            not_shown_stay_behind(8),
            "8 names that cannot be shown stay behind too: a device that is removed listed \
             them, and what they are called is not a name as this version writes one."
        );
        assert!(not_shown_stay_behind(1).starts_with("1 name that cannot be shown stays behind"));
    }

    /// What the wait after a change says of what is missing, as it goes on
    /// (decision 2026-10-04 §7.1, step 4; §8; decision 2026-10-19 §3, §5):
    /// whether each relay holds the change, as the node knows it; a relay
    /// that is not connected, by name or by the row of what waits that it
    /// lacks; what is still to send; and this device's own word. A relay
    /// that took the change and was lost before the names went leaves the
    /// names unsaid. A relay out of reach is said by S2 or S3, in place of
    /// the line that it is not connected, and does not keep the names from
    /// being said to be sent. Which row is this device's goes by its key,
    /// from its key file, and not by the node's word of it (§16).
    #[test]
    fn the_wait_says_what_is_missing_of_each_relay_and_of_what_is_sent() {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let written = |n: u8| encode_public_key(&key(n)).unwrap();
        let reach = |holds: &str, out: Option<i64>| {
            json!({ "about": "0101", "lacks_for": null,
                    "class": null, "holds": holds, "reached": out.is_none(),
                    "out_of_reach_since": out, "reference": 0, "last_reached": null,
                    "waits": null, "refusing_waits_since": null, "no_room": null })
        };
        let look = |not_reached: Value, waiting: Value, to_go: Value, own: Value| {
            json!({
                "change": 3,
                "latest": "0101",
                "relays": [{ "relay": "relay.example:9474", "reach": reach("holds", None) }],
                "not_reached": not_reached,
                "waiting": waiting,
                "names": { "sent": ["lab"], "to_go": to_go },
                "devices": [
                    { "key": written(1), "label": "desktop", "words": "w",
                      "applied": own["applied"], "sent": own["sent"] },
                    // Another device's word is not this device's, though
                    // the node should say that the row is this device's.
                    { "key": written(2), "label": "laptop", "words": "w", "this_device": true,
                      "applied": 3, "sent": true },
                ],
            })
        };
        let reached = json!([{ "relay": "127.0.0.1:9474", "waits": 0 }]);
        let sent = json!({ "applied": 3, "sent": true });
        let not_sent = json!({ "applied": 3, "sent": false });
        let lines = |seen: &Value| after_a_change(seen, 3, &key(1), 0);
        let missing = |seen: &Value| {
            lines(seen)
                .into_iter()
                .filter(|line| line.starts_with("keep this machine on"))
                .count()
        };

        let all = lines(&look(json!([]), reached.clone(), json!([]), sent.clone()));
        assert!(all.contains(&"1 name sent".to_string()), "{all:?}");
        assert!(
            all.contains(&"relay.example:9474 holds the change".to_string()),
            "{all:?}"
        );
        assert_eq!(
            missing(&look(json!([]), reached.clone(), json!([]), sent.clone())),
            0
        );

        // The relay took the change, and the connection was lost before
        // the names went: no row says what waits there, and no name is
        // known to be still to go.
        let lost = look(
            json!(["relay.example:9474"]),
            json!([]),
            json!([]),
            not_sent.clone(),
        );
        assert_eq!(missing(&lost), 2);
        let said = lines(&lost).join("\n");
        // Nor is a name said to be sent: that is not known of a relay
        // that is not reached.
        assert!(!said.contains("1 name sent"), "{said}");
        assert!(
            said.contains(
                "keep this machine on: relay.example:9474 is not connected, and what is still \
                 to send there is not known until it is"
            ),
            "{said}"
        );
        assert!(
            said.contains(
                "keep this machine on: this device has not yet sent every relay what it carried"
            ),
            "{said}"
        );

        // A relay for which there is no row of what waits is not reached,
        // though the node has not named it so yet.
        let no_row = look(json!([]), json!([]), json!([]), sent.clone());
        assert_eq!(missing(&no_row), 1);
        let said = lines(&no_row).join("\n");
        assert!(
            said.contains("a relay that this device is set up with is not connected"),
            "{said}"
        );
        assert!(!said.contains("1 name sent"), "{said}");

        // Each alone is missing.
        let not_reached = look(
            json!(["relay.example:9474"]),
            json!([]),
            json!([]),
            sent.clone(),
        );
        assert_eq!(missing(&not_reached), 1);
        for own in [
            not_sent.clone(),
            // Its word of the change before says nothing of this one.
            json!({ "applied": 2, "sent": true }),
            json!({}),
        ] {
            let seen = look(json!([]), reached.clone(), json!([]), own.clone());
            assert_eq!(missing(&seen), 1, "{own}");
        }
        let to_go = look(json!([]), reached.clone(), json!(["team"]), sent.clone());
        assert_eq!(missing(&to_go), 1);
        assert!(
            lines(&to_go)
                .contains(&"keep this machine on: 1 name still to send (1 sent)".to_string())
        );
        let waits = json!([{ "relay": "127.0.0.1:9474", "waits": 2 }]);
        assert_eq!(missing(&look(json!([]), waits, json!([]), sent.clone())), 1);
        // A relay that does not hold the change is missing, as before.
        let mut behind = look(json!([]), reached.clone(), json!([]), sent.clone());
        behind["relays"][0]["reach"]["holds"] = json!("lacks");
        assert_eq!(missing(&behind), 1);
        assert!(lines(&behind).contains(
            &"keep this machine on: relay.example:9474 does not hold the change yet".to_string()
        ));

        // Out of reach and lacking the change: S2, in place of the line
        // that it is not connected. The names are said to be sent, over
        // the relays that are reached.
        let mut out = look(
            json!(["relay.example:9474"]),
            json!([]),
            json!([]),
            sent.clone(),
        );
        out["relays"][0]["reach"] = reach("lacks", Some(0));
        let said = lines(&out);
        assert!(said.contains(
            &"keep this machine on: relay.example:9474 cannot be reached from here, and is not \
              known to hold the change yet: it has not answered since this device started at \
              00:00 UTC"
                .to_string()
        ), "{said:?}");
        assert!(!said.join("\n").contains("is not connected"), "{said:?}");
        assert!(said.contains(&"1 name sent".to_string()), "{said:?}");
        // Out of reach and holding it: S3.
        out["relays"][0]["reach"] = reach("holds", Some(0));
        let said = lines(&out);
        assert!(
            said.contains(
                &"relay.example:9474 holds the change, and cannot be reached from here: it has \
                  not answered since this device started at 00:00 UTC"
                    .to_string()
            ),
            "{said:?}"
        );
        assert_eq!(missing(&out), 0, "{said:?}");
        // What is known of a relay from before the change says nothing of
        // it: it is not said to hold the change, nor to be out of reach.
        out["relays"][0]["reach"]["about"] = json!("0202");
        let said = lines(&out);
        assert!(
            said.contains(
                &"keep this machine on: relay.example:9474 does not hold the change yet"
                    .to_string()
            ),
            "{said:?}"
        );
    }

    /// A node whose looks are given, each at its time of day: the clock
    /// that the wait goes by is the test's, and moves to each look's time
    /// as the look is asked for. Where no look is left, the wait ends as an
    /// error.
    struct Looks {
        own: [u8; 32],
        looks: std::cell::RefCell<Vec<(i64, Value)>>,
        at: std::cell::Cell<i64>,
    }

    impl Looks {
        fn from(at: i64, looks: Vec<(i64, Value)>) -> Self {
            Self {
                own: NodeIdentity::from_seed([1; 32]).unwrap().public_key(),
                looks: std::cell::RefCell::new(looks),
                at: std::cell::Cell::new(at),
            }
        }

        /// What the wait says of these looks, and how it ends.
        fn said(&self) -> (anyhow::Result<Waited>, Vec<String>) {
            let mut said = Vec::new();
            let waited = waits_after(3, None, self, |line| said.push(line));
            (waited, said)
        }
    }

    impl AfterAChange for Looks {
        fn own(&self) -> anyhow::Result<[u8; 32]> {
            Ok(self.own)
        }
        fn look(&self) -> anyhow::Result<Value> {
            let mut looks = self.looks.borrow_mut();
            if looks.is_empty() {
                anyhow::bail!("no look is left");
            }
            let (at, seen) = looks.remove(0);
            self.at.set(at);
            Ok(seen)
        }
        fn another_version(&self) -> anyhow::Result<Option<String>> {
            Ok(None)
        }
        fn pause(&self) {}
        fn now(&self) -> i64 {
            self.at.get()
        }
    }

    /// 10:53:00 UTC on 2026-10-19, in seconds: the time of the change.
    const AT_10_53: i64 = 1_792_407_180;

    /// A look after change 3, with relays met by `scenarios`, and this
    /// device's word as `word`, with no word to come.
    fn after(scenarios: &[wait::tests::Scenario], word: wait::OwnWord) -> Value {
        use wait::tests::{look_at, reached};
        let relays: Vec<_> = scenarios.iter().map(|s| (*s, reached(*s))).collect();
        look_at(&relays, word, false)
    }

    /// Whether `line` starts with a time as each line of the wait does:
    /// two spaces, the hour, minute and second, and two spaces.
    fn has_its_time(line: &str) -> bool {
        let b = line.as_bytes();
        let digit = |at: usize| b.get(at).is_some_and(u8::is_ascii_digit);
        line.starts_with("  ")
            && [2, 3, 5, 6, 8, 9].into_iter().all(digit)
            && b.get(4) == Some(&b':')
            && b.get(7) == Some(&b':')
            && line.get(10..12) == Some("  ")
    }

    /// **Each line of the wait starts with its time, and is said once**
    /// (decision 2026-10-24, rule 3): two looks with the same lines at two
    /// times say each line once, at the time of the first; a line is new
    /// by its words, not its time. S1 says that the times are in UTC, and
    /// every line after it, to the line that the end begins with, starts
    /// with its time.
    #[test]
    fn each_line_of_the_wait_starts_with_its_time_and_is_said_once() {
        use wait::OwnWord;
        use wait::tests::Scenario::{Moving, Ok as Reached};
        let pending = after(&[Reached, Moving], OwnWord::None);
        let node = Looks::from(
            AT_10_53,
            vec![
                (AT_10_53 + 2, pending.clone()),
                (AT_10_53 + 30, pending),
                (AT_10_53 + 40, after(&[Reached, Reached], OwnWord::Sent)),
            ],
        );
        let (waited, said) = node.said();
        assert_eq!(waited.unwrap(), Waited::Ended(wait::End::Done), "{said:?}");
        assert_eq!(said[0], wait::first_line());
        assert!(
            said[0].ends_with(
                "Until the wait ends, each line below starts with the time it was said, in UTC."
            ),
            "{said:?}"
        );
        let ended = said
            .iter()
            .position(|line| line.ends_with("  The wait has ended."))
            .unwrap();
        for line in &said[1..=ended] {
            assert!(has_its_time(line), "{line}: {said:?}");
        }
        let holds = |relay: &str| -> Vec<&String> {
            let line = format!("{relay} holds the change");
            said.iter().filter(|said| said.ends_with(&line)).collect()
        };
        assert_eq!(
            holds("relay-0.example:9474"),
            ["  10:53:02  relay-0.example:9474 holds the change"]
        );
        assert_eq!(holds("relay-1.example:9474").len(), 1, "{said:?}");
        assert_eq!(said[ended], "  10:53:40  The wait has ended.");
    }

    /// **Where no line has been said for a minute, the wait says that it
    /// is still waiting** (decision 2026-10-24, rule 3), naming the time of
    /// the last line that was not that: nothing at 59 seconds, the line at
    /// 60, and again at 120, naming the same time. A new line is said as it
    /// comes, and the next is a minute after it.
    #[test]
    fn still_waiting_is_said_after_a_minute_with_no_new_line() {
        use wait::OwnWord;
        use wait::tests::Scenario::{Moving, Ok as Reached};
        let pending = after(&[Reached, Moving], OwnWord::None);
        let mut one_more = pending.clone();
        one_more["names"] = json!({ "sent": [], "to_go": ["lab"] });
        // The first look at 10:53:01; a new line at 150 seconds after it.
        let first = AT_10_53 + 1;
        let looks = [
            (0, &pending),
            (59, &pending),
            (60, &pending),
            (119, &pending),
            (120, &pending),
            (150, &one_more),
            (209, &one_more),
            (210, &one_more),
        ];
        let looks = looks.map(|(after, seen)| (first + after, seen.clone()));
        let (_, said) = Looks::from(AT_10_53, looks.to_vec()).said();
        let still: Vec<&String> = said
            .iter()
            .filter(|line| line.contains("still waiting"))
            .collect();
        assert_eq!(
            still,
            [
                "  10:54:01  still waiting: no new line since 10:53:01",
                "  10:55:01  still waiting: no new line since 10:53:01",
                "  10:56:31  still waiting: no new line since 10:55:31",
            ],
            "{said:?}"
        );
        assert!(
            said.iter()
                .any(|line| line
                    == "  10:55:31  keep this machine on: 1 name still to send (0 sent)"),
            "{said:?}"
        );
    }

    /// **No line says that the wait is still waiting at a look that ends
    /// it** (decision 2026-10-24, rule 3): a minute after the last line, a
    /// look with no new line that ends the wait says only the line that it
    /// has ended, and then what the end says.
    #[test]
    fn no_still_waiting_line_comes_beside_the_end() {
        use wait::OwnWord;
        use wait::tests::Scenario::{Ok as Reached, OutHolding};
        // End 2 once the node says that no word is to come; the same lines
        // before, while it says one is.
        let ends = after(&[Reached, OutHolding], OwnWord::Carried);
        let mut goes_on = ends.clone();
        goes_on["word_to_come"] = json!(true);
        let looks = vec![(AT_10_53 + 1, goes_on), (AT_10_53 + 61, ends)];
        let (waited, said) = Looks::from(AT_10_53, looks).said();
        assert_eq!(
            waited.unwrap(),
            Waited::Ended(wait::End::Warned),
            "{said:?}"
        );
        assert!(
            !said.iter().any(|line| line.contains("still waiting")),
            "{said:?}"
        );
        assert!(
            said.iter()
                .any(|line| line == "  10:54:01  The wait has ended."),
            "{said:?}"
        );
    }

    /// **`cordelia init --new-key` names each relay that it could not send
    /// to as it is configured** (decision 2026-10-24, rule 2): by the name
    /// of its row, both names of a connection that two relays given no
    /// key share, and never the address it was reached at.
    #[test]
    fn init_new_key_names_each_relay_it_could_not_send_to_as_configured() {
        let sent = json!({ "waiting": [
            { "relay": "127.0.0.1:9474", "name": "localhost:9474", "waits": 2 },
            { "relay": "127.0.0.1:9475", "name": null,
              "names": ["localhost:9475", "loopback.example:9475"], "waits": 1 },
            { "relay": "192.0.2.9:9474", "name": null, "names": [], "waits": 1 },
            { "relay": "192.0.2.8:9474", "name": "sent.example:9474", "waits": 0 },
        ]});
        assert_eq!(
            still_to_send_to(&sent),
            [
                "localhost:9474",
                "localhost:9475 and loopback.example:9475",
                UNNAMED_RELAY,
            ]
        );
    }

    /// **Each end begins with the line that the wait has ended** (decision
    /// 2026-10-24, rule 3), with its time; the lines of the end come under
    /// it as they were, with none: end 1, end 2 and end 3, and where the
    /// device has since applied another change or no longer stands in its
    /// phrase.
    #[test]
    fn each_end_begins_with_the_wait_has_ended() {
        use wait::OwnWord;
        use wait::tests::Scenario::{Ok as Reached, OutHolding, OutLacking};
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let at = AT_10_53 + 5;
        let mut another = after(&[Reached], OwnWord::Sent);
        another["change"] = json!(4);
        let mut removed = after(&[Reached], OwnWord::Sent);
        removed["state"] = json!("removed");
        removed["cannot_go_on"] = json!("this device was removed");
        for seen in [
            after(&[Reached, Reached], OwnWord::Sent),
            after(&[Reached, OutHolding], OwnWord::Carried),
            after(&[Reached, OutLacking], OwnWord::None),
            another,
            removed,
        ] {
            let (waited, said) = Looks::from(AT_10_53, vec![(at, seen.clone())]).said();
            let ended = said
                .iter()
                .position(|line| line == "  10:53:05  The wait has ended.")
                .unwrap_or_else(|| panic!("{said:?}"));
            let end_says: Vec<String> = match waited.unwrap() {
                Waited::Ended(end) => {
                    let (relays, word, _) = wait::end_of_look(&seen, 3, &own).unwrap();
                    wait::end_lines(end, &relays, word, at)
                }
                Waited::Another => vec![
                    "This device has since applied another change: `cordelia devices` says.".into(),
                ],
                Waited::NoLongerStands => vec![wait::no_longer_stands(&seen).unwrap()],
                Waited::Moved => unreachable!("no change was named, so none was moved from"),
            };
            assert_eq!(said[ended + 1..], end_says, "{said:?}");
            assert!(
                said[ended + 1..].iter().all(|line| !has_its_time(line)),
                "{said:?}"
            );
        }
    }

    /// **A device that moves from the change ends the wait with status 3**
    /// (decision 2026-10-24 (removal), rule 9), and says why, in the words
    /// the node noted at the move: at another number and at the same one,
    /// where the look names the change entry that the command made as one
    /// the device moved from. A look that keeps another entry than the one
    /// made, with no move from it, is another change; and a move from
    /// another entry is not this change's.
    #[test]
    fn a_device_that_moves_from_the_change_ends_the_wait_with_status_3() {
        use wait::OwnWord;
        use wait::tests::{KEPT, Scenario::Ok as Reached};
        let made = hex::encode(KEPT);
        let says = "a change made apart on (w) \"desktop\" removed (x) \"tablet\", which this \
                    change lists: this device follows that change now";
        let waited_on = |seen: Value| {
            let node = Looks::from(AT_10_53, vec![(AT_10_53 + 5, seen)]);
            let mut said = Vec::new();
            let waited = waits_after(3, Some(&made), &node, |line| said.push(line));
            (waited, said)
        };
        let moved = |number: u64| {
            let mut seen = after(&[Reached], OwnWord::Sent);
            seen["change"] = json!(number);
            seen["latest"] = json!(hex::encode([9u8; 32]));
            seen["moved"] = json!([{ "from": made, "says": says }]);
            seen
        };
        for number in [2, 3, 4] {
            let (waited, said) = waited_on(moved(number));
            let waited = waited.unwrap();
            assert_eq!(waited, Waited::Moved, "{said:?}");
            assert_eq!(status_of(&Ok(waited)), 3);
            assert_eq!(said.last().map(String::as_str), Some(says), "{said:?}");
            assert!(
                said.iter()
                    .any(|line| line == "  10:53:05  The wait has ended."),
                "{said:?}"
            );
        }
        // Another entry kept at the same number, with no move from this
        // one: another change.
        let mut another = moved(3);
        another["moved"] = json!([{ "from": hex::encode([7u8; 32]), "says": says }]);
        let (waited, said) = waited_on(another);
        assert_eq!(waited.unwrap(), Waited::Another, "{said:?}");
        // The entry made, still kept: the wait ends as it would.
        let (waited, said) = waited_on(after(&[Reached, Reached], OwnWord::Sent));
        assert_eq!(waited.unwrap(), Waited::Ended(wait::End::Done), "{said:?}");
    }

    /// **The count of a relay that the wait waits out** (decision
    /// 2026-10-24, rule 4): a relay not reached, its reference 30 seconds
    /// ago, gives no count; at 3 minutes and 10 seconds, 3 of the 5; at 4,
    /// 4 of the 5; at 5 and 6 minutes and in no class, that it has not been
    /// reached in the minutes that the command has waited for it, and that
    /// the command stops waiting once this machine has tried it again and
    /// failed; out of reach, no count. A relay that refuses the change
    /// counts from when it came to refuse it, from minute 1 to minute 4.
    #[test]
    fn the_count_of_a_relay_waited_out() {
        use wait::OwnWord;
        use wait::tests::Scenario::{Dialling, LacksForAMoment, Ok as Reached};
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let at = AT_10_53 + 600;
        let counts = |seen: &Value| -> Vec<String> {
            after_a_change(seen, 3, &own, at)
                .into_iter()
                .filter(|line| line.contains(" for ") && line.contains("relay-1"))
                .collect()
        };
        let mut seen = after(&[Reached, Dialling], OwnWord::None);
        let reach = |seen: &mut Value, field: &str, value: Value| {
            seen["relays"][1]["reach"][field] = value;
        };
        let of_the_five = |m: u64| {
            format!(
                "relay-1.example:9474 has not been reached for {m} of the 5 minutes that this \
                 command waits for it"
            )
        };
        // From minute 5, the minutes of the wait, in which it was not
        // reached: not for how long it has not been, since it may have been
        // lost before the change.
        let waited = |m: u64| {
            format!(
                "relay-1.example:9474 has not been reached in the {m} minutes that this command \
                 has waited for it. This command stops waiting for it once this machine has tried \
                 it again and failed."
            )
        };
        for (ago, said) in [
            (30, None),
            (190, Some(of_the_five(3))),
            (245, Some(of_the_five(4))),
            (305, Some(waited(5))),
            (360, Some(waited(6))),
        ] {
            reach(&mut seen, "reference", json!(at - ago));
            assert_eq!(counts(&seen), Vec::from_iter(said), "{ago}");
        }
        reach(&mut seen, "out_of_reach_since", json!(at - 10));
        reach(&mut seen, "class", json!("out_lacking"));
        assert!(counts(&seen).is_empty(), "{:?}", counts(&seen));

        let mut seen = after(&[Reached, LacksForAMoment], OwnWord::None);
        for (ago, said) in [(30, None), (130, Some(2)), (250, Some(4)), (310, None)] {
            reach(&mut seen, "refused_since", json!(at - ago));
            let count = said.map(|m: u64| {
                format!(
                    "relay-1.example:9474 has refused the change for {m} of the 5 minutes that \
                     this command waits for it"
                )
            });
            assert_eq!(counts(&seen), Vec::from_iter(count), "{ago}");
        }
    }

    /// The exit status of the wait after a change (decision 2026-10-19 §4,
    /// rule 8): 0 only at ends 1 and 2; 3 at end 3, where the wait cannot
    /// be started, on an error in the wait, and where the device has since
    /// applied another change. 1 and 2 are never given once the change is
    /// made: they are what `main` and the argument parser give.
    #[test]
    fn the_statuses() {
        use wait::End;
        assert_eq!(NOT_AT_EVERY_RELAY_STATUS, 3);
        assert_eq!(status_of(&Ok(Waited::Ended(End::Done))), 0);
        assert_eq!(status_of(&Ok(Waited::Ended(End::Warned))), 0);
        assert_eq!(status_of(&Ok(Waited::Ended(End::NotDone))), 3);
        assert_eq!(status_of(&Ok(Waited::Another)), 3);
        assert_eq!(status_of(&Ok(Waited::Moved)), 3);
        assert_eq!(status_of(&Ok(Waited::NoLongerStands)), 3);
        assert_eq!(status_of(&Err(anyhow::anyhow!("the node stopped"))), 3);
        let (said, status) = wait_not_started(&"no such file");
        assert_eq!(status, 3);
        assert_eq!(
            said,
            "This command could not go on to say what is still missing (no such file). The node \
             goes on by itself: `cordelia devices` shows whether each relay holds the change, and \
             what this device has still to send. Keep this machine on until every relay holds \
             the change and nothing is left to send."
        );
    }

    /// A command that has the device begin again says before its yes how
    /// much the device holds that it has sent to no relay (decision
    /// 2026-10-04 §16): how many versions, of how many names, as the node
    /// counts them. It refuses nothing. Nothing is said where nothing
    /// waits, or beside a node that does not say.
    #[test]
    fn beginning_again_says_what_the_device_has_sent_to_no_relay() {
        let seen = |versions: u64, names: u64| json!({ "sent_to_no_relay": { "versions": versions, "names": names } });
        assert_eq!(waits_says(&seen(0, 0)), None);
        // A look that was not asked for the count carries none.
        assert_eq!(waits_says(&json!({ "among": "alone" })), None);
        // Only a look for a command that has the device begin again
        // asks for it.
        assert_eq!(look_asks(false), json!({}));
        assert_eq!(look_asks(true), json!({ "sent_to_no_relay": true }));
        assert_eq!(
            waits_says(&seen(1, 1)).unwrap(),
            "1 version of 1 name that this device holds has been sent to no relay yet: it is \
             let go with everything else that it holds."
        );
        assert_eq!(
            waits_says(&seen(5, 2)).unwrap(),
            "5 versions of 2 names that this device holds have been sent to no relay yet: they \
             are let go with everything else that it holds."
        );
    }

    /// `cordelia accept` on a device that is alone under a recovery
    /// phrase leaves that phrase, which lets go of everything that the
    /// device holds: what it has sent to no relay is said before its
    /// yes, as before any beginning again (decision 2026-10-04 §5.1,
    /// §16). Where nothing waits, the yes says what it said.
    #[test]
    fn accepting_alone_says_what_the_device_has_sent_to_no_relay() {
        let leaves = "The recovery phrase that this device follows stops working here: this \
                      device leaves it, and joins the devices of the device (w1 w2 w3 w4).";
        let from = "the device (w1 w2 w3 w4)";
        let waits = json!({
            "among": "alone",
            "sent_to_no_relay": { "versions": 3, "names": 1 },
        });
        assert_eq!(
            alone_says(&waits, from),
            format!(
                "3 versions of 1 name that this device holds have been sent to no relay yet: \
                 they are let go with everything else that it holds.\n{leaves}"
            )
        );
        let none = json!({
            "among": "alone",
            "sent_to_no_relay": { "versions": 0, "names": 0 },
        });
        assert_eq!(alone_says(&none, from), leaves);
        assert_eq!(alone_says(&json!({ "among": "alone" }), from), leaves);
    }

    /// `cordelia phrase` says what the device has sent to no relay where
    /// it goes on to ask its yes (decision 2026-10-04 §16): on a device
    /// that is alone under a phrase, or one of several. A device that
    /// has stopped is refused there, and lets go of nothing: nothing is
    /// said of what it holds. Its count is said by the command that the
    /// refusal names, before that command's yes.
    #[test]
    fn a_new_phrase_says_what_waits_only_where_it_asks_its_yes() {
        let seen = |among: &str| {
            json!({
                "among": among,
                "sent_to_no_relay": { "versions": 2, "names": 1 },
            })
        };
        let waits = "2 versions of 1 name that this device holds have been sent to no relay \
                     yet: they are let go with everything else that it holds.";
        for asks_a_yes in ["alone", "several"] {
            let said = waits_before_a_new_phrase(&seen(asks_a_yes));
            assert_eq!(said.as_deref(), Some(waits), "{asks_a_yes}");
        }
        for refused in ["stopped", "no_phrase", ""] {
            assert_eq!(waits_before_a_new_phrase(&seen(refused)), None, "{refused}");
        }
        // The command that a stopped device is told to run says it.
        assert_eq!(waits_says(&seen("stopped")).as_deref(), Some(waits));
        // Nothing waits: nothing is said.
        let none = json!({ "among": "alone", "sent_to_no_relay": { "versions": 0, "names": 0 } });
        assert_eq!(waits_before_a_new_phrase(&none), None);
    }

    /// `cordelia devices` says of each device whether it has sent what it
    /// held when it applied the change, what this device has still to
    /// send by name, each name that no device lists yet, with those of a
    /// key that no longer counts apart, and the files that the change
    /// could not carry (decision 2026-10-04 §4.2, §7.3, §8).
    #[test]
    fn devices_says_what_was_sent_and_which_names_are_not_yet_listed() {
        let shown = |label: &str| json!({ "key": "k", "label": label, "words": "w w w w" });
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let written = |n: u8| encode_public_key(&key(n)).unwrap();
        // A file's name as another device may have written it: with what
        // would move the cursor and repaint a line, and far too long.
        let hostile = format!("ghost\u{1b}[2K\r\u{202e}.md{}", "x".repeat(400));
        let seen = json!({
            "this_device": "cordelia_pk1another",
            "change": 2,
            "devices": [
                { "key": written(1), "label": "desktop", "words": "w",
                  "applied": 2, "sent": false },
                { "key": written(2), "label": "laptop", "words": "w", "this_device": true,
                  "applied": 2, "sent": true },
                { "key": written(3), "label": "tablet", "words": "w", "applied": 2,
                  "sent": false },
                { "key": written(4), "label": "phone", "words": "w", "applied": 1,
                  "sent": true },
            ],
            "names": { "sent": ["lab"], "to_go": ["team", "~"] },
            "names_not_listed": [
                { "name": "old-notes", "by": [shown("laptop")], "by_gone": [], "days_left": 89 },
                { "name": "its-own", "by": [], "by_gone": [shown("")], "days_left": 1 },
            ],
            "not_carried": [
                { "name": "lab", "file": "ghost.md" },
                { "name": "lab", "file": hostile },
            ],
            "names_not_shown": 3,
            "left_out": [
                { "label": "tablet", "words": "t t t t", "number": 2 },
                { "label": "added 7", "words": "n n n n", "number": 2,
                  "key": "cordelia_pk1notshown" },
            ],
        });
        let lines = devices_lines(&seen, &key(1)).join("\n");
        // A key that is not in the last change is shown by its label,
        // and its key is asked for as that device prints it. One that a
        // recovery could not show is shown with its key (§9).
        assert!(
            lines.contains(
                "(t t t t) \"tablet\": add it again, or it was meant to go. Its key is the one \
                 it prints (`cordelia id`)."
            ),
            "{lines}"
        );
        assert!(
            lines.contains(
                "(n n n n) \"added 7\"  cordelia_pk1notshown: the recovery could not show it, \
                 and asked nothing of it."
            ),
            "{lines}"
        );
        assert!(
            lines.contains(
                "\n3 names that cannot be shown are listed by a device: what they are called \
                 is not a name as this version writes one"
            ),
            "{lines}"
        );
        // This device is the row of the key in its key file, whatever
        // row the node says is this device's, and whatever key the node
        // names as its own (§16).
        assert!(
            lines.starts_with(&format!("This device: {}\n", written(1))),
            "{lines}"
        );
        assert!(lines.contains("(w) \"desktop\": this device"), "{lines}");
        assert!(!lines.contains("\"laptop\": this device"), "{lines}");
        assert!(
            lines.contains("(w) \"laptop\": has applied change 2, and has sent what it held"),
            "{lines}"
        );
        assert!(
            lines.contains(
                "(w) \"tablet\": has applied change 2, and is still sending what it held (if it \
                 is lost now, what it had not sent is lost with it; `cordelia sync carry` brings \
                 in what it had sent before)"
            ),
            "{lines}"
        );
        // A device that has not applied the change is not said to have
        // sent anything, whatever its word of an earlier one says.
        assert!(
            lines.contains("(w) \"phone\": has not applied change 2 yet"),
            "{lines}"
        );
        assert!(
            lines.contains("`cordelia sync carry` brings in what it had sent to the relays"),
            "{lines}"
        );
        assert!(
            lines.contains("Still to send from this device (1 name sent, 2 to go):\n  team\n  ~"),
            "{lines}"
        );
        assert!(
            lines.contains(
                "Names that no device lists yet since the last change (`cordelia sync carry \
                 <name>` brings one in, and `cordelia sync map` does for a folder that comes to \
                 sync it):\n  old-notes: synced before by (w w w w) \"laptop\"; what the relays \
                 hold of it can be brought in for 89 more days"
            ),
            "{lines}"
        );
        assert!(
            lines.contains(
                "Names that only a device which no longer counts had synced (they stay behind: \
                 `cordelia sync carry <name> --from <device>` brings one in, with the recovery \
                 phrase):\n  its-own: synced before by the device (w w w w); it can be brought \
                 in for 1 more day"
            ),
            "{lines}"
        );
        assert!(lines.contains("Not carried at the last change"), "{lines}");
        assert!(lines.contains("  ghost.md in lab"), "{lines}");
        // A file's name is printed as local history prints names, and no
        // more than its first characters (§16).
        let cut = format!(
            "  ghost\\u{{1b}}[2K\\r\\u{{202e}}.md{}... in lab",
            "x".repeat(cordelia_core::protocol::FILE_NAME_SHOWN_CHARS - 14)
        );
        assert!(lines.contains(&cut), "{lines}");
        assert!(!lines.contains('\u{1b}'), "{lines}");
        assert!(!lines.contains('\u{202e}'), "{lines}");
        assert_eq!(file_shown("plain.md"), "plain.md");
        // So is a line of the status that names one.
        let (_, says) = status_lines(&json!({
            "short": "x",
            "says": ["what this device held of 1 file: gh\u{1b}[2Kost.md in lab"],
        }));
        assert_eq!(
            says,
            ["what this device held of 1 file: gh\\u{1b}[2Kost.md in lab"]
        );

        // With nothing to say of names, nothing is said of them.
        let quiet = json!({ "this_device": "k", "change": 2, "devices": [],
            "names": { "sent": ["lab"], "to_go": [] } });
        assert!(names_lines(&quiet).is_empty());
    }

    /// `cordelia devices` shows what your devices keep at a relay past
    /// the line, from the last sync cycle's report (decision 2026-10-19
    /// §2, rule 5): the total and the names in MiB, and beside each
    /// device, of the last change and added since, the MiB it signed.
    /// At the line and below it, none of it is shown.
    #[test]
    fn devices_shows_what_each_device_keeps_past_the_line() {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let written = |n: u8| encode_public_key(&key(n)).unwrap();
        let mib = 1024 * 1024;
        let seen_at = |total: u64| {
            json!({
                "this_device": written(1),
                "change": 1,
                "devices": [
                    { "key": written(1), "label": "laptop", "words": "w", "applied": 1,
                      "sent": true, "maker": true },
                    { "key": written(2), "label": "desktop", "words": "w", "applied": 1,
                      "sent": true },
                ],
                "added": [
                    { "key": written(3), "label": "tablet", "words": "w", "counted": true,
                      "by": { "key": written(1), "label": "laptop", "words": "w" },
                      "at": 0, "applied": 1, "sent": true },
                ],
                "personal_channel": {
                    "total": total,
                    "words": 12_373_197_u64,
                    "by": [
                        { "key": written(1), "words": 6 * mib, "not_words": 107_000 },
                        { "key": written(2), "words": 3_250_586_u64, "not_words": 0 },
                        { "key": written(3), "words": 0, "not_words": 1_280 },
                        { "key": written(9), "words": 1_280, "not_words": 0 },
                    ],
                    "at": "2026-10-19T10:00:00Z",
                },
            })
        };
        let past = devices_lines_at(&seen_at(13_002_342), &key(1), 0, &LOOKED_UP);
        assert!(
            past.contains(
                &"Your devices keep 12.4 MiB of the 16 MiB a relay holds for them (names: 11.8 \
                  MiB)"
                    .to_string()
            ),
            "{past:#?}"
        );
        let line_of = |lines: &[String], label: &str| -> String {
            let of_it = format!("\"{label}\"");
            lines
                .iter()
                .find(|line| line.contains(&of_it))
                .unwrap_or_else(|| panic!("no line for {label}: {lines:?}"))
                .clone()
        };
        assert!(
            line_of(&past, "laptop").ends_with("; keeps 6.1 MiB there"),
            "{past:#?}"
        );
        assert!(
            line_of(&past, "desktop").ends_with("; keeps 3.1 MiB there"),
            "{past:#?}"
        );
        assert!(
            line_of(&past, "tablet").ends_with("; keeps 0.0 MiB there"),
            "{past:#?}"
        );
        // At the line, and with no report: nothing of it.
        let line = PERSONAL_CHANNEL_WARN_BYTES;
        for seen in [
            seen_at(line),
            json!({ "this_device": written(1), "change": 1 }),
        ] {
            let lines = devices_lines_at(&seen, &key(1), 0, &LOOKED_UP).join("\n");
            assert!(!lines.contains("MiB"), "{lines}");
        }
        let just_past = devices_lines_at(&seen_at(line + 256), &key(1), 0, &LOOKED_UP);
        assert!(
            just_past
                .iter()
                .any(|l| l.starts_with("Your devices keep 12.0 MiB of the 16"))
        );
    }

    /// Right after a device is added, nothing is said against it that is
    /// not known (decision 2026-10-04 §8). For the first five minutes
    /// after this device joined, each device that it has not heard from
    /// is said to be "not heard from yet", with no advice; and so is a
    /// device for the first five minutes after it was added. After that,
    /// the sentence with its advice is said. A device that has said it
    /// applied the change is said to have, whenever it is asked.
    #[test]
    fn a_device_not_heard_from_just_after_it_was_added_is_said_to_be_only_that() {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let written = |n: u8| encode_public_key(&key(n)).unwrap();
        let (now, wait) = (1_800_000_000_i64, STATUS_AMBER_WAIT_SECS as i64);
        assert_eq!(wait, 300);
        let advice = "has not applied change 1 yet, as far as this device has heard: adding it \
                      again from a device that has (`cordelia add-device`)";
        let says_of = |seen: &Value, own: u8, label: &str, at: i64| -> String {
            let lines = devices_lines_at(seen, &key(own), at, &LOOKED_UP);
            let of_it = format!("\"{label}\"");
            let line = lines.iter().find(|line| line.contains(&of_it));
            line.unwrap_or_else(|| panic!("no line for {label}: {lines:?}"))
                .clone()
        };

        // On the device that added the other: the desktop was added at
        // `now`, and has not been heard from.
        let adder = json!({
            "this_device": written(1),
            "change": 1,
            "devices": [
                { "key": written(1), "label": "laptop", "words": "w", "applied": 1,
                  "sent": true, "maker": true },
            ],
            "added": [
                { "key": written(2), "label": "desktop", "words": "w", "counted": true,
                  "by": { "key": written(1), "label": "laptop", "words": "w" },
                  "at": now, "applied": null, "sent": false },
            ],
        });
        for soon in [now, now + 1, now + wait - 1] {
            let line = says_of(&adder, 1, "desktop", soon);
            assert!(line.ends_with(": not heard from yet"), "{soon}: {line}");
            assert!(!line.contains("add-device"), "{soon}: {line}");
        }
        for later in [now + wait, now + wait + 1, now + 86_400] {
            let line = says_of(&adder, 1, "desktop", later);
            assert!(line.contains(advice), "{later}: {line}");
            assert!(!line.contains("not heard from yet"), "{later}: {line}");
        }
        // A time ahead of this device's clock holds nothing back.
        assert!(says_of(&adder, 1, "desktop", now - wait).contains(advice));
        assert!(says_of(&adder, 1, "desktop", now - 1).contains(advice));

        // On a third device, which did not add the desktop: the time of the
        // record is the laptop's, written by its clock, and holds nothing
        // back, however near it is to this device's.
        let mut third = adder.clone();
        third["this_device"] = json!(written(3));
        third["devices"][0]["applied"] = json!(null);
        third["devices"].as_array_mut().unwrap().push(
            json!({ "key": written(3), "label": "tablet", "words": "w", "applied": 1,
                          "sent": true, "maker": false }),
        );
        for soon in [now, now + 1, now + wait - 1] {
            let line = says_of(&third, 3, "desktop", soon);
            assert!(line.contains(advice), "{soon}: {line}");
        }

        // On the device that joined: it took what the laptop's key handed
        // it at `now`, and has not heard from the laptop, which is a
        // device of the statement and has no time of its own.
        let joined = |taken: bool| {
            json!({
                "this_device": written(2),
                "change": 1,
                "devices": [
                    { "key": written(1), "label": "laptop", "words": "w", "applied": null,
                      "sent": false, "maker": true },
                ],
                "added": [
                    { "key": written(2), "label": "desktop", "words": "w", "counted": true,
                      "by": { "key": written(1), "label": "laptop", "words": "w" },
                      "at": now - 3000, "applied": 1, "sent": true },
                ],
                "accepting": [
                    { "key": written(1), "words": "w", "typed_at": now - 60, "until": now + 3540,
                      "taken": taken, "taken_at": if taken { json!(now) } else { json!(null) },
                      "asking": !taken, "said": "this device has joined" },
                ],
            })
        };
        let line = says_of(&joined(true), 2, "laptop", now + wait - 1);
        assert!(
            line.ends_with(": not heard from yet; the change was made on it"),
            "{line}"
        );
        assert!(says_of(&joined(true), 2, "laptop", now + wait).contains(advice));
        // A time of taking ahead of this device's clock holds nothing back.
        assert!(says_of(&joined(true), 2, "laptop", now - 1).contains(advice));
        // A key that was typed and not taken is no joining.
        assert!(says_of(&joined(false), 2, "laptop", now + 1).contains(advice));

        // What is known is said at once: a device that has said it
        // applied the change has, however lately it was added.
        let mut heard = adder.clone();
        heard["added"][0]["applied"] = json!(1);
        let line = says_of(&heard, 1, "desktop", now + 1);
        assert!(line.contains("has applied change 1"), "{line}");
    }

    /// What `cordelia devices` says of each relay, one case each
    /// (decision 2026-10-19, rule 12): D2 while a relay not heard since the
    /// device woke is not out of reach, D3 once it is; D4 for one that is
    /// out of reach and lacks the change; D5 for one that is out of reach
    /// and holds it, whether or not it has answered since the device woke;
    /// and the lines of before. Each word for word, with `<when>` with and
    /// without its date, and `<since>` in both forms.
    #[test]
    fn each_relay_line_by_its_case() {
        // Noon, 2026-10-21, in UTC; and a moment of the day before.
        let now = 1_792_584_000;
        let yesterday = now - 86_400;
        let relay = |heard: bool, holds_latest: Value, reach: Value| {
            json!({ "relay": "b.example:9474", "heard_since_woke": heard,
                    "holds_latest": holds_latest, "reach": reach })
        };
        let reach = |holds: &str, out: Option<i64>, last_reached: Option<i64>| {
            json!({ "about": "0101", "lacks_for": null,
                    "class": null, "holds": holds, "reached": false, "out_of_reach_since": out,
                    "reference": now - 900, "reference_by": "change",
                    "last_reached": last_reached, "waits": null,
                    "refusing_waits_since": null, "no_room": null,
                    "answered_at": yesterday, "lacking_secs": null })
        };
        let woke = Some(now - 600);
        // The change entry the device keeps, as the look names it.
        const LATEST: Option<&str> = Some("0101");
        let cases = [
            // D2: not heard since the device woke, not out of reach.
            (
                relay(false, Value::Null, reach("neither", None, None)),
                "has not answered since this device started or woke at 11:50 UTC. A change made \
                 while this device was off may be there, and not have reached it.",
            ),
            // D3: the same, out of reach.
            (
                relay(false, Value::Null, reach("neither", Some(now - 60), None)),
                "has not answered since this device started or woke at 11:50 UTC, and cannot be \
                 reached from here. A change made while this device was off may be there, and \
                 not have reached it.",
            ),
            // D4: out of reach, and lacks the change; `<since>` at its
            // reference, where it was not reached since, and when it was
            // last reached before it. Each says first that it cannot be
            // reached from here (decision 2026-10-24, rule 7).
            (
                relay(false, Value::Null, reach("lacks", Some(now - 60), None)),
                "cannot be reached from here, and is not known to hold the latest change: it has \
                 not answered since this device applied the change at 11:45 UTC. A device of \
                 yours that reaches only it may not have heard of that change. If you know that \
                 b.example:9474 is gone for good, take it out of the configuration of every \
                 device. Do not do so only because this machine cannot reach it: it may still \
                 serve a device that does.",
            ),
            (
                relay(
                    false,
                    Value::Null,
                    reach("lacks", Some(now - 60), Some(now - 1200)),
                ),
                "cannot be reached from here, and is not known to hold the latest change: it has \
                 not answered since this device applied the change at 11:45 UTC (it was last \
                 reached at 11:40 UTC). A device of yours that reaches only it may not have \
                 heard of that change. If you know that b.example:9474 is gone for good, take it \
                 out of the configuration of every device. Do not do so only because this \
                 machine cannot reach it: it may still serve a device that does.",
            ),
            // D5: out of reach, and holds it, by what is kept across a
            // start; `<since>` at when it was last reached.
            (
                relay(
                    false,
                    Value::Null,
                    reach("holds", Some(now - 60), Some(now - 600)),
                ),
                "cannot be reached from here, and holds the latest change (as it said at 12:00 UTC \
                 on 2026-10-20): it has not been reached since 11:50 UTC",
            ),
            (
                relay(
                    true,
                    json!(true),
                    reach("holds", Some(now - 60), Some(now - 300)),
                ),
                "cannot be reached from here, and holds the latest change (as it said at 12:00 UTC \
                 on 2026-10-20): it has not been reached since 11:55 UTC",
            ),
            // The lines of before.
            (
                relay(true, json!(true), reach("holds", None, None)),
                "holds the latest change",
            ),
            (
                relay(true, json!(false), reach("lacks", None, None)),
                "does not hold the latest change yet",
            ),
            (
                relay(true, Value::Null, reach("neither", None, None)),
                "has not said whether it holds the latest change",
            ),
            // Its reach of the kept entry, not its last answer: a relay
            // given no key whose connection closed lacks the change though
            // it answered that it holds it (decision 2026-10-19 §1).
            (
                relay(true, json!(true), reach("lacks", None, None)),
                "does not hold the latest change yet",
            ),
            (
                relay(true, json!(false), reach("holds", None, None)),
                "holds the latest change",
            ),
        ];
        for (relay, said) in cases {
            assert_eq!(relay_says(&relay, woke, LATEST, now), said, "{relay}");
        }
        // What is known of a relay about the entry before says nothing of
        // this one: the lines of before.
        let mut before = relay(true, json!(true), reach("holds", Some(now - 60), None));
        before["reach"]["about"] = json!("0202");
        assert_eq!(
            relay_says(&before, woke, LATEST, now),
            "holds the latest change"
        );
        // With no wake said, no time is said of it.
        let d2 = relay(false, Value::Null, reach("lacks", None, None));
        assert!(
            relay_says(&d2, None, LATEST, now)
                .starts_with("has not answered since this device started or woke. "),
            "{}",
            relay_says(&d2, None, LATEST, now)
        );

        // In the list, what waits at a relay whose line is sentences is
        // said on a line of its own.
        let key = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let seen = json!({
            "this_device": encode_public_key(&key).unwrap(),
            "change": 1, "devices": [], "woke_at": now - 600, "latest": "0101",
            "relays": [
                relay(false, Value::Null, reach("lacks", Some(now - 60), None)),
                relay(false, Value::Null, reach("lacks", None, None)),
            ],
            "waiting": [{ "relay": "192.0.2.1:9474", "name": "b.example:9474", "waits": 2 }],
        });
        let lines = devices_lines_at(&seen, &key, now, &LOOKED_UP);
        let from = lines.iter().position(|line| line == "Relays:").unwrap();
        // The device's wake, as the look says it.
        assert!(
            lines[from + 3].contains("since this device started or woke at 11:50 UTC. "),
            "{lines:?}"
        );
        assert!(
            lines[from + 1].starts_with(
                "  b.example:9474: cannot be reached from here, and is not known to hold the \
                 latest change"
            ),
            "{lines:?}"
        );
        assert_eq!(
            lines[from + 2],
            "      2 of this device's channels still to send there"
        );
    }

    /// `cordelia devices` lists each relay once, by its name, with both
    /// things said on its line: whether it holds the latest change, and
    /// what waits to be sent there (decision 2026-10-04 §8). What waits
    /// at an address that is no relay's name is listed after the relays,
    /// and never by its address (decision 2026-10-24, rule 2).
    #[test]
    fn devices_lists_each_relay_once_with_what_waits_there() {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let relay = |name: &str, holds: Value| json!({ "relay": name, "heard_since_woke": true, "holds_latest": holds });
        let seen = json!({
            "this_device": encode_public_key(&key(1)).unwrap(),
            "change": 1,
            "devices": [],
            "relays": [
                relay("one.example:9474", json!(true)),
                relay("two.example:9474", json!(false)),
                relay("three.example:9474", json!(true)),
                relay("192.0.2.4:9474", json!(true)),
            ],
            "waiting": [
                { "relay": "192.0.2.1:9474", "name": "one.example:9474", "waits": 1 },
                { "relay": "192.0.2.2:9474", "name": "two.example:9474", "waits": 3 },
                { "relay": "192.0.2.3:9474", "name": "three.example:9474", "waits": 0 },
                { "relay": "192.0.2.4:9474", "name": null, "waits": 2 },
                { "relay": "192.0.2.9:9474", "name": null, "waits": 5 },
                { "relay": "192.0.2.8:9474", "name": null, "waits": 0 },
            ],
        });
        let lines = devices_lines(&seen, &key(1));
        let from = lines.iter().position(|line| line == "Relays:").unwrap();
        assert_eq!(
            lines[from..],
            [
                "Relays:",
                "  one.example:9474: holds the latest change; 1 of this device's channels still \
                 to send there",
                "  two.example:9474: does not hold the latest change yet; 3 of this device's \
                 channels still to send there",
                "  three.example:9474: holds the latest change",
                "  192.0.2.4:9474: holds the latest change; 2 of this device's channels still to \
                 send there",
                "  a relay that this device is connected to and that no line above names: 5 of \
                 this device's channels still to send there",
            ]
        );
        // No relay is on two lines, by its name and by its address.
        let said = lines.join("\n");
        for address in [
            "192.0.2.1",
            "192.0.2.2",
            "192.0.2.3",
            "192.0.2.8",
            "192.0.2.9",
        ] {
            assert!(!said.contains(address), "{address}: {said}");
        }
        assert_eq!(said.matches("192.0.2.4").count(), 1, "{said}");
    }

    /// A relay that is set up with no key is given no name in the row of
    /// what waits there, which holds the address it is reached at: it is
    /// still one line in `cordelia devices`, by its name, with what waits
    /// on it, where that address is one that its name is found at here.
    /// A row at an address that no relay's name is found at is still
    /// listed after the relays, as a relay that no line above names.
    #[test]
    fn devices_lists_a_relay_with_no_key_once() {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let seen = json!({
            "this_device": encode_public_key(&key(1)).unwrap(),
            "change": 1,
            "devices": [],
            "relays": [
                { "relay": "localhost:9474", "heard_since_woke": true, "holds_latest": true },
            ],
            "waiting": [
                { "relay": "127.0.0.1:9474", "name": null, "waits": 4 },
                { "relay": "192.0.2.9:9474", "name": null, "waits": 5 },
            ],
        });
        let lines = devices_lines(&seen, &key(1));
        let from = lines.iter().position(|line| line == "Relays:").unwrap();
        assert_eq!(
            lines[from..],
            [
                "Relays:",
                "  localhost:9474: holds the latest change; 4 of this device's channels still to \
                 send there",
                "  a relay that this device is connected to and that no line above names: 5 of \
                 this device's channels still to send there",
            ]
        );
        assert!(!lines.join("\n").contains("127.0.0.1"), "{lines:?}");

        // A row that the node gives another relay's name is that relay's,
        // and is not claimed by an address that this relay's name is
        // found at.
        let mut two = seen.clone();
        two["relays"].as_array_mut().unwrap().push(
            json!({ "relay": "other.example:9474", "heard_since_woke": true,
                          "holds_latest": true }),
        );
        two["waiting"] = json!([
            { "relay": "127.0.0.1:9474", "name": "other.example:9474", "waits": 3 },
            { "relay": "192.0.2.9:9474", "name": null, "waits": 5 },
        ]);
        let lines = devices_lines(&two, &key(1));
        let from = lines.iter().position(|line| line == "Relays:").unwrap();
        assert_eq!(
            lines[from..],
            [
                "Relays:",
                "  localhost:9474: holds the latest change",
                "  other.example:9474: holds the latest change; 3 of this device's channels \
                 still to send there",
                "  a relay that this device is connected to and that no line above names: 5 of \
                 this device's channels still to send there",
            ]
        );
    }

    /// `cordelia devices` looks the relays' names up as its lookup says,
    /// and within its wait: a row at the address that the lookup gives a
    /// relay's name is said on that relay's line, and a lookup that does
    /// not end does not hold the command up past the wait. (Here the
    /// relay's name is an address, which the system's own lookup would
    /// give as it is.)
    #[test]
    fn devices_looks_the_relays_up_only_as_its_lookup_says_and_within_its_wait() {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let seen = json!({
            "this_device": encode_public_key(&key(1)).unwrap(),
            "change": 1,
            "devices": [],
            "relays": [
                { "relay": "203.0.113.7:9474", "heard_since_woke": true, "holds_latest": true },
            ],
            "waiting": [{ "relay": "203.0.113.5:9474", "name": null, "waits": 2 }],
        });
        fn found(name: &str) -> Vec<String> {
            match name {
                "203.0.113.7:9474" => vec!["203.0.113.5:9474".to_string()],
                _ => Vec::new(),
            }
        }
        fn never(name: &str) -> Vec<String> {
            std::thread::sleep(std::time::Duration::from_secs(30));
            found(name)
        }
        let relays_of = |lookup: &Lookup| -> Vec<String> {
            let lines = devices_lines_at(&seen, &key(1), 0, lookup);
            let from = lines.iter().position(|line| line == "Relays:").unwrap();
            lines[from + 1..].to_vec()
        };
        let wait = std::time::Duration::from_secs(5);
        assert_eq!(
            relays_of(&Lookup { wait, by: found }),
            [
                "  203.0.113.7:9474: holds the latest change; 2 of this device's channels still \
              to send there"
            ]
        );
        let began = std::time::Instant::now();
        let short = std::time::Duration::from_millis(200);
        assert_eq!(
            relays_of(&Lookup {
                wait: short,
                by: never
            }),
            [
                "  203.0.113.7:9474: holds the latest change",
                "  a relay that this device is connected to and that no line above names: 2 of \
                 this device's channels still to send there",
            ]
        );
        assert!(
            began.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            began.elapsed()
        );
    }

    /// The lookups of the relays' names that `cordelia devices` makes are
    /// bounded: where they do not end within the wait, none is found, and
    /// the command goes on; where they do, each name's addresses are
    /// given, in the order of the names.
    #[test]
    fn the_lookups_of_the_relays_names_end_within_their_wait() {
        let names = || vec!["one:1".to_string(), "two:2".to_string()];
        let never = |_: &str| -> Vec<String> {
            std::thread::sleep(std::time::Duration::from_secs(3600));
            Vec::new()
        };
        let began = std::time::Instant::now();
        let wait = std::time::Duration::from_millis(200);
        assert_eq!(
            addresses_within(names(), wait, never),
            vec![Vec::<String>::new(); 2]
        );
        assert!(began.elapsed() < std::time::Duration::from_secs(5));
        let at = |name: &str| vec![format!("found {name}")];
        assert_eq!(
            addresses_within(names(), wait, at),
            [
                vec!["found one:1".to_string()],
                vec!["found two:2".to_string()]
            ]
        );
    }

    /// What the node says in the middle of a line begins a line of its
    /// own with a capital: the last line of `cordelia accept`, and each
    /// notice that `cordelia devices --clear` asks about. What begins
    /// with no letter is left as it is.
    #[test]
    fn a_line_of_its_own_begins_with_a_capital() {
        assert_eq!(
            capitalised("this device has joined: it has applied change 1"),
            "This device has joined: it has applied change 1"
        );
        assert_eq!(
            capitalised("new device: (w w w w) \"desktop\""),
            "New device: (w w w w) \"desktop\""
        );
        assert_eq!(
            capitalised("(w w w w) \"desktop\" left"),
            "(w w w w) \"desktop\" left"
        );
        assert_eq!(capitalised("Already so"), "Already so");
        assert_eq!(capitalised(""), "");
    }

    /// The twelve words are shown numbered, four to a row, with the
    /// columns lined up and the numbers right-aligned (decision
    /// 2026-10-04 §5): the number that a word is shown by is the number
    /// that it is asked for by. No row ends in a space. And the text has
    /// room for any twelve words of the list from the start: it is never
    /// moved as it grows.
    #[test]
    fn the_words_are_shown_numbered_four_to_a_row_with_the_columns_lined_up() {
        let legal = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert_eq!(
            numbered(legal, 4).as_str(),
            "   1. legal       2. winner      3. thank       4. year\n   \
             5. wave        6. sausage     7. worth       8. useful\n   \
             9. legal      10. winner     11. thank      12. yellow"
        );
        // Twelve of the longest words, and twelve of the shortest: the
        // numbers are in the same columns whatever the words are.
        let longest = ["abstract"; 12].join(" ");
        let shortest = ["zoo"; 12].join(" ");
        let columns = |rows: &str| -> Vec<Vec<usize>> {
            rows.lines()
                .map(|row| row.match_indices(". ").map(|(at, _)| at).collect())
                .collect()
        };
        let of_the_longest = numbered(&longest, 4);
        assert_eq!(columns(&of_the_longest), [[4, 19, 34, 49]; 3]);
        for words in [legal, &longest, &shortest] {
            let rows = numbered(words, 4);
            assert_eq!(columns(&rows), columns(&of_the_longest), "{words}");
            assert_eq!(rows.lines().count(), 3);
            assert!(rows.lines().all(|row| !row.ends_with(' ')), "{rows:?}");
            // Each word after its number, in the order they were given.
            let read: Vec<&str> = rows.split_whitespace().collect();
            let numbers: Vec<String> = (1..=12).map(|number| format!("{number}.")).collect();
            let shown: Vec<&str> = read.iter().skip(1).step_by(2).copied().collect();
            assert_eq!(
                read.iter().step_by(2).collect::<Vec<_>>(),
                numbers.iter().collect::<Vec<_>>()
            );
            assert_eq!(shown.join(" "), words);
            // Within the room it was given, and so never moved.
            assert!(rows.len() <= PHRASE_WORDS * 16, "{}", rows.len());
            assert_eq!(rows.capacity(), numbered(legal, 4).capacity());
        }
        // Two spaces, three columns of fifteen and one of twelve: and
        // with the two ends of rows, within the room for sixteen a word.
        assert_eq!(of_the_longest.lines().next().unwrap().len(), 59);
        assert_eq!(of_the_longest.len(), 3 * 59 + 2);
    }

    /// **The terminal's size says how the words are shown** (decision
    /// 2026-10-04 §5): four to a row; one to a line where it is narrower
    /// than a row of four; and nothing, with the size they need, where
    /// it has too few lines, or is narrower than one word with its
    /// number. A terminal that says nothing of its size is shown the
    /// rows of four.
    #[test]
    fn the_terminals_size_says_how_the_words_are_shown_or_that_they_are_not() {
        let says = "Your recovery phrase (shown once):";
        let asks = "Write the twelve words down, in order. Keep them where only you can read \
                    them.\nPress Enter when you have. The words are then cleared from the \
                    screen. ";
        assert_eq!((says.len(), asks.lines().count()), (34, 2));
        let lines: Vec<usize> = asks.lines().map(str::len).collect();
        assert_eq!(lines, [78, 71]);
        let shown =
            |columns: usize, lines: usize| words_in_a_row(Some((columns, lines)), says, asks);
        let too_small = |has: (usize, usize), needs: (usize, usize)| {
            Err(format!(
                "this terminal is too small to show the twelve words: it has {} columns and {} \
                 lines.\nThey need {} columns and {} lines. Nothing was made.",
                has.0, has.1, needs.0, needs.1
            ))
        };
        // A row of four is 59 columns, and a word with its number 14.
        assert_eq!((widest_row(4), widest_row(1)), (59, 14));
        assert_eq!(words_in_a_row(None, says, asks), Ok(4));

        // Wide enough for every line: a heading, three rows, two lines
        // below, and a line between each.
        assert_eq!(shown(80, 24), Ok(4));
        assert_eq!(shown(80, 8), Ok(4));
        assert_eq!(shown(78, 8), Ok(4));
        assert_eq!(shown(80, 7), too_small((80, 7), (80, 8)));
        // Narrower than the first line below: it takes two.
        assert_eq!(shown(77, 9), Ok(4));
        assert_eq!(shown(77, 8), too_small((77, 8), (77, 9)));
        // As wide as a row of four, and no wider.
        assert_eq!(shown(59, 10), Ok(4));
        assert_eq!(shown(59, 9), too_small((59, 9), (59, 10)));
        // Narrower than a row of four: one to a line.
        assert_eq!(shown(58, 19), Ok(1));
        assert_eq!(shown(58, 18), too_small((58, 18), (58, 19)));
        assert_eq!(shown(40, 24), Ok(1));
        // As wide as a word with its number: three lines of heading,
        // twelve words, six and six below.
        assert_eq!(shown(14, 29), Ok(1));
        assert_eq!(shown(14, 28), too_small((14, 28), (14, 29)));
        // Narrower than that: however many lines it has.
        assert_eq!(shown(13, 1000), too_small((13, 1000), (14, 29)));
        assert_eq!(shown(1, 1), too_small((1, 1), (14, 29)));

        // One to a line: each word after its number, with no space
        // after it.
        let legal = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let rows = numbered(legal, 1);
        assert_eq!(
            rows.as_str(),
            "   1. legal\n   2. winner\n   3. thank\n   4. year\n   5. wave\n   6. sausage\n   \
             7. worth\n   8. useful\n   9. legal\n  10. winner\n  11. thank\n  12. yellow"
        );
        assert!(numbered(&["abstract"; 12].join(" "), 1).len() <= PHRASE_WORDS * 16);
        assert_eq!(rows.capacity(), numbered(legal, 4).capacity());
        assert_eq!(lines_taken("", 10), 0);
        assert_eq!(lines_taken("\n", 10), 1);
        assert_eq!(lines_taken("0123456789", 10), 1);
        assert_eq!(lines_taken("0123456789a", 10), 2);
    }

    /// Where the words that `cordelia phrase` showed are not all typed
    /// back, nothing is made, and a person is told that those words are
    /// no recovery phrase and are not to be kept (decision 2026-10-04
    /// §5): at the third miss, and where the input ended, after what a
    /// command says of that anywhere.
    #[test]
    fn where_the_words_are_not_typed_back_they_are_said_to_be_no_phrase() {
        assert_eq!(not_typed_back_says(&TypedBack::All), None);
        assert_eq!(
            not_typed_back_says(&TypedBack::Missed).as_deref(),
            Some(
                "Three tries did not match. Nothing was made, and the words you were shown are \
                 not a recovery phrase: do not keep them. Run `cordelia phrase` again."
            )
        );
        for said in [
            "nothing was typed",
            "a recovery phrase is twelve words, and this is 5",
        ] {
            assert_eq!(
                not_typed_back_says(&TypedBack::Ended(said.to_string())),
                Some(format!(
                    "{said}. Nothing was made, and the words you were shown are not a recovery \
                     phrase: do not keep them."
                ))
            );
        }
    }

    /// What `cordelia phrase` says before anything is shown: what a
    /// phrase is for, who has it, and that it is no wallet's (decision
    /// 2026-10-04 §5).
    #[test]
    fn what_a_phrase_is_for_is_said_before_one_is_shown() {
        for says in [
            "Your recovery phrase is twelve words.",
            "You need it to remove a device, or to recover on a new machine.",
            "(You can add a device without it.)",
            "Nobody else has it, and this device does not keep it. It is shown once, now.",
            "It is not a wallet phrase. Never type it into a wallet, and never type a wallet's \
             words here.",
        ] {
            assert!(WHOSE_WORDS.contains(says), "{says}");
        }
        assert_eq!(WHOSE_WORDS.lines().count(), 6);
    }

    /// Where what answered at the node's address is no look of this
    /// command's version, or names another key as this device, the
    /// refusal says how the node is restarted on each system (decision
    /// 2026-10-04 §16): the command that restarts the service, on a line
    /// of its own, and `cordelia status` after it, as the node's own
    /// refusal says it. Neither names a command that restarts no service.
    #[test]
    fn a_refusal_of_what_answered_names_the_command_that_restarts_the_node() {
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let systems = [
            (
                "linux",
                "systemctl --user daemon-reload && systemctl --user restart cordelia",
            ),
            (
                "macos",
                "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia; launchctl bootstrap \
                 gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist || (sleep 30; \
                 launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist)",
            ),
        ];
        for (os, restart) in systems {
            let how = format!(
                "\n  {restart}\nThen run `cordelia status`.\nWhere the node does not run as \
                 the service that the install script set up, stop it and start it again with \
                 whatever started it."
            );
            assert_eq!(
                how,
                format!("\n{}", cordelia_api::commands::restart_says(os))
            );
            assert_eq!(
                no_look_says(os),
                format!(
                    "what answered at the node's address says nothing of where this device \
                     stands: it is no node of this command's version. Nothing was done. \
                     Restart the node:{how}"
                )
            );
            assert_eq!(
                not_this_devices_key_says(&own, os),
                format!(
                    "what answered at the node's address does not name this device's key, \
                     which is the one in its key file ({}). Nothing was done. A node goes on \
                     under the key it was started with. If this device was given a new key, \
                     restart the node:{how}",
                    fingerprint::shown(&own)
                )
            );
            for says in [no_look_says(os), not_this_devices_key_says(&own, os)] {
                assert!(!says.contains("cordelia start"), "{says}");
            }
        }
        // And the refusal itself is those words.
        let refused = names_this_device(&json!({ "this_device": "no key" }), &own).unwrap_err();
        assert_eq!(
            refused.to_string(),
            not_this_devices_key_says(&own, std::env::consts::OS)
        );
    }

    /// `cordelia init --new-key` ends, on each system, with the command
    /// that restarts the node as the service, on a line of its own, and
    /// `cordelia status` after it (decision 2026-10-04 §5.2); and with
    /// what is done where the node does not run as the service. It names
    /// no command that does not restart a service.
    #[test]
    fn a_new_key_ends_with_the_command_that_restarts_the_node() {
        let systems = [
            (
                "linux",
                "systemctl --user daemon-reload && systemctl --user restart cordelia",
            ),
            (
                "macos",
                "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia; launchctl bootstrap \
                 gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist || (sleep 30; \
                 launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist)",
            ),
        ];
        for (os, restart) in systems {
            let says = after_a_new_key_says(os);
            assert_eq!(
                says,
                format!(
                    "It follows no recovery phrase. Its memory folders and their mappings are \
                     as they were.\nThe node still runs under the old key. Before anything \
                     else, restart the node:\n  {restart}\nThen run `cordelia status`.\nWhere \
                     the node does not run as the service that the install script set up, stop \
                     it and start it again with whatever started it.\nThe status then names \
                     the ways on."
                )
            );
            assert!(!says.contains("cordelia start"), "{says}");
        }
    }

    /// On a machine that follows no phrase, `cordelia phrase` says, before
    /// any word is shown, that a person who has a phrase already and has
    /// lost every device wants `cordelia recover` (decision 2026-10-04
    /// §5.2, §9), with the command on a line of its own. A device that
    /// follows a phrase is told nothing of it: its yes says what a new
    /// phrase does there.
    #[test]
    fn a_person_who_has_a_phrase_and_no_device_is_pointed_to_recover() {
        let opening = phrase_opening("no_phrase");
        assert!(opening.starts_with(WHOSE_WORDS), "{opening}");
        assert!(
            opening.ends_with(
                "\n\nIf you have a recovery phrase already and every device is lost, do not \
                 make a new one.\nPress Ctrl-C, and recover with the phrase you have:\n  \
                 cordelia recover\n"
            ),
            "{opening}"
        );
        for among in ["alone", "several", "stopped"] {
            assert_eq!(phrase_opening(among), format!("{WHOSE_WORDS}\n"), "{among}");
        }
    }

    // ── The carried word (decision 2026-10-19 §4, rules 6 and 7) ────

    /// A look after change 3 on device 1, set up with three relays: A and B
    /// with keys it knows, C with none. Device 2's row has `other`, device
    /// 1's own row `own`, each a carried word or null.
    fn look_with_words(own: Value, other: Value, held: [Option<bool>; 3]) -> Value {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let written = |n: u8| encode_public_key(&key(n)).unwrap();
        json!({
            "this_device": written(1),
            "change": 3,
            "relays": [
                { "relay": "a.example:9474", "key": written(10), "holds_latest": true,
                  "heard_since_woke": true, "has_what_was_carried": held[0] },
                { "relay": "b.example:9474", "key": written(11), "holds_latest": true,
                  "heard_since_woke": true, "has_what_was_carried": held[1] },
                { "relay": "c.example:9474", "key": null, "holds_latest": true,
                  "heard_since_woke": true, "has_what_was_carried": held[2] },
            ],
            "devices": [
                { "key": written(1), "label": "laptop", "words": "w1", "applied": 3,
                  "sent": false, "carried_word": own },
                { "key": written(2), "label": "desktop", "words": "w2", "applied": 3,
                  "sent": false, "carried_word": other },
            ],
        })
    }

    fn word_naming(keys: &[String], more: u64, not_yet: u64) -> Value {
        json!({ "keys": keys, "more": more, "not_yet": not_yet })
    }

    fn written_key(n: u8) -> String {
        encode_public_key(&NodeIdentity::from_seed([n; 32]).unwrap().public_key()).unwrap()
    }

    /// The lines of the carried word, word for word (decision 2026-10-19
    /// §5): D1 in `cordelia devices` and S5 in the wait after a change, of
    /// another device whose carried word is read, each with and without
    /// `<not yet>`; and S4, of this device's own word.
    #[test]
    fn each_line_of_the_carried_word_word_for_word() {
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let (a, b, unknown) = (written_key(10), written_key(11), written_key(12));
        let row_of_2 = |seen: &Value| {
            let lines = devices_lines_at(seen, &own, 0, &LOOKED_UP);
            let at = lines
                .iter()
                .position(|line| line.starts_with("  (w2)"))
                .unwrap();
            lines[at].clone()
        };
        let waited = |seen: &Value| after_a_change(seen, 3, &own, 0);

        // Not yet at one relay, which it does not name.
        let seen = look_with_words(
            Value::Null,
            word_naming(&[a.clone(), unknown.clone()], 0, 1),
            [None; 3],
        );
        assert_eq!(
            row_of_2(&seen),
            format!(
                "  (w2) \"desktop\": has applied change 3, and has sent what it held to \
                 a.example:9474 and the relay whose key is {unknown}; not yet to 1 other relay \
                 that it is set up with (if it is lost now, what it held is at a.example:9474 \
                 and the relay whose key is {unknown} alone)"
            )
        );
        assert!(waited(&seen).contains(&format!(
            "(w2) \"desktop\" has applied the change, and has sent what it held to \
             a.example:9474 and the relay whose key is {unknown}; not yet to 1 other relay"
        )));
        // At every relay it is set up with: no `<not yet>`. Two not yet,
        // and more counted.
        let seen = look_with_words(
            Value::Null,
            word_naming(std::slice::from_ref(&b), 0, 0),
            [None; 3],
        );
        assert_eq!(
            row_of_2(&seen),
            "  (w2) \"desktop\": has applied change 3, and has sent what it held to b.example:9474"
        );
        assert!(
            waited(&seen).contains(
                &"(w2) \"desktop\" has applied the change, and has sent what it held to \
              b.example:9474"
                    .to_string()
            )
        );
        let eight: Vec<String> = (0..8)
            .map(|n| {
                if n == 0 {
                    a.clone()
                } else {
                    written_key(20 + n)
                }
            })
            .collect();
        let seen = look_with_words(Value::Null, word_naming(&eight, 2, 2), [None; 3]);
        let row = row_of_2(&seen);
        assert!(
            row.contains(" and 2 more; not yet to 2 other relays that it is set up with"),
            "{row}"
        );
        assert!(
            row.contains("has sent what it held to a.example:9474, the relay whose key is"),
            "{row}"
        );

        // Its own word: S4, in place of the line that it has not yet sent.
        let seen = look_with_words(
            word_naming(std::slice::from_ref(&a), 0, 2),
            Value::Null,
            [Some(true), Some(false), None],
        );
        let lines = waited(&seen);
        assert!(lines.contains(
            &"this device has sent what it carried to a.example:9474; not yet to b.example:9474 \
              and c.example:9474"
                .to_string()
        ), "{lines:?}");
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("has not yet sent every relay"))
        );
        // Every relay holds it: no `<not yet>`.
        let seen = look_with_words(
            word_naming(&[a.clone(), b.clone()], 0, 0),
            Value::Null,
            [Some(true), Some(true), Some(true)],
        );
        assert!(
            waited(&seen).contains(
                &"this device has sent what it carried to a.example:9474, b.example:9474 and \
              c.example:9474"
                    .to_string()
            )
        );
        // Its own carried word of another change than this one (rule 7:
        // "under this change"): the line of today.
        let mut seen = look_with_words(
            word_naming(std::slice::from_ref(&a), 0, 2),
            Value::Null,
            [Some(true), Some(false), None],
        );
        seen["devices"][0]["applied"] = json!(2);
        let lines = waited(&seen);
        assert!(
            lines.contains(
                &"keep this machine on: this device has not yet sent every relay what it carried"
                    .to_string()
            ),
            "{lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.starts_with("this device has sent"))
        );
        // Without its own carried word, the line of today.
        let seen = look_with_words(Value::Null, Value::Null, [Some(true), None, None]);
        assert!(
            waited(&seen).contains(
                &"keep this machine on: this device has not yet sent every relay what it carried"
                    .to_string()
            )
        );
        // Without the word of the other device, the line of today too.
        assert!(
            waited(&seen).contains(
                &"(w2) \"desktop\" has applied the change, and is still sending what it held"
                    .to_string()
            )
        );
        assert!(row_of_2(&seen).contains("is still sending what it held"));
    }

    /// `<held>` and `<not yet>` come from two sets that never overlap
    /// (decision 2026-10-19 §5): a relay that a line names as holding
    /// what was carried is never one it counts or names as not yet.
    #[test]
    fn held_and_not_yet_never_overlap() {
        let own = NodeIdentity::from_seed([1; 32]).unwrap().public_key();
        let names = ["a.example:9474", "b.example:9474", "c.example:9474"];
        for held in [
            [Some(true), Some(false), None],
            [Some(true), Some(true), None],
            [Some(false), Some(true), Some(true)],
            [Some(true), Some(true), Some(true)],
        ] {
            let seen = look_with_words(word_naming(&[written_key(10)], 0, 0), Value::Null, held);
            let line = own_carried_line(&seen).unwrap();
            let (sent_to, not_yet) = match line.split_once("; not yet to ") {
                Some((sent_to, not_yet)) => (sent_to, not_yet),
                None => (line.as_str(), ""),
            };
            for (name, has) in names.iter().zip(held) {
                assert_eq!(sent_to.contains(name), has == Some(true), "{line}");
                assert_eq!(not_yet.contains(name), has != Some(true), "{line}");
            }
        }
        // None holds what was carried, by the look: no line of the word.
        let seen = look_with_words(
            word_naming(&[written_key(10)], 0, 0),
            Value::Null,
            [None; 3],
        );
        assert_eq!(own_carried_line(&seen), None);
        // Another device's word: `<not yet>` is its fourth field, and its
        // keys are named; a relay named is never counted.
        let seen = look_with_words(
            Value::Null,
            word_naming(&[written_key(10), written_key(11)], 0, 0),
            [None; 3],
        );
        let lines = after_a_change(&seen, 3, &own, 0);
        let line = lines.iter().find(|line| line.starts_with("(w2)")).unwrap();
        assert!(!line.contains("not yet"), "{line}");

        // At end 2 (S6, S7): A is OK, B and C hold the change and are out
        // of reach, and B alone took all that was carried before it went.
        // A relay is in `<held>` or gets the rest, never both.
        let reach = |class: &str| {
            json!({ "class": class, "holds": "holds", "reached": class == "ok",
                    "out_of_reach_since": (class != "ok").then_some(0), "reference": 0,
                    "last_reached": null, "waits": null, "refusing_waits_since": null,
                    "no_room": null })
        };
        for (word, held) in [
            (
                wait::OwnWord::Carried,
                [Some(true), Some(true), Some(false)],
            ),
            (
                wait::OwnWord::Carried,
                [Some(true), Some(false), Some(false)],
            ),
            (wait::OwnWord::Carried, [None, None, None]),
            (wait::OwnWord::Sent, [None, None, None]),
        ] {
            let mut seen =
                look_with_words(word_naming(&[written_key(10)], 0, 0), Value::Null, held);
            for (relay, class) in seen["relays"].as_array_mut().unwrap().iter_mut().zip([
                "ok",
                "out_holding",
                "out_holding",
            ]) {
                relay["reach"] = reach(class);
            }
            let relays = wait::relays_of(&seen).unwrap();
            let lines = wait::end_lines(wait::End::Warned, &relays, word, 0).join("\n");
            let all_at = lines
                .split("All that this device carried is at ")
                .nth(1)
                .and_then(|rest| rest.split(". ").next())
                .unwrap_or_default()
                .to_string();
            let rest = lines
                .split("You may close this machine. ")
                .nth(1)
                .and_then(|rest| rest.split(" the rest when").next())
                .and_then(|rest| rest.split(". ").last())
                .filter(|rest| rest.ends_with("get") || rest.ends_with("gets"))
                .unwrap_or_default()
                .to_string();
            for (n, name) in names.iter().enumerate() {
                let whole = word == wait::OwnWord::Sent || n == 0 || held[n] == Some(true);
                assert_eq!(all_at.contains(name), whole, "{name}: {lines}");
                assert_eq!(rest.contains(name), !whole, "{name}: {lines}");
                if n > 0 {
                    let all = format!("  {name} holds the change and all that this device carried");
                    assert_eq!(lines.contains(&all), whole, "{name}: {lines}");
                }
            }
        }
    }
}
