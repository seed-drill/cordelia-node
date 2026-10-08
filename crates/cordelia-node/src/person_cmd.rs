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
use cordelia_api::look::lists_of;
use cordelia_api::person::{PersonError, first_entry};
use cordelia_core::config::{self, Config};
use cordelia_core::protocol::{CHANGE_FETCH_MAX_SECS, LEAVING_SEND_WAIT_SECS, PHRASE_WORDS};
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::fingerprint;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::{Phrase, PhraseError};
use cordelia_crypto::statement::{Device, SignedStatement, Statement, StatementError};

use crate::terminal::Terminal;
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
        anyhow::bail!(
            "what answered at the node's address says nothing of where this device stands: it \
             is no node of this command's version. Nothing was done. Stop the node and start \
             it again (`cordelia start`)."
        );
    }
    Ok(seen)
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
/// It is cut where a name is cut, and its control characters and the
/// marks that change the direction of text are shown as escapes, as
/// local history prints names.
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
    anyhow::bail!(
        "what answered at the node's address does not name this device's key, which is the \
         one in its key file ({}). Nothing was done. A node goes on under the key it was \
         started with: if this device was given a new key, stop the node and start it again \
         (`cordelia start`).",
        fingerprint::shown(own)
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
/// **Each word typed back is held against the word that was shown at its
/// number** (decision 2026-10-04 §16), here and at no other command: a
/// phrase written down wrongly is found out word by word. The third
/// word that is not the word shown stops the command, and nothing is
/// made ([`Terminal::phrase_back`]).
pub fn phrase(config_path: &str, name: Option<String>) -> anyhow::Result<()> {
    let at = Terminal::for_a_phrase()?;
    refuse_before_a_phrase(config_path)?;
    // The first statement is made for the key in this device's key file.
    let this_device = own_key(config_path)?;
    let seen = look_with_what_waits(config_path)?;
    names_this_device(&seen, &this_device)?;
    let among = text(&seen, "among").to_string();
    println!("{WHOSE_WORDS}\n");
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

    let phrase = Phrase::generate()?;
    at.once(
        "Your recovery phrase (shown once):",
        numbered(phrase.words()?.as_str()).as_str(),
        "Write the twelve words down, in order. Keep them where only you can read them.\n\
         Press Enter when you have. The words are then cleared from the screen. ",
    )?;
    let made = {
        // Each word is held against the word shown by its place in the
        // list: the words themselves are not set beside each other.
        let typed_back = at.phrase_back(
            "Now type the words back, one at a time. What you type is not shown.",
            &*phrase.places()?,
        )?;
        if !typed_back {
            anyhow::bail!(
                "Three words did not match. Nothing was made, and the words you were shown are \
                 not a recovery phrase: do not keep them. Run `cordelia phrase` again."
            );
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

/// The twelve `words` as they are shown: each with its number, four to a
/// row, the columns lined up. So the numbers that a person writes down
/// are the numbers that the words are asked for by.
///
/// The text is overwritten when it is dropped, and is never moved as it
/// grows: it has room for sixteen bytes a word, which is a number, a full
/// stop and a space, the eight letters of the longest word, and what
/// parts it from the next.
fn numbered(words: &str) -> Zeroizing<String> {
    use std::fmt::Write;
    let (in_a_row, longest, between) = (4, 8, 3);
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
        ("fork", _) => anyhow::bail!(
            "two changes were made apart, and this device has seen both: the fork is settled \
             first, with the phrase (`cordelia settle`)."
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
            println!("{now_said}.");
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

/// What `cordelia devices` prints, a line each. `own` is this device's
/// key, from its key file: which row is this device's goes by it.
fn devices_lines(seen: &Value, own: &[u8; 32]) -> Vec<String> {
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
            // A device that is lost in that state has left what it had
            // not sent: what it had sent before comes in by command
            // (§7.3, §8).
            false => format!(
                "has applied change {change}, and is still sending what it held (if it is \
                 lost now, what it had not sent is lost with it; `cordelia sync carry` brings \
                 in what it had sent before)"
            ),
        },
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

    out.push(String::new());
    out.push("Devices of the last change:".into());
    for device in list(seen, "devices") {
        let made = match device["maker"] == true {
            true => "; the change was made on it",
            false => "",
        };
        out.push(format!(
            "  {}: {}{made}{}",
            shown(device),
            applied(device),
            left(device)
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
            true => format!("{}{}", applied(device), left(device)),
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
    if let Some(apart) = seen["apart"].as_object() {
        out.push(String::new());
        out.push(format!(
            "The change made apart (change {}, made on {}):",
            apart["number"].as_u64().unwrap_or(0),
            shown(&apart["made_on"])
        ));
        for device in apart["devices"].as_array().into_iter().flatten() {
            out.push(format!("  {}", shown(device)));
        }
        for device in apart["removed"].as_array().into_iter().flatten() {
            out.push(format!("  removed: ({})", text(device, "words")));
        }
    }
    out.push(String::new());
    out.push("Relays:".into());
    let relays: Vec<&Value> = list(seen, "relays").collect();
    if relays.is_empty() {
        out.push("  none is reached".into());
    }
    for relay in relays {
        let holds = match (
            relay["heard_since_woke"] == true,
            relay["holds_latest"].as_bool(),
        ) {
            (false, _) => {
                "has not answered since this device woke: a change made while it was \
                           off may not have reached it"
            }
            (true, Some(true)) => "holds the latest change",
            (true, Some(false)) => "does not hold the latest change yet",
            (true, None) => "has not said whether it holds the latest change",
        };
        out.push(format!("  {}: {holds}", text(relay, "relay")));
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
    for waits in list(seen, "waiting") {
        if let Some(n) = waits["waits"].as_u64().filter(|n| *n > 0) {
            out.push(format!(
                "  {}: {n} of this device's channels still to send there",
                text(waits, "relay")
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
    for notice in notices {
        let clears = at.yes(&format!(
            "\n{}.\nClearing it changes what this device shows, and nothing else.",
            text(notice, "says")
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
    /// `cordelia settle`: the statement that settles two made apart.
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

/// `cordelia settle`: settle two changes that were made apart, on a
/// device that has seen both (decision 2026-10-04 §4.5).
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
    /// The statement made apart, its entry, and what the entry is named
    /// by, worked out from it, where the device is in a fork.
    apart: Option<(SignedStatement, CheckedEntry, String)>,
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
        let apart = match handed["apart_statement"].as_str() {
            None => None,
            Some(statement) => {
                let statement = SignedStatement::from_bytes(&hex::decode(statement)?)?;
                statement.verify()?;
                let entry = entry_of(text(handed, "apart_entry"))?;
                // What it is named by is worked out here, from the entry.
                let named = hex::encode(entry.id());
                Some((statement, entry, named))
            }
        };
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
            apart,
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

    /// The label that this device knows `key` by: the statement's, the
    /// other statement's, or that of the record that added it.
    fn label(&self, key: &[u8; 32]) -> String {
        let listed = |statement: &Statement| {
            statement
                .devices
                .iter()
                .find(|device| device.key == *key)
                .map(|device| device.label.clone())
        };
        listed(&self.applied.statement)
            .or_else(|| listed(&self.apart.as_ref()?.0.statement))
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

/// Ask whether a device stays or is removed. **No answer is suggested:
/// each is typed** (decision 2026-10-04 §6), and pressing Enter answers
/// nothing. `neither` says that the third answer is on offer: the device
/// is in no list.
///
/// Where the input ends at the question, the command is refused: nothing
/// is made of an answer that nobody typed.
fn asks_of(at: &Terminal, says: &str, neither: bool) -> anyhow::Result<Answer> {
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
        if key == own || Some(key) == goes || !handed.left.contains(&key) {
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
        if key == own || Some(key) == goes {
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
/// the one that goes, and but those that a person is asked about.
fn stays_unasked(handed: &Handed, goes: Option<[u8; 32]>, asked: &[Question]) -> Vec<Device> {
    let is_asked = |key: &[u8; 32]| asked.iter().any(|question| question.device.key == *key);
    handed
        .applied
        .statement
        .devices
        .iter()
        .filter(|device| Some(device.key) != goes && !is_asked(&device.key))
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
                "apart": handed.apart.as_ref().map(|(_, _, id)| id.clone()),
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
                return stays_in_a_new_process(config_path, number);
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
fn asked(at: &Terminal, handed: &Handed, which: &Which) -> anyhow::Result<Prepared> {
    let own = handed.this_device;
    let applied = &handed.applied.statement;
    let mut stay: Vec<Device> = Vec::new();
    let mut removed: Vec<[u8; 32]> = Vec::new();

    if let Which::Settle = which {
        let Some((apart, _, _)) = &handed.apart else {
            anyhow::bail!("this device has seen no two changes made apart: nothing to settle.");
        };
        let apart = &apart.statement;
        println!("\nTwo changes were made apart. Each is shown from its signed bytes.");
        for (says, statement) in [("this device had applied", applied), ("made apart", apart)] {
            println!("\nChange {} ({says}):", statement.number);
            for line in lists_shown(statement, handed)? {
                println!("{line}");
            }
        }
        println!(
            "\nThe settlement is a change numbered above both. It undoes no removal: every \
             key that either removed stays removed. Of each other device of either, say \
             whether it stays, is removed, or is neither: one that is neither is in no list, \
             and is added again by hand. A device added under the other change since it was \
             made is not known here, and is in no list."
        );
        let gone = |key: &[u8; 32]| applied.removes(key) || apart.removes(key);
        let mut each: Vec<&Device> = Vec::new();
        for device in applied.devices.iter().chain(&apart.devices) {
            if !gone(&device.key) && !each.iter().any(|seen| seen.key == device.key) {
                each.push(device);
            }
        }
        for device in each {
            if device.key == own {
                stay.push(device.clone());
                continue;
            }
            let in_both = applied.lists(&device.key) && apart.lists(&device.key);
            let says = format!(
                "\n{}, a device of {}{}:",
                named(&device.label, &device.key),
                match (in_both, applied.lists(&device.key)) {
                    (true, _) => "both changes",
                    (false, true) => "the change this device had applied",
                    (false, false) => "the change made apart",
                },
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
        if !stay.iter().any(|device| device.key == own) {
            stay.insert(0, own_listing(at, handed)?);
        }
        let (apart, _, _) = handed.apart.as_ref().expect("checked above");
        return Ok(prepare_settlement(
            &handed.applied,
            apart,
            &own,
            stay,
            &removed,
        )?);
    }

    // A removal, or a renewal.
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
        if applied.removes(&goes) {
            anyhow::bail!("that key was removed already, by an earlier change.");
        }
        let known =
            applied.lists(&goes) || handed.added.iter().any(|r| r.addition.device.key == goes);
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
    let asked = questions(handed, goes);
    stay.extend(stays_unasked(handed, goes, &asked));
    if !applied.lists(&own) {
        // This device was added since: the device that makes a statement
        // is always among its devices, whoever added it.
        stay.push(own_listing(at, handed)?);
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
    Ok(prepare_change(&handed.applied, &own, stay, &removed)?)
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
fn refuses_a_key_it_does_not_know(at: &Terminal, goes: &[u8; 32]) -> anyhow::Result<()> {
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

/// This device as a change will list it, where the statement applied
/// does not: it was added since (decision 2026-10-04 §6, §16). It is
/// shown as an addition is, from the record of its own addition, with who
/// added it and when, and a person confirms its listing by a typed
/// answer. The label it is listed under is the one in that record.
///
/// Refused where no record of its addition was handed: a device that is
/// in no list and was added by nobody makes no change.
fn own_listing(at: &Terminal, handed: &Handed) -> anyhow::Result<Device> {
    let (says, device) = own_addition(handed)?;
    let typed = at.answer(&format!(
        "{says}\n  Type `stays` to list this device, or anything else to stop: "
    ))?;
    if typed.as_deref() != Some("stays") {
        anyhow::bail!("That was not `stays`. Nothing was done.");
    }
    Ok(device)
}

/// What [`own_listing`] shows of this device, and the device as the
/// record of its addition has it.
fn own_addition(handed: &Handed) -> anyhow::Result<(String, Device)> {
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
    let says = format!(
        "\nThis device is not in the last change: it was added since, as {}, from {} at {}.\n\
         The device that makes a change is always among its devices: this change lists it \
         under that label.",
        named(&added.device.label, &own),
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
    let apart = handed.apart.as_ref().map(|(_, entry, _)| entry);
    match prepared.sign(&phrase, &handed.held, apart) {
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

/// Go on to the wait that follows a change ([`stays`]) in a new image of
/// this program, which takes the place of this one (decision 2026-10-04
/// §16): the memory that held the phrase, and signed with it, is gone
/// when the wait begins, and the process that waits never held it.
///
/// What this process has said is written out first. Where the program
/// cannot be run again (it was replaced where it lay, say), nothing waits
/// in this process: the command says where to look, and ends.
fn stays_in_a_new_process(config_path: &str, number: u64) -> anyhow::Result<()> {
    use std::io::Write;
    std::io::stdout().flush()?;
    #[cfg(unix)]
    let failed = {
        use std::os::unix::process::CommandExt;
        match std::env::current_exe() {
            Ok(program) => std::process::Command::new(program)
                .arg("--config")
                .arg(config_path)
                .arg(STAYS_COMMAND)
                .arg(number.to_string())
                .exec(),
            Err(e) => e,
        }
    };
    #[cfg(not(unix))]
    let failed = "it runs on a Unix system";
    println!(
        "This command could not go on to say what is still missing ({failed}). The node goes on \
         by itself: `cordelia devices` shows whether each relay holds the change, and what this \
         device has still to send. Keep this machine on until every relay holds the change and \
         nothing is left to send."
    );
    Ok(())
}

/// `cordelia change-made <number>`: what `remove-device`, `renew` and
/// `settle` go on to once the change numbered so is made ([`stays`]). It
/// asks nothing, and holds no phrase.
pub fn change_made(config_path: &str, number: u64) -> anyhow::Result<()> {
    stays(config_path, number)
}

/// What a look says after the change numbered `number`, in lines, and
/// how many things are still missing before this machine may be closed
/// (decision 2026-10-04 §7.1, step 4; §8).
///
/// Nothing is missing only where all of these hold:
///
/// - **every relay that the device is set up with holds the change,** and
///   has been heard from since the device woke;
/// - **the node is connected to every one of them:** what waits to be
///   sent to a relay is known only while it is, so a relay that is not
///   reached is missing, whatever it last said it holds. That is each
///   relay that the node names as not reached, and any relay for which
///   there is no row of what waits;
/// - **nothing waits to be sent** to any of them, of any channel of this
///   device's own, and no name is still to go;
/// - **this device's own word says that it has sent what it carried.**
///   It writes that once nothing that it carried waits at any relay it
///   is set up with, with every one of them connected: so a relay that
///   took the change and was lost before the names went does not let
///   the wait end.
fn after_a_change(seen: &Value, number: u64, own: &[u8; 32]) -> (Vec<String>, usize) {
    let mut now: Vec<String> = Vec::new();
    let mut missing = 0;
    let relays: Vec<&Value> = list(seen, "relays").collect();
    let set_up = relays.len();
    if relays.is_empty() {
        missing += 1;
        now.push("keep this machine on: no relay is reached yet".into());
    }
    for relay in relays {
        let name = text(relay, "relay");
        match relay["holds_latest"].as_bool() {
            Some(true) if relay["heard_since_woke"] == true => {
                now.push(format!("{name} holds the change"));
            }
            _ => {
                missing += 1;
                now.push(format!(
                    "keep this machine on: {name} does not hold the change yet"
                ));
            }
        }
    }
    let not_reached: Vec<&str> = list(seen, "not_reached")
        .filter_map(Value::as_str)
        .collect();
    for relay in &not_reached {
        missing += 1;
        now.push(format!(
            "keep this machine on: {relay} is not connected, and what is still to send \
             there is not known until it is"
        ));
    }
    // A row of what waits for each relay that the device is set up with,
    // or one of them is not reached, whether or not it was named so.
    let rows = list(seen, "waiting").count();
    if not_reached.is_empty() && rows < set_up {
        missing += 1;
        now.push(
            "keep this machine on: a relay that this device is set up with is not connected, \
             and what is still to send there is not known until it is"
                .into(),
        );
    }
    let all_reached = not_reached.is_empty() && rows >= set_up;
    for waits in list(seen, "waiting") {
        if let Some(n) = waits["waits"].as_u64().filter(|n| *n > 0) {
            missing += 1;
            now.push(format!(
                "keep this machine on: {n} of this device's channels still to send to {}",
                text(waits, "relay")
            ));
        }
    }
    // What this device has still to send: what it carried, as names
    // sent and names to go. A name is said to be sent only while every
    // relay is reached: it is counted over those that are.
    let to_go = list(&seen["names"], "to_go").count();
    let sent = list(&seen["names"], "sent").count();
    if to_go > 0 {
        missing += 1;
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
    if !said_sent {
        missing += 1;
        now.push(
            "keep this machine on: this device has not yet sent every relay what it carried".into(),
        );
    }
    for device in list(seen, "devices").filter(|device| !is_own(device, own)) {
        let applied = device["applied"].as_u64() == Some(number);
        now.push(match (applied, device["sent"] == true) {
            (true, true) => format!(
                "{} has applied the change, and has sent what it held",
                shown(device)
            ),
            (true, false) => format!(
                "{} has applied the change, and is still sending what it held",
                shown(device)
            ),
            (false, _) => format!("{} has not applied the change yet", shown(device)),
        });
    }
    (now, missing)
}

/// After a change: stay, and show as they come whether each relay holds
/// the change, what this device has still to send, and which of the
/// remaining devices have applied it (decision 2026-10-04 §7.1, step 4).
/// It ends when this machine may be closed ([`after_a_change`]).
fn stays(config_path: &str, number: u64) -> anyhow::Result<()> {
    println!(
        "This machine may be closed only when every relay holds the change and this device \
         has sent what it holds. This command stays until then, and says what is missing. \
         Stopping it stops nothing: the node goes on."
    );
    // Which row is this device's goes by its key file, as the prompts
    // go, and not by the node's word (decision 2026-10-04 §16).
    let own = own_key(config_path)?;
    let mut said: Vec<String> = Vec::new();
    loop {
        std::thread::sleep(ASK_EVERY);
        let seen = look(config_path)?;
        if seen["change"].as_u64() != Some(number) {
            println!("This device has since applied another change: `cordelia devices` says.");
            return Ok(());
        }
        let (now, missing) = after_a_change(&seen, number, &own);
        for line in &now {
            if !said.contains(line) {
                println!("  {line}");
            }
        }
        said = now;
        if missing == 0 {
            println!(
                "Every relay holds the change, and this device has sent what it holds: this \
                 machine may be closed. `cordelia devices` shows which devices have applied \
                 the change."
            );
            return Ok(());
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
            let waiting: Vec<String> = list(&sent, "waiting")
                .filter(|relay| relay["waits"].as_u64().unwrap_or(0) > 0)
                .map(|relay| text(relay, "relay").to_string())
                .collect();
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
    println!(
        "It follows no recovery phrase. Its memory folders and their mappings are as they \
         were.\nThe node still runs under the old key: stop it and start it again (`cordelia \
         start`) before anything else. Then make a phrase here (`cordelia phrase`), or add \
         this device from one that has one."
    );
    Ok(())
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
                .sign(&phrase, &first.entry, None)
                .unwrap();
            Self {
                listed,
                removed,
                statement: read(&entry),
                entry,
                own,
            }
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
        assert!(handed.apart.is_none());
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
        // The statement made apart, where there is one, likewise.
        let mut with_apart = f.handed(&f.statement, &[]);
        with_apart["apart_statement"] = with_apart["statement"].clone();
        with_apart["apart_entry"] = with_apart["entry"].clone();
        with_apart["apart"] = hex::encode([7u8; 32]).into();
        let handed = f.read(&with_apart).unwrap();
        let (statement, _, named) = handed.apart.unwrap();
        assert_eq!(statement, f.statement);
        assert_eq!(named, hex::encode(f.entry.id()));
        let mut forged = f.statement.clone();
        forged.signature[0] ^= 1;
        with_apart["apart_statement"] = hex::encode(forged.to_bytes().unwrap()).into();
        assert!(f.read(&with_apart).is_err());
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
        let (says, device) = own_addition(&read).unwrap();
        assert_eq!(device, Device::new(five, "desktop").unwrap());
        let shown = format!(
            "it was added since, as {}, from {} at {}.",
            named("desktop", &five),
            named("laptop", &f.own.public_key()),
            time_of(7)
        );
        assert!(says.contains(&shown), "{says}");

        let mut handed = f.handed(&f.statement, &[]);
        handed["this_device"] = encode_public_key(&five).unwrap().into();
        let read = Handed::of(&handed, &five).unwrap();
        let refused = own_addition(&read).err().unwrap().to_string();
        assert!(refused.contains("it makes no change"), "{refused}");
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
            Some(crate::Commands::ChangeMade { number: 3 })
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

    /// After a change, this machine may be closed only where every relay
    /// that the device is set up with holds the change and is connected,
    /// nothing waits to be sent, no name is still to go, and the device's
    /// own word says that it has sent what it carried (decision
    /// 2026-10-04 §7.1, step 4; §8). A relay that took the change and was
    /// lost before the names went leaves three things missing, and each
    /// alone is one. Which row is this device's goes by its key, from its
    /// key file, and not by the node's word of it (§16).
    #[test]
    fn the_wait_after_a_change_ends_only_once_the_devices_own_word_says_all_is_sent() {
        let key = |n: u8| NodeIdentity::from_seed([n; 32]).unwrap().public_key();
        let written = |n: u8| encode_public_key(&key(n)).unwrap();
        let look = |not_reached: Value, waiting: Value, to_go: Value, own: Value| {
            json!({
                "change": 3,
                "relays": [{ "relay": "relay.example:9474", "holds_latest": true,
                             "heard_since_woke": true }],
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
        let missing = |seen: &Value| after_a_change(seen, 3, &key(1));

        let (lines, none) = missing(&look(json!([]), reached.clone(), json!([]), sent.clone()));
        assert_eq!(none, 0, "{lines:?}");
        assert!(lines.contains(&"1 name sent".to_string()), "{lines:?}");
        assert!(
            lines.contains(&"relay.example:9474 holds the change".to_string()),
            "{lines:?}"
        );

        // The relay took the change, and the connection was lost before
        // the names went: no row says what waits there, and no name is
        // known to be still to go.
        let lost = look(
            json!(["relay.example:9474"]),
            json!([]),
            json!([]),
            json!({ "applied": 3, "sent": false }),
        );
        let (lines, count) = missing(&lost);
        assert_eq!(count, 2, "{lines:?}");
        let said = lines.join("\n");
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
        let (lines, count) = missing(&no_row);
        assert_eq!(count, 1, "{lines:?}");
        let said = lines.join("\n");
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
        assert_eq!(missing(&not_reached).1, 1);
        for own in [
            json!({ "applied": 3, "sent": false }),
            // Its word of the change before says nothing of this one.
            json!({ "applied": 2, "sent": true }),
            json!({}),
        ] {
            let seen = look(json!([]), reached.clone(), json!([]), own.clone());
            assert_eq!(missing(&seen).1, 1, "{own}");
        }
        let to_go = look(json!([]), reached.clone(), json!(["team"]), sent.clone());
        let (lines, count) = missing(&to_go);
        assert_eq!(count, 1, "{lines:?}");
        assert!(
            lines.contains(&"keep this machine on: 1 name still to send (1 sent)".to_string()),
            "{lines:?}"
        );
        let waits = json!([{ "relay": "127.0.0.1:9474", "waits": 2 }]);
        assert_eq!(
            missing(&look(json!([]), waits, json!([]), sent.clone())).1,
            1
        );
        // A relay that does not hold the change is missing, as before.
        let mut behind = look(json!([]), reached, json!([]), sent);
        behind["relays"][0]["holds_latest"] = json!(false);
        assert_eq!(missing(&behind).1, 1);
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
            numbered(legal).as_str(),
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
        let of_the_longest = numbered(&longest);
        assert_eq!(columns(&of_the_longest), [[4, 19, 34, 49]; 3]);
        for words in [legal, &longest, &shortest] {
            let rows = numbered(words);
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
            assert_eq!(rows.capacity(), numbered(legal).capacity());
        }
        // Two spaces, three columns of fifteen and one of twelve: and
        // with the two ends of rows, within the room for sixteen a word.
        assert_eq!(of_the_longest.lines().next().unwrap().len(), 59);
        assert_eq!(of_the_longest.len(), 3 * 59 + 2);
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
}
