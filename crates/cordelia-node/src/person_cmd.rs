//! The commands a person types for the devices under a recovery phrase
//! (decision 2026-10-04 §5 to §8): `cordelia phrase`, `add-device`,
//! `accept`, `devices`, `remove-device`, `renew`, `settle` and `init
//! --new-key`.
//!
//! **Every yes is asked here, at a terminal** ([`crate::terminal`]), and
//! each command that asks refuses, before anything else, where its input
//! is not one. What a command then asks of the node is a call that any
//! program with the node's token can make: the yes stops a command that
//! is run by mistake, and nothing else.
//!
//! **The recovery phrase stays in this process** (§5). It is made here
//! (`cordelia phrase`), or typed here with echo off (`remove-device`,
//! `renew`, `settle`), and is in memory that is overwritten when it is
//! dropped. It is never an argument, is never sent to the node, and is
//! in no error and no file. A command that needs it:
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

use cordelia_api::change::{Prepared, prepare_change, prepare_settlement};
use cordelia_api::look::lists_of;
use cordelia_api::person::{PersonError, first_entry};
use cordelia_core::config::{self, Config};
use cordelia_core::protocol::{CHANGE_FETCH_MAX_SECS, LEAVING_SEND_WAIT_SECS};
use cordelia_crypto::addition::SignedAddition;
use cordelia_crypto::bech32::{decode_public_key, encode_public_key};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::fingerprint;
use cordelia_crypto::identity::NodeIdentity;
use cordelia_crypto::phrase::{Phrase, PhraseError};
use cordelia_crypto::statement::{Device, SignedStatement, Statement, StatementError};

use crate::terminal;
use crate::{Told, api_post, api_post_told};

/// Whose words a recovery phrase is, and what it is for: said wherever
/// one is made (decision 2026-10-04 §5).
const WHOSE_WORDS: &str = "\
A recovery phrase is twelve words. They are Cordelia's recovery phrase for your devices.
The words are from the list that a wallet's seed phrase uses, and are no wallet's: never
type these into a wallet, and never type a wallet's words here.

Without the phrase a device can be added, and none can ever be removed or recovered.
Nobody else holds it, and this device does not keep it: it is shown once, now.";

/// What is said where a person did not say yes.
const NOT_A_YES: &str = "That was not a yes. Nothing was done.";

/// How often the node is asked while a command waits for something to
/// come about.
const ASK_EVERY: Duration = Duration::from_secs(1);

/// How long `cordelia accept` stays and says what became of the key.
/// The node goes on asking for the rest of the hour, and `cordelia
/// status` says what became of it.
const ACCEPT_STAYS: Duration = Duration::from_secs(60);

/// How often a mistyped phrase may be typed again at one prompt.
const PHRASE_TRIES: usize = 3;

// ── What the node says ──────────────────────────────────────────────

/// Everything the node says of this device and its person
/// (`cordelia_api::look::Look`, with what waits to be sent).
fn look(config_path: &str) -> anyhow::Result<Value> {
    api_post(config_path, "/api/v1/devices/list", json!({}))
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap_or_default()
}

fn list<'a>(value: &'a Value, field: &str) -> impl Iterator<Item = &'a Value> {
    value[field].as_array().into_iter().flatten()
}

/// A device as it is shown for a decision: its label, and the first four
/// words of its key's fingerprint (decision 2026-10-04 §6).
fn named(label: &str, key: &[u8; 32]) -> String {
    let words = fingerprint::shown(key);
    match label.is_empty() {
        true => format!("the device ({words})"),
        false => format!("{label} ({words})"),
    }
}

/// A device that the node shows, as [`named`] says it.
fn shown(device: &Value) -> String {
    let (label, words) = (text(device, "label"), text(device, "words"));
    match label.is_empty() {
        true => format!("the device ({words})"),
        false => format!("{label} ({words})"),
    }
}

/// A time in seconds, as a person reads it.
fn time_of(at: u64) -> String {
    i64::try_from(at)
        .ok()
        .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| format!("{at}"))
}

/// The name that this machine goes by, for the label of a device that a
/// person gave none.
fn default_label() -> String {
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
fn entry_of(hex_bytes: &str) -> anyhow::Result<CheckedEntry> {
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
    let says = list(seen, "says")
        .filter_map(|line| line.as_str())
        .map(str::to_string)
        .collect();
    (short, says)
}

// ── cordelia phrase ─────────────────────────────────────────────────

/// `cordelia phrase`: make the recovery phrase of this person's devices
/// here (decision 2026-10-04 §5, §5.2).
///
/// The phrase is made in this process, shown once, and typed back whole
/// before anything is made. The node is handed the first statement's
/// change entry and the statement key, and never the words.
pub fn phrase(config_path: &str, name: Option<String>) -> anyhow::Result<()> {
    terminal::require()?;
    let seen = look(config_path)?;
    let among = text(&seen, "among").to_string();
    println!("{WHOSE_WORDS}\n");
    let agreed = match among.as_str() {
        "no_phrase" => true,
        "alone" => terminal::yes(
            "This replaces the recovery phrase that this device follows: the old one stops \
             working here, and what the relays hold under it is left behind.",
        )?,
        "several" => {
            let others = seen["others"].as_u64().unwrap_or(0);
            terminal::yes(&format!(
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
    let this_device = decode_public_key(text(&seen, "this_device"))?;
    let label = name.unwrap_or_else(default_label);
    // A label that a statement would refuse is refused before any word
    // is shown.
    Device::new(this_device, &label)?;

    let phrase = Phrase::generate()?;
    terminal::once(
        "The recovery phrase, shown once:",
        phrase.words()?.as_str(),
        "Write the twelve words down, in their order, and keep them where only you can \
         read them.\nPress Enter when they are written down: they are then taken off the \
         screen. ",
    )?;
    let made = {
        let typed = terminal::phrase(
            "Type the twelve words back, from what you wrote (what you type is not shown): ",
        )?;
        // The same words give the same key: the words themselves are
        // not set beside each other.
        let same = Phrase::parse(&typed)
            .ok()
            .and_then(|typed| Some(typed.public_key().ok()? == phrase.public_key().ok()?));
        if same != Some(true) {
            anyhow::bail!(
                "the words typed are not the words that were shown. Nothing was made, and the \
                 words that were shown are no phrase of anything: do not keep them. Run \
                 `cordelia phrase` again."
            );
        }
        first_entry(&phrase, &this_device, &label)?
    };
    // The phrase has signed and sealed: it is dropped here, and
    // overwritten, before the node is asked anything.
    drop(phrase);

    let asked = api_post(
        config_path,
        "/api/v1/phrase/make",
        json!({
            "entry": hex::encode(made.entry.to_wire()),
            "statement_key": hex::encode(made.statement_key),
            "from": among,
        }),
    );
    if let Err(e) = asked {
        anyhow::bail!(
            "{e}\nNothing was made, and the words that were shown are no phrase of anything: \
             do not keep them."
        );
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

// ── cordelia add-device ─────────────────────────────────────────────

/// `cordelia add-device <key>`: hand a device what it needs to be one of
/// the person's (decision 2026-10-04 §6). The phrase is not typed to
/// add: a device that is in vouches for the new one.
pub fn add_device(config_path: &str, key: &str, name: Option<String>) -> anyhow::Result<()> {
    terminal::require()?;
    let device = decode_public_key(key).map_err(|e| {
        anyhow::anyhow!("that is no device's key, as `cordelia id` prints one: {e}")
    })?;
    let body = json!({ "device": key, "label": name });
    let would = api_post(config_path, "/api/v1/devices/add/look", body.clone())?;
    let agreed = match text(&would, "would") {
        "hand_again" => terminal::yes(&format!(
            "{} is one of your devices already: this hands it the last change again, and \
             adds nothing.",
            named(text(&would, "label"), &device)
        ))?,
        _ => {
            let label = name.as_deref().unwrap_or("the new device");
            if let Some(was) = would["left_out_as"].as_str() {
                println!(
                    "This key was not in the last change. This device knew it as {was}, and it \
                     holds what your devices held before that change."
                );
            }
            if would["counts_already"] == true {
                println!("This key counts as one of your devices already, by an earlier addition.");
            }
            terminal::yes(&format!(
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
    let added = api_post(config_path, "/api/v1/devices/add", body)?;
    let this_device = text(&added, "this_device");
    let own = decode_public_key(this_device)?;
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
    terminal::require()?;
    let typed = decode_public_key(key).map_err(|e| {
        anyhow::anyhow!("that is no device's key, as `cordelia id` prints one: {e}")
    })?;
    let seen = look(config_path)?;
    let from = named("", &typed);
    let says = match (text(&seen, "state"), text(&seen, "among")) {
        ("no_phrase", _) => {
            let folders = seen["folders"].as_u64().unwrap_or(0);
            format!(
                "This device, and the {folders} folder{} it maps, will join the devices of \
                 {from}: what is in those folders will be sent to them.",
                if folders == 1 { "" } else { "s" }
            )
        }
        ("removed", _) => anyhow::bail!(
            "this device was removed: `cordelia init --new-key` first. It is then added as a \
             new device."
        ),
        ("fork", _) => anyhow::bail!(
            "two changes were made apart, and this device has seen both: the fork is settled \
             first, with the phrase (`cordelia settle`)."
        ),
        ("not_listed" | "not_opened", _) => format!(
            "This device takes, within the hour, only what {from} hands over under the \
             recovery phrase that it already follows, with the change that stopped it or one \
             made after that. It keeps its folders, and carries what it holds."
        ),
        (_, "alone") => {
            if seen["sync_on"] == true {
                anyhow::bail!(
                    "sync is on here, and this device is alone under a recovery phrase: \
                     `cordelia sync off` first, so that sending its folders to another set of \
                     devices takes two acts."
                );
            }
            format!(
                "The recovery phrase that this device follows stops working here: this device \
                 leaves it, and joins the devices of {from}."
            )
        }
        _ => format!(
            "This device is one of several. It takes, within the hour, only what {from} hands \
             over under the recovery phrase that it already follows, where that brings a \
             change it can apply. Anything else moves nothing."
        ),
    };
    if !terminal::yes(&says)? {
        println!("{NOT_A_YES}");
        return Ok(());
    }
    let kept = api_post(config_path, "/api/v1/devices/accept", json!({ "key": key }))?;
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
    if clear {
        terminal::require()?;
    }
    let seen = look(config_path)?;
    if clear {
        return clear_notices(config_path, &seen);
    }
    for line in devices_lines(&seen) {
        println!("{line}");
    }
    Ok(())
}

/// What `cordelia devices` prints, a line each.
fn devices_lines(seen: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let change = seen["change"].as_u64();
    out.push(format!("This device: {}", text(seen, "this_device")));
    let Some(change) = change else {
        out.extend(list(seen, "says").filter_map(|line| Some(line.as_str()?.to_string())));
        return out;
    };
    out.push(format!("The last change it has applied: change {change}."));
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
        _ if device["this_device"] == true => "this device".to_string(),
        Some(number) if number == change => format!("has applied change {change}"),
        _ => format!(
            "has not applied change {change} yet, as far as this device has heard: adding it \
             again from a device that has (`cordelia add-device`) hands it the change"
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
    for device in removed {
        out.push(format!(
            "  ({})  {}",
            text(device, "words"),
            text(device, "key")
        ));
    }
    let left_out: Vec<&Value> = list(seen, "left_out").collect();
    if !left_out.is_empty() {
        out.push(String::new());
        out.push("Not in the last change (each holds what your devices held before it):".into());
    }
    for device in left_out {
        out.push(format!(
            "  {} ({}): add it again, or it was meant to go. Its key is the one it prints \
             (`cordelia id`).",
            text(device, "label"),
            text(device, "words")
        ));
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

/// Ask of each notice whether it is cleared on this device, and clear
/// those that a person says yes to.
fn clear_notices(config_path: &str, seen: &Value) -> anyhow::Result<()> {
    let notices: Vec<&Value> = list(seen, "notices").collect();
    if notices.is_empty() {
        println!("There is nothing to clear on this device.");
        return Ok(());
    }
    for notice in notices {
        let clears = terminal::yes(&format!(
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

/// `cordelia remove-device <key>` (decision 2026-10-04 §7.1).
pub fn remove_device(config_path: &str, key: &str) -> anyhow::Result<()> {
    terminal::require()?;
    let device = decode_public_key(key).map_err(|e| {
        anyhow::anyhow!("that is no device's key, as `cordelia devices` lists one: {e}")
    })?;
    change(config_path, &Which::Remove(device))
}

/// `cordelia renew`: a new secret for the devices that stay, with no
/// device removed but those added since that a person says go (decision
/// 2026-10-04 §6, §7.1).
pub fn renew(config_path: &str) -> anyhow::Result<()> {
    terminal::require()?;
    change(config_path, &Which::Renew)
}

/// `cordelia settle`: settle two changes that were made apart, on a
/// device that has seen both (decision 2026-10-04 §4.5).
pub fn settle(config_path: &str) -> anyhow::Result<()> {
    terminal::require()?;
    change(config_path, &Which::Settle)
}

/// What the node hands a command that makes a change: read from the
/// signed bytes of each thing, and checked here.
struct Handed {
    this_device: [u8; 32],
    /// The statement the device has applied, and the change entry of it.
    applied: SignedStatement,
    held: CheckedEntry,
    /// What that entry is named by, in hex, as the node gave it.
    over: String,
    /// The statement made apart, its entry, and what the entry is named
    /// by, where the device is in a fork.
    apart: Option<(SignedStatement, CheckedEntry, String)>,
    /// Each record of an addition that the device counts, of a key that
    /// the statement lists in neither list.
    added: Vec<SignedAddition>,
}

impl Handed {
    fn of(handed: &Value) -> anyhow::Result<Self> {
        let applied = SignedStatement::from_bytes(&hex::decode(text(handed, "statement"))?)?;
        applied.verify()?;
        let apart = match handed["apart_statement"].as_str() {
            None => None,
            Some(statement) => {
                let statement = SignedStatement::from_bytes(&hex::decode(statement)?)?;
                statement.verify()?;
                let entry = entry_of(text(handed, "apart_entry"))?;
                Some((statement, entry, text(handed, "apart").to_string()))
            }
        };
        let mut added: Vec<SignedAddition> = Vec::new();
        for kept in list(handed, "additions") {
            if kept["counted"] != true {
                continue;
            }
            let record = SignedAddition::from_bytes(&hex::decode(text(kept, "record"))?)?;
            record.verify()?;
            let key = record.addition.device.key;
            let known = applied.statement.lists(&key)
                || applied.statement.removes(&key)
                || added.iter().any(|other| other.addition.device.key == key);
            if !known {
                added.push(record);
            }
        }
        Ok(Self {
            this_device: decode_public_key(text(handed, "this_device"))?,
            applied,
            held: entry_of(text(handed, "entry"))?,
            over: text(handed, "over").to_string(),
            apart,
            added,
        })
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

/// What a person answers of one device at a change.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    Stays,
    Removed,
    /// In no list: only at a settlement.
    Neither,
}

/// Ask whether a device stays or is removed. `suggested` is the answer
/// that pressing Enter gives, where one is suggested. `neither` says
/// that the third answer is on offer: the device is in no list.
fn asks_of(says: &str, suggested: Option<Answer>, neither: bool) -> anyhow::Result<Answer> {
    let third = match neither {
        true => ", or `neither` (it is in no list, and is added again by hand)",
        false => "",
    };
    let enter = match suggested {
        Some(Answer::Stays) => " [Enter: stays]",
        Some(Answer::Removed) => " [Enter: removed]",
        _ => " [no answer is suggested]",
    };
    loop {
        let typed = terminal::answer(&format!(
            "{says}\n  Type `stays` or `removed`{third}{enter}: "
        ))?;
        match (typed.as_str(), suggested) {
            ("stays", _) => return Ok(Answer::Stays),
            ("removed", _) => return Ok(Answer::Removed),
            ("neither", _) if neither => return Ok(Answer::Neither),
            ("", Some(suggested)) => return Ok(suggested),
            _ => println!("  That is none of the answers."),
        }
    }
}

/// Make a change (see the module's documentation): what the node
/// prepared is shown, a person answers, the lists are shown from the
/// bytes that will be signed, and then the yes and the phrase. Where a
/// statement arrived meanwhile, nothing is made and it asks again.
fn change(config_path: &str, which: &Which) -> anyhow::Result<()> {
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
        let handed = Handed::of(&handed)?;
        let prepared = asked(&handed, which)?;

        // The lists, from the bytes that the phrase will sign.
        let signs = Statement::from_bytes(prepared.bytes())?;
        println!(
            "\nThe change that the recovery phrase will sign (change {}):",
            signs.number
        );
        for line in lists_shown(&signs, &handed)? {
            println!("{line}");
        }
        if !terminal::yes("\nMake this change?")? {
            println!("{NOT_A_YES}");
            return Ok(());
        }
        let entry = signed(prepared, &handed)?;

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
        )?;
        match made {
            Told::Yes(made) => {
                let number = made["change"].as_u64().unwrap_or(signs.number);
                println!(
                    "\nThe change is made (change {number}). It must not be made again on \
                     another device, even if this command is stopped now: two changes made \
                     apart have to be settled with the phrase."
                );
                return stays(config_path, number);
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
fn asked(handed: &Handed, which: &Which) -> anyhow::Result<Prepared> {
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
                "\n{}, a device of {}:",
                named(&device.label, &device.key),
                match (in_both, applied.lists(&device.key)) {
                    (true, _) => "both changes",
                    (false, true) => "the change this device had applied",
                    (false, false) => "the change made apart",
                }
            );
            match asks_of(&says, None, true)? {
                Answer::Stays => stay.push(device.clone()),
                Answer::Removed => removed.push(device.key),
                Answer::Neither => {}
            }
        }
        if !stay.iter().any(|device| device.key == own) {
            stay.insert(0, Device::new(own, &handed.label(&own))?);
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
        if !known {
            anyhow::bail!(
                "that key is no device of yours that this device knows of: `cordelia devices` \
                 lists them, each with its key."
            );
        }
        println!("\nTo be removed: {}.", named(&handed.label(&goes), &goes));
        removed.push(goes);
    }
    for device in &applied.devices {
        if Some(device.key) != goes {
            stay.push(device.clone());
        }
    }
    if !applied.lists(&own) {
        // This device was added since: the device that makes a statement
        // is always among its devices, whoever added it.
        stay.push(Device::new(own, &handed.label(&own))?);
    }
    for record in &handed.added {
        let added = &record.addition;
        let key = added.device.key;
        if key == own || Some(key) == goes {
            continue;
        }
        let by_the_one_that_goes = Some(added.adder) == goes;
        let says = format!(
            "\n{}, added since the last change, from {} at {}{}:",
            named(&added.device.label, &key),
            named(&handed.label(&added.adder), &added.adder),
            time_of(added.at),
            match by_the_one_that_goes {
                true => ". It was added by the device that is being removed",
                false => "",
            }
        );
        let suggested = (!by_the_one_that_goes).then_some(Answer::Stays);
        match asks_of(&says, suggested, false)? {
            Answer::Stays => stay.push(added.device.clone()),
            Answer::Removed => removed.push(key),
            Answer::Neither => {}
        }
    }
    Ok(prepare_change(&handed.applied, &own, stay, &removed)?)
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
            label => format!(", known here as {label}"),
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

/// Ask for the recovery phrase, and sign and seal with it what was
/// shown. The phrase is in this function and nowhere else: it is typed
/// with echo off, signs the statement, seals the part of the change
/// entry that is for it, signs the entry, and is dropped, and
/// overwritten, as this returns.
///
/// A mistyped phrase is told from a wrong one: words that are no
/// recovery phrase fail its checksum, and may be typed again. A phrase
/// that is one, and not the one that this device follows, makes nothing.
fn signed(prepared: Prepared, handed: &Handed) -> anyhow::Result<CheckedEntry> {
    let mut tries = 0;
    let phrase = loop {
        tries += 1;
        let typed =
            terminal::phrase("\nThe recovery phrase, twelve words (what you type is not shown): ")?;
        match Phrase::parse(&typed) {
            Ok(phrase) => break phrase,
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
    };
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

/// After a change: stay, and show as they come whether each relay holds
/// the change, what this device has still to send, and which of the
/// remaining devices have applied it (decision 2026-10-04 §7.1, step 4).
/// It ends when this machine may be closed.
fn stays(config_path: &str, number: u64) -> anyhow::Result<()> {
    println!(
        "This machine may be closed only when every relay holds the change and this device \
         has sent what it holds. This command stays until then, and says what is missing. \
         Stopping it stops nothing: the node goes on."
    );
    let mut said: Vec<String> = Vec::new();
    loop {
        std::thread::sleep(ASK_EVERY);
        let seen = look(config_path)?;
        if seen["change"].as_u64() != Some(number) {
            println!("This device has since applied another change: `cordelia devices` says.");
            return Ok(());
        }
        let mut now: Vec<String> = Vec::new();
        let mut missing = 0;
        let relays: Vec<&Value> = list(&seen, "relays").collect();
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
        for waits in list(&seen, "waiting") {
            if let Some(n) = waits["waits"].as_u64().filter(|n| *n > 0) {
                missing += 1;
                now.push(format!(
                    "keep this machine on: {n} of this device's channels still to send to {}",
                    text(waits, "relay")
                ));
            }
        }
        for device in list(&seen, "devices").filter(|device| device["this_device"] != true) {
            now.push(match device["applied"].as_u64() == Some(number) {
                true => format!("{} has applied the change", shown(device)),
                false => format!("{} has not applied the change yet", shown(device)),
            });
        }
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
    terminal::require()?;
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
    let seen = look(config_path)?;
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
    let agreed = terminal::yes(&format!(
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
            let goes_on = terminal::yes(
                "Under a new key nothing more can be sent in the old one's name. Go on \
                 without having told them?",
            )?;
            if !goes_on {
                println!(
                    "Stopped. This device has said that it left, and keeps its key and what \
                     it holds: run `cordelia init --new-key` again when a relay is reached."
                );
                return Ok(());
            }
        }
    }
    api_post(config_path, "/api/v1/devices/forget", json!({}))?;

    // The new key, in the place of the old one.
    let identity = NodeIdentity::generate()?;
    std::fs::write(&key_path, identity.seed())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
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
