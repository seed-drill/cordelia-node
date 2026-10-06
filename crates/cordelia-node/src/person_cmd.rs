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

use crate::terminal::Terminal;
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

/// This device's key, read from its key file as `cordelia id` reads it
/// (decision 2026-10-04 §16). What a command shows as this device, signs
/// for and prints is this, and never the node's word of it: whatever
/// answers at the node's address could otherwise name a key of its own.
fn own_key(config_path: &str) -> anyhow::Result<[u8; 32]> {
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
fn names_this_device(answer: &Value, own: &[u8; 32]) -> anyhow::Result<()> {
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
    let at = Terminal::for_a_phrase()?;
    // The first statement is made for the key in this device's key file.
    let this_device = own_key(config_path)?;
    let seen = look(config_path)?;
    names_this_device(&seen, &this_device)?;
    let among = text(&seen, "among").to_string();
    println!("{WHOSE_WORDS}\n");
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
        "The recovery phrase, shown once:",
        phrase.words()?.as_str(),
        "Write the twelve words down, in their order, and keep them where only you can \
         read them.\nPress Enter when they are written down: they are then taken off the \
         screen. ",
    )?;
    let made = {
        let typed = at.phrase(
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
    let at = Terminal::at()?;
    let device = decode_public_key(key).map_err(|e| {
        anyhow::anyhow!("that is no device's key, as `cordelia id` prints one: {e}")
    })?;
    // The key that the other device is told to type is the one in this
    // device's key file.
    let own = own_key(config_path)?;
    let body = json!({ "device": key, "label": name });
    let would = api_post(config_path, "/api/v1/devices/add/look", body.clone())?;
    names_this_device(&would, &own)?;
    let agreed = match text(&would, "would") {
        "hand_again" => at.yes(&format!(
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
    let typed = decode_public_key(key).map_err(|e| {
        anyhow::anyhow!("that is no device's key, as `cordelia id` prints one: {e}")
    })?;
    let own = own_key(config_path)?;
    let seen = look(config_path)?;
    names_this_device(&seen, &own)?;
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
    if !at.yes(&says)? {
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
    let own = own_key(config_path)?;
    if clear {
        let at = Terminal::at()?;
        let seen = look(config_path)?;
        names_this_device(&seen, &own)?;
        return clear_notices(config_path, &at, &seen);
    }
    let seen = look(config_path)?;
    names_this_device(&seen, &own)?;
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
        // Whether it has sent what it held when it applied the change
        // (§8): it says so itself, once it has.
        Some(number) if number == change => match device["sent"] == true {
            true => format!("has applied change {change}, and has sent what it held"),
            false => format!(
                "has applied change {change}, and is still sending what it held (if it is \
                 lost now, what it had not sent is lost with it)"
            ),
        },
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
        out.push("Names that no device lists yet since the last change:".into());
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
            "Names that only a device which no longer counts had synced (they stay behind):".into(),
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
            text(file, "file"),
            text(file, "name")
        ));
    }
    out
}

/// A count with its noun: `1 name`, `3 names`.
fn counted(n: usize, noun: &str) -> String {
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

/// `cordelia remove-device <key>` (decision 2026-10-04 §7.1).
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
    /// What that entry is named by, in hex, as the node gave it.
    over: String,
    /// The statement made apart, its entry, and what the entry is named
    /// by, where the device is in a fork.
    apart: Option<(SignedStatement, CheckedEntry, String)>,
    /// The record of each device added since that counts, of a key that
    /// the statement lists in neither list: what the node says a person
    /// is asked about.
    added: Vec<SignedAddition>,
    /// Each name that the personal channel lists, with the keys that
    /// list it, as this device holds that channel.
    names: Vec<(String, Vec<[u8; 32]>)>,
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
                Some((statement, entry, text(handed, "apart").to_string()))
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
        let mut names = Vec::new();
        for listed in list(handed, "names") {
            let by: Vec<[u8; 32]> = list(listed, "by")
                .filter_map(|key| decode_public_key(key.as_str()?).ok())
                .collect();
            names.push((text(listed, "name").to_string(), by));
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
        Ok(Self {
            this_device: *own,
            applied,
            held: entry_of(text(handed, "entry"))?,
            over: text(handed, "over").to_string(),
            apart,
            added,
            names,
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
fn asks_of(
    at: &Terminal,
    says: &str,
    suggested: Option<Answer>,
    neither: bool,
) -> anyhow::Result<Answer> {
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
        let typed = at.answer(&format!(
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
        )?;
        match made {
            Told::Yes(made) => {
                let number = made["change"].as_u64().unwrap_or(signs.number);
                for file in list(&made, "not_carried") {
                    println!(
                        "  What this device held of {} in {} could not be read, and was not \
                         carried: it meets its channel as a new file does.",
                        text(file, "file"),
                        text(file, "name")
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
                "\n{}, a device of {}:",
                named(&device.label, &device.key),
                match (in_both, applied.lists(&device.key)) {
                    (true, _) => "both changes",
                    (false, true) => "the change this device had applied",
                    (false, false) => "the change made apart",
                }
            );
            match asks_of(at, &says, None, true)? {
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
        if !known {
            anyhow::bail!(
                "that key is no device of yours that this device knows of: `cordelia devices` \
                 lists them, each with its key."
            );
        }
        println!("\nTo be removed: {}.", named(&handed.label(&goes), &goes));
        println!("  {}", handed.received_from(&goes));
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
        stay.push(own_listing(at, handed)?);
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
        match asks_of(at, &says, suggested, false)? {
            Answer::Stays => stay.push(added.device.clone()),
            Answer::Removed => removed.push(key),
            Answer::Neither => {}
        }
    }
    Ok(prepare_change(&handed.applied, &own, stay, &removed)?)
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
    if typed != "stays" {
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
fn signed(at: &Terminal, prepared: Prepared, handed: &Handed) -> anyhow::Result<CheckedEntry> {
    let mut tries = 0;
    let phrase = loop {
        tries += 1;
        let typed =
            at.phrase("\nThe recovery phrase, twelve words (what you type is not shown): ")?;
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
        // What this device has still to send: what it carried, as names
        // sent and names to go. (What waits is counted above, for each
        // relay it waits at.)
        let to_go = list(&seen["names"], "to_go").count();
        let sent = list(&seen["names"], "sent").count();
        if to_go > 0 {
            now.push(format!(
                "keep this machine on: {} still to send ({sent} sent)",
                counted(to_go, "name")
            ));
        } else if sent > 0 {
            now.push(format!("{} sent", counted(sent, "name")));
        }
        for device in list(&seen, "devices").filter(|device| device["this_device"] != true) {
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
        with_apart["apart"] = with_apart["over"].clone();
        let handed = f.read(&with_apart).unwrap();
        assert_eq!(handed.apart.unwrap().0, f.statement);
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
                format!("  made on laptop ({})", fingerprint::shown(&own)),
                "  devices (3):".to_string(),
                format!("    laptop ({})  (this device)", fingerprint::shown(&own)),
                format!("    phone ({})", fingerprint::shown(&f.listed)),
                format!("    desktop ({})", fingerprint::shown(&key(5))),
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

    /// `cordelia devices` says of each device whether it has sent what it
    /// held when it applied the change, what this device has still to
    /// send by name, each name that no device lists yet, with those of a
    /// key that no longer counts apart, and the files that the change
    /// could not carry (decision 2026-10-04 §4.2, §7.3, §8).
    #[test]
    fn devices_says_what_was_sent_and_which_names_are_not_yet_listed() {
        let shown = |label: &str| json!({ "key": "k", "label": label, "words": "w w w w" });
        let seen = json!({
            "this_device": "cordelia_pk1this",
            "change": 2,
            "devices": [
                { "key": "a", "label": "desktop", "words": "w", "this_device": true,
                  "applied": 2, "sent": false },
                { "key": "b", "label": "laptop", "words": "w", "applied": 2, "sent": true },
                { "key": "c", "label": "tablet", "words": "w", "applied": 2, "sent": false },
                { "key": "d", "label": "phone", "words": "w", "applied": 1, "sent": true },
            ],
            "names": { "sent": ["lab"], "to_go": ["team", "~"] },
            "names_not_listed": [
                { "name": "old-notes", "by": [shown("laptop")], "by_gone": [], "days_left": 89 },
                { "name": "its-own", "by": [], "by_gone": [shown("")], "days_left": 1 },
            ],
            "not_carried": [{ "name": "lab", "file": "ghost.md" }],
        });
        let lines = devices_lines(&seen).join("\n");
        assert!(lines.contains("desktop (w): this device"), "{lines}");
        assert!(
            lines.contains("laptop (w): has applied change 2, and has sent what it held"),
            "{lines}"
        );
        assert!(
            lines.contains("tablet (w): has applied change 2, and is still sending what it held"),
            "{lines}"
        );
        // A device that has not applied the change is not said to have
        // sent anything, whatever its word of an earlier one says.
        assert!(
            lines.contains("phone (w): has not applied change 2 yet"),
            "{lines}"
        );
        assert!(
            lines.contains("Still to send from this device (1 name sent, 2 to go):\n  team\n  ~"),
            "{lines}"
        );
        assert!(
            lines.contains(
                "Names that no device lists yet since the last change:\n  old-notes: synced \
                 before by laptop (w w w w); what the relays hold of it can be brought in for \
                 89 more days"
            ),
            "{lines}"
        );
        assert!(
            lines.contains(
                "Names that only a device which no longer counts had synced (they stay \
                 behind):\n  its-own: synced before by the device (w w w w); it can be brought \
                 in for 1 more day"
            ),
            "{lines}"
        );
        assert!(lines.contains("Not carried at the last change"), "{lines}");
        assert!(lines.contains("  ghost.md in lab"), "{lines}");

        // With nothing to say of names, nothing is said of them.
        let quiet = json!({ "this_device": "k", "change": 2, "devices": [],
            "names": { "sent": ["lab"], "to_go": [] } });
        assert!(names_lines(&quiet).is_empty());
    }
}
