//! `cordelia sync carry`: a carry that a person asks for (decision
//! 2026-10-04 §7.3).
//!
//! A device that applies a change carries what it holds, and reads the
//! channels it left no more. What the relays hold of a generation that
//! was left, beyond what the remaining devices had taken, stays where it
//! is until a person asks for it: the last edits of a device that never
//! returned, or a name that no device syncs any more.
//!
//! `cordelia sync carry <name>` asks for one name, and with no name for
//! every name that this device holds. The node reads the name's channel
//! in each generation that the device left and still holds the secret
//! of, the newest first, and takes what keys that count signed there:
//! each version as this device's own entry, at its revision, where the
//! new channel holds neither that version nor an entry at a higher
//! revision. The command says what was brought in, what was left and
//! why, and what could not be read.
//!
//! `cordelia sync map` does the same for a name that the device comes to
//! sync, where the new channel holds nothing for it, and prints it with
//! the same words ([`carried_lines`]).
//!
//! ## With the recovery phrase
//!
//! **What a removed key signed comes in only by `--from`,** at a
//! terminal, with the phrase ([`from`]). The command says what it found
//! before it asks for anything: the keys, each by the first words of its
//! fingerprint, worked out here from the key itself; how many versions
//! would go into slots where the new channel holds none; which stand
//! above a version that the new channel holds; and that a device in
//! someone else's hands may have written any of them since. It brings in
//! the first kind on a yes, and the second only on a second yes that
//! names the files, for a name that has a folder here. With no key it
//! lists the removed keys that signed there, and takes nothing.
//!
//! **`--phrase` reads the generations whose secret this device never
//! held** ([`with_the_phrase`]): the part of the change entry that is for
//! the phrase holds their secrets, and the command opens it in this
//! process. It makes the proofs of each channel's key here, has the node
//! pull, reads what the relays handed here, and hands the node the
//! versions that keys which count signed.
//!
//! **The phrase stays in this process,** as in every command that reads
//! one (decision 2026-10-04 §5): it is typed with echo off, signs a word
//! that says what may be taken ([`cordelia_api::carry::Word`]), and is
//! dropped before anything is read at a relay or handed to the node.
//! The node is handed that word, and no secret.

use std::time::Duration;

use serde_json::{Value, json};
use zeroize::Zeroizing;

use cordelia_api::carry::{self, Allows, Handed, Word};
use cordelia_api::change::read_with;
use cordelia_api::person::PersonError;
use cordelia_core::protocol::{CARRY_FIRST_MAX_SECS, CARRY_PART_MAX_BYTES, CARRY_READ_MAX_SECS};
use cordelia_crypto::entry::{CheckedEntry, Entry};
use cordelia_crypto::statement::StatementError;
use cordelia_crypto::{derive, fingerprint, proof};

use crate::person_cmd::{
    NOT_A_YES, counted, entry_of, file_shown, list, look, names_this_device, own_key, text,
    typed_phrase, words_then,
};
use crate::terminal::Terminal;
use crate::{Told, api_post_told, api_post_within, refuse_another_version, refuse_before_a_phrase};

/// How long `cordelia sync map` waits for the node's answer: a device
/// that comes to sync a name carries it first, before the node answers.
pub(crate) const MAP_WAITS: Duration = Duration::from_secs(CARRY_FIRST_MAX_SECS + 30);

/// How long `cordelia sync carry` waits for the node's answer about one
/// name: the node reads for no longer than a carry may, and then waits
/// for the last page that it had asked for.
const CARRY_WAITS: Duration = Duration::from_secs(CARRY_READ_MAX_SECS + 90);

/// `cordelia sync carry [<name>] [--from [<key>]...] [--phrase]`
/// (decision 2026-10-04 §7.3). Each `--from` names one removed key, by
/// its label or by the first six words of its key's fingerprint; with no
/// key after it, the removed keys that signed there are listed.
pub(crate) fn carry(
    config_path: &str,
    name: Option<String>,
    from: Option<Vec<String>>,
    phrase: bool,
) -> anyhow::Result<()> {
    // In its one spelling, as `map` sends a name that is typed.
    let name = name.map(|name| cordelia_core::sync_name::tidy(&name));
    let needs_a_name = |with: &str| {
        anyhow::anyhow!(
            "`cordelia sync carry {with}` is for one name: cordelia sync carry <name> {with}"
        )
    };
    match (from, phrase) {
        (Some(_), true) => anyhow::bail!(
            "`--from` and `--phrase` are two carries, and each is run by itself: `--from` takes \
             what a removed device wrote, from the generations that this device left; `--phrase` \
             takes what your devices that count wrote, from the generations whose secret this \
             device never held. Nothing was done."
        ),
        (Some(named), false) => {
            let name = name.ok_or_else(|| needs_a_name("--from"))?;
            // Each `--from` names one key; one with nothing after it
            // names none.
            let named: Vec<String> = named
                .into_iter()
                .filter(|named| !named.trim().is_empty())
                .collect();
            from_keys(config_path, &name, &named)
        }
        (None, true) => {
            let name = name.ok_or_else(|| needs_a_name("--phrase"))?;
            with_the_phrase(config_path, &name)
        }
        (None, false) => {
            refuse_another_version(config_path)?;
            of_the_keys_that_count(config_path, name)
        }
    }
}

/// `cordelia sync carry [<name>]`: with a name, that name; with none,
/// every name that this device holds.
fn of_the_keys_that_count(config_path: &str, name: Option<String>) -> anyhow::Result<()> {
    let names: Vec<String> = match name {
        Some(name) => vec![name],
        None => {
            let seen = look(config_path)?;
            let mut held: Vec<String> = list(&seen["names"], "sent")
                .chain(list(&seen["names"], "to_go"))
                .filter_map(|name| name.as_str().map(str::to_string))
                .collect();
            held.sort();
            held.dedup();
            if held.is_empty() {
                println!(
                    "This device holds no name. `cordelia sync carry <name>` carries one by its \
                     name; `cordelia devices` lists the names that no device lists yet."
                );
                return Ok(());
            }
            held
        }
    };
    println!(
        "Asking the relays for what your devices had sent before the last change, in each \
         generation that this device left in the last 90 days (up to {} for a name)...",
        minutes(CARRY_READ_MAX_SECS)
    );
    for name in names {
        let done = api_post_within(
            config_path,
            "/api/v1/carry",
            json!({ "name": name }),
            Some(CARRY_WAITS),
        )?;
        for line in carried_lines(&done) {
            println!("{line}");
        }
    }
    Ok(())
}

/// What the node answered, or its refusal as this command's own error:
/// nothing was taken where it refused.
fn told(asked: anyhow::Result<Told>) -> anyhow::Result<Value> {
    match asked? {
        Told::Yes(answer) => Ok(answer),
        Told::No { message, .. } => anyhow::bail!("{message}\nNothing was taken."),
    }
}

/// 32 bytes, from their hex.
fn bytes_of(hex_bytes: &str, what: &str) -> anyhow::Result<[u8; 32]> {
    carry::key_named(hex_bytes)
        .ok_or_else(|| anyhow::anyhow!("the node handed {what} that is not 32 bytes in hex"))
}

/// What is said of a removed device before anything of it is taken
/// (decision 2026-10-04 §7.3).
const MAY_HAVE_CHANGED: &str = "This is what that device wrote, as the relays hold it now. If it \
    was in someone else's hands, they may have changed it since: say no unless you know it was \
    not.";

/// `cordelia sync carry <name> --from [<key>]...`: what the named removed
/// devices signed in the name's channel, in the generations that this
/// device left (decision 2026-10-04 §7.3). With no key, the removed keys
/// that signed there are listed, and nothing is taken.
fn from_keys(config_path: &str, name: &str, named: &[String]) -> anyhow::Result<()> {
    // With a key named it asks for the phrase: at a terminal, in a
    // process that cannot be dumped, before anything is read.
    let at = match named.is_empty() {
        true => {
            refuse_another_version(config_path)?;
            None
        }
        false => {
            let at = Terminal::for_a_phrase()?;
            refuse_before_a_phrase(config_path)?;
            Some(at)
        }
    };
    let own = own_key(config_path)?;
    println!(
        "Asking the relays for what they hold of {} in each generation that this device left in \
         the last 90 days (up to {})...",
        file_shown(name),
        minutes(CARRY_READ_MAX_SECS)
    );
    let found = told(api_post_told(
        config_path,
        "/api/v1/carry/from/look",
        json!({ "name": name, "from": named }),
        Some(CARRY_WAITS),
    ))?;
    names_this_device(&found, &own)?;
    if let Some(nothing) = found["nothing"].as_str() {
        println!("{}: nothing can be read: {nothing}.", file_shown(name));
        return Ok(());
    }
    for line in not_read_lines(&found) {
        println!("{line}");
    }
    for line in signed_lines(&found, name) {
        println!("{line}");
    }
    let Some(at) = at else {
        println!(
            "Nothing was taken. To bring in what one of them wrote: cordelia sync carry {} \
             --from \"<its label, or those six words>\"",
            file_shown(name)
        );
        return Ok(());
    };

    // What it found, before anything is asked (§7.3).
    let found = Found::of(&found)?;
    for line in found.lines(name) {
        println!("{line}");
    }
    if found.empty == 0 && (found.above.is_empty() || !found.has_folder) {
        println!("Nothing was taken.");
        return Ok(());
    }
    println!("\n{MAY_HAVE_CHANGED}");
    if found.empty > 0
        && !at.yes(&format!(
            "\nBring in {} into {} where the new channel holds nothing?",
            counted(found.empty, "version"),
            match found.empty {
                1 => "the slot",
                _ => "slots",
            }
        ))?
    {
        println!("{NOT_A_YES}");
        return Ok(());
    }
    // The second kind, only on a second yes, which names the files.
    let mut above: Vec<String> = Vec::new();
    if !found.above.is_empty() && found.has_folder {
        let files: Vec<String> = found.above.iter().map(|file| file_shown(file)).collect();
        let second = at.yes(&format!(
            "\nAlso bring in {} above {} that the new channel holds? The text that each replaces \
             is kept beside its file, here and on each device that holds it:\n  {}",
            counted(files.len(), "version"),
            match files.len() {
                1 => "the version",
                _ => "the versions",
            },
            files.join("\n  ")
        ))?;
        match second {
            true => above = found.above.clone(),
            false if found.empty == 0 => {
                println!("{NOT_A_YES}");
                return Ok(());
            }
            false => println!("Those stay where they are."),
        }
    }

    // The phrase signs what was shown, and is dropped before the node is
    // asked anything more.
    let allows = Allows::From {
        name: name.to_string(),
        keys: found.keys.iter().map(hex::encode).collect(),
        above,
    };
    let word = word_for(config_path, &at, &own, &found.under, &allows)?;
    let done = told(api_post_told(
        config_path,
        "/api/v1/carry/from",
        json!({ "word": word }),
        Some(CARRY_WAITS),
    ))?;
    for line in carried_lines(&done) {
        println!("{line}");
    }
    Ok(())
}

/// Ask for the recovery phrase, and give its word for `allows` on this
/// device, under the change entry named `under`. The phrase is in this
/// function and nowhere else: it signs the word, and is dropped, and
/// overwritten, as this returns.
///
/// A phrase that is one, and not the one that this device follows, gives
/// no word: the node says which phrase the device follows by the first
/// words of its key's fingerprint, and the words of the phrase that was
/// typed are set beside them here.
fn word_for(
    config_path: &str,
    at: &Terminal,
    own: &[u8; 32],
    under: &[u8; 32],
    allows: &Allows,
) -> anyhow::Result<Word> {
    let phrase = typed_phrase(at)?;
    let follows = look(config_path)?;
    if text(&follows, "phrase_words") != fingerprint::shown(&phrase.public_key()?) {
        anyhow::bail!(
            "that is a recovery phrase, and it is not the one that this device follows: nothing \
             was taken."
        );
    }
    let now = chrono::Utc::now().timestamp();
    Ok(Word::give(&phrase, own, under, allows.says()?, now)?)
}

/// What `--from` found, read from the node's answer. The keys are read
/// from their bytes, and their words are worked out here.
struct Found {
    /// The keys that were named.
    keys: Vec<[u8; 32]>,
    /// The label that this device knew each by.
    labels: Vec<String>,
    /// What the change entry that the device keeps is named by.
    under: [u8; 32],
    /// How many versions would go into slots where the new channel holds
    /// nothing.
    empty: usize,
    /// The files of which a version stands above one that the new
    /// channel holds.
    above: Vec<String>,
    /// How many deletes of theirs there are, which are never taken.
    deletes: usize,
    /// How many the new channel holds already, or holds a higher
    /// revision of.
    held: usize,
    higher: usize,
    ties: Vec<String>,
    /// Whether a folder of this device's is mapped to the name.
    has_folder: bool,
}

impl Found {
    fn of(found: &Value) -> anyhow::Result<Self> {
        let mut keys = Vec::new();
        let mut labels = Vec::new();
        for key in list(found, "keys") {
            keys.push(bytes_of(text(key, "key"), "a key")?);
            labels.push(text(key, "label").to_string());
        }
        let number = |field: &str| found[field].as_u64().unwrap_or(0) as usize;
        let files = |field: &str| -> Vec<String> {
            list(found, field)
                .filter_map(|file| file.as_str().map(str::to_string))
                .collect()
        };
        Ok(Self {
            keys,
            labels,
            under: bytes_of(text(found, "under"), "what its change entry is named by")?,
            empty: number("empty"),
            above: files("above"),
            deletes: number("deletes"),
            held: number("held"),
            higher: number("higher"),
            ties: files("ties"),
            has_folder: found["has_folder"] == true,
        })
    }

    /// What was found, in lines (decision 2026-10-04 §7.3): the keys; how
    /// many versions would go into slots where the new channel holds
    /// none; which stand above a version that the new channel holds; and
    /// that a device in someone else's hands may have written any of
    /// them since.
    fn lines(&self, name: &str) -> Vec<String> {
        let name = file_shown(name);
        let mut lines = vec![format!("\nWhat {} signed in {name}:", {
            match self.keys.len() {
                1 => "this removed key",
                _ => "these removed keys, the newest version of each file among them",
            }
        })];
        for (key, label) in self.keys.iter().zip(&self.labels) {
            lines.push(format!(
                "  {}",
                words_then(&carry::naming_words(key), label)
            ));
        }
        lines.push(format!(
            "  {} would go into {} where the new channel holds nothing.",
            counted(self.empty, "version"),
            match self.empty {
                1 => "a slot",
                _ => "slots",
            }
        ));
        if !self.above.is_empty() {
            let files: Vec<String> = self.above.iter().map(|file| file_shown(file)).collect();
            lines.push(format!(
                "  {} above a version that the new channel holds: {}.",
                match files.len() {
                    1 => "1 version stands".to_string(),
                    n => format!("{n} versions stand"),
                },
                files.join(", ")
            ));
            lines.push(match self.has_folder {
                true => "    Those come in only on a second yes, which names them.".to_string(),
                false => format!(
                    "    Those are not brought in: no folder of this device's is mapped to \
                     {name}, so nothing would be kept of the text that each replaces. Map a \
                     folder to it first (`cordelia sync map`)."
                ),
            });
        }
        if self.deletes > 0 {
            lines.push(format!(
                "  {} not taken: a delete that a removed key signed never is.",
                match self.deletes {
                    1 => "1 delete is".to_string(),
                    n => format!("{n} deletes are"),
                }
            ));
        }
        let there = self.held + self.higher + self.ties.len();
        if there > 0 {
            lines.push(format!(
                "  {} nothing to bring: the new channel holds {}, or a higher revision.",
                match there {
                    1 => "1 version is".to_string(),
                    n => format!("{n} versions are"),
                },
                match there {
                    1 => "it",
                    _ => "them",
                }
            ));
        }
        lines.push(
            "  A device in someone else's hands may have written any of these since it was \
             removed: a relay keeps what a key last sent it."
                .to_string(),
        );
        lines
    }
}

/// Each removed key that signed in the generations that were read, with
/// how much, in lines (decision 2026-10-04 §7.3). The words that name a
/// key are worked out here, from the key.
fn signed_lines(found: &Value, name: &str) -> Vec<String> {
    let name = file_shown(name);
    let mut lines = Vec::new();
    for signed in list(found, "signed") {
        let Some(key) = carry::key_named(text(signed, "key")) else {
            continue;
        };
        let entries = signed["entries"].as_u64().unwrap_or(0) as usize;
        lines.push(format!(
            "  {}: {}",
            words_then(&carry::naming_words(&key), text(signed, "label")),
            counted(entries, "entry").replace("entrys", "entries")
        ));
    }
    match lines.is_empty() {
        true => vec![format!(
            "No removed key signed anything that the relays hold of {name}, in the generations \
             that this device can read."
        )],
        false => {
            let says = format!(
                "Removed keys that signed in {name}, in the generations that this device can \
                 read, each by the first six words of its key's fingerprint:"
            );
            lines.insert(0, says);
            lines
        }
    }
}

/// What could not be read, by generation and relay, in lines.
fn not_read_lines(done: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    for generation in list(done, "generations") {
        let change = generation["number"].as_u64().unwrap_or(0);
        for relay in list(generation, "relays") {
            let read = text(relay, "read");
            if matches!(read, "whole" | "not held") {
                continue;
            }
            lines.push(format!(
                "  Could not read change {change} at {} to its end ({read}): run this again \
                 once it can be.",
                text(relay, "relay")
            ));
        }
        if list(generation, "relays").next().is_none() {
            lines.push(format!(
                "  Could not read change {change}: no relay was reached. Run this again once \
                 one is."
            ));
        }
    }
    lines
}

/// `cordelia sync carry <name> --phrase`: what your devices that count
/// signed in the name's channel, in the generations whose secret this
/// device never held (decision 2026-10-04 §7.3). The part of the change
/// entry that is for the phrase holds those secrets: it is opened here,
/// the channels are read through the node with proofs made here, and
/// the node is handed the versions, and no secret.
fn with_the_phrase(config_path: &str, name: &str) -> anyhow::Result<()> {
    let at = Terminal::for_a_phrase()?;
    refuse_before_a_phrase(config_path)?;
    let own = own_key(config_path)?;
    let shown = file_shown(name);
    println!(
        "With the recovery phrase, this reads what the relays hold of {shown} in the generations \
         whose secret this device never held: it was off through a change, or was added after \
         one. From those it takes what your devices that count signed, as `cordelia sync carry \
         {shown}` does from the generations that this device left: what your own devices wrote, \
         as the relays hold it now."
    );
    if !at.yes(&format!(
        "\nRead those generations of {shown}, and bring in what the new channel lacks?"
    ))? {
        println!("{NOT_A_YES}");
        return Ok(());
    }
    println!("Fetching what the relays hold of the new channel first...");
    let handed = told(api_post_told(
        config_path,
        "/api/v1/carry/phrase/look",
        json!({ "name": name }),
        Some(CARRY_WAITS),
    ))?;
    names_this_device(&handed, &own)?;
    // What the word is given under is worked out here, from the entry.
    let entry = entry_of(text(&handed, "entry"))?;
    let under = entry.id();
    let held: Vec<[u8; 32]> = list(&handed, "held")
        .filter_map(|channel| carry::key_named(channel.as_str()?))
        .collect();
    let counts: Vec<[u8; 32]> = list(&handed, "counts")
        .filter_map(|key| carry::key_named(key.as_str()?))
        .collect();
    let sessions: Vec<(String, [u8; 32])> = list(&handed, "sessions")
        .filter_map(|at| {
            let session = carry::key_named(at["session"].as_str()?)?;
            Some((text(at, "relay").to_string(), session))
        })
        .collect();
    if sessions.is_empty() {
        anyhow::bail!("no relay is connected: nothing can be read. Nothing was taken.");
    }

    // The phrase opens the secrets, signs its word, and is dropped
    // before anything is read at a relay.
    let (word, generations) = {
        let phrase = typed_phrase(&at)?;
        let (statement, for_phrase) = match read_with(&phrase, &entry) {
            Ok(read) => read,
            Err(PersonError::Statement(StatementError::AnotherPhrase))
            | Err(PersonError::ChangeEntry(_)) => anyhow::bail!(
                "that is a recovery phrase, and it is not the one that this device follows: \
                 nothing was taken."
            ),
            Err(e) => anyhow::bail!("{e}: nothing was taken."),
        };
        let allows = Allows::Handed {
            name: name.to_string(),
        };
        let now = chrono::Utc::now().timestamp();
        let word = Word::give(&phrase, &own, &under, allows.says()?, now)?;
        // The secret of the name's channel in each generation that the
        // entry gives the phrase, the newest first: the person secret
        // of each is dropped with the part that held it.
        let mut generations: Vec<(u64, Zeroizing<[u8; 32]>)> = Vec::new();
        let its_own = (statement.statement.number, for_phrase.secret);
        let earlier = for_phrase.earlier.iter().map(|e| (e.number, e.secret));
        for (number, secret) in [its_own].into_iter().chain(earlier) {
            let secret = Zeroizing::new(secret);
            generations.push((number, Zeroizing::new(derive::own_secret(&secret, name)?)));
        }
        (word, generations)
    };

    let mut versions = Vec::new();
    let mut by_other_keys = 0;
    let mut read_any = false;
    for (number, secret) in &generations {
        let channel = derive::channel_id(secret)?;
        if held.contains(&channel) {
            // The node holds this generation's secret: the plain command
            // reads it.
            continue;
        }
        read_any = true;
        let mut proofs = Vec::new();
        for (relay, session) in &sessions {
            let proof = proof::make(secret, session, &own)?;
            proofs.push(json!({ "relay": relay, "proof": hex::encode(proof) }));
        }
        let (entries, relays) = read_through_the_node(config_path, &channel, proofs)?;
        for relay in &relays {
            let read = text(relay, "read");
            if !matches!(read, "whole" | "not held") {
                println!(
                    "  Could not read change {number} at {} to its end ({read}): run this again \
                     once it can be.",
                    text(relay, "relay")
                );
            }
        }
        let was = carry::read(&entries, secret, *number, |key| counts.contains(key))?;
        by_other_keys += was.signed_by(|key| !counts.contains(key));
        versions.extend(was.versions);
    }
    drop(generations);
    if !read_any {
        println!(
            "{shown}: this device holds the secret of every generation that its change entry \
             gives the phrase. `cordelia sync carry {shown}` reads those."
        );
        return Ok(());
    }

    // The newest version of each file, handed to the node in the clear,
    // a batch at a time.
    let newest: Vec<Handed> = carry::newest(versions)
        .iter()
        .filter_map(|version| Handed::of(version, &own))
        .collect();
    let mut total = json!({
        "name": name, "generations": [], "carried": 0, "held": 0, "higher": 0,
        "ties": [], "above": [], "deletes": 0, "by_other_keys": by_other_keys, "nothing": null,
    });
    for batch in batches(&newest, CARRY_PART_MAX_BYTES) {
        let done = told(api_post_told(
            config_path,
            "/api/v1/carry/handed",
            json!({ "word": word, "versions": batch }),
            Some(CARRY_WAITS),
        ))?;
        add_to(&mut total, &done);
    }
    for line in carried_lines(&total) {
        println!("{line}");
    }
    Ok(())
}

/// Read the channel whose ID is `channel` at each relay, through the
/// node, with the proofs given: the node proves and pulls, and hands back
/// what the relays handed, a part at a time. Each entry is checked here
/// as whatever a device is given is checked: one that does not pass is
/// dropped. Returns the entries, and what the node says of each relay.
pub(crate) fn read_through_the_node(
    config_path: &str,
    channel: &[u8; 32],
    proofs: Vec<Value>,
) -> anyhow::Result<(Vec<CheckedEntry>, Vec<Value>)> {
    let read = told(api_post_told(
        config_path,
        "/api/v1/carry/read",
        json!({ "channel": hex::encode(channel), "proofs": proofs }),
        Some(CARRY_WAITS),
    ))?;
    let relays: Vec<Value> = list(&read, "relays").cloned().collect();
    let mut entries: Vec<CheckedEntry> = Vec::new();
    let mut from = (read["entries"].as_u64().unwrap_or(0) > 0).then_some(0u64);
    while let Some(at) = from {
        let part = told(api_post_told(
            config_path,
            "/api/v1/carry/read/part",
            json!({ "read": read["read"], "from": at }),
            Some(Duration::from_secs(30)),
        ))?;
        for bytes in list(&part, "entries") {
            let checked = hex::decode(bytes.as_str().unwrap_or_default())
                .ok()
                .and_then(|bytes| Entry::from_wire(&bytes).ok()?.check().ok());
            entries.extend(checked);
        }
        from = part["next"].as_u64();
    }
    Ok((entries, relays))
}

/// `versions` in batches, each of which holds no more than `max_bytes`
/// of text, and one version at least.
fn batches(versions: &[Handed], max_bytes: usize) -> Vec<&[Handed]> {
    let mut batches = Vec::new();
    let (mut start, mut bytes) = (0, 0);
    for (at, version) in versions.iter().enumerate() {
        let size = version.text.as_ref().map_or(0, String::len) + version.name.len();
        if at > start && bytes + size > max_bytes {
            batches.push(&versions[start..at]);
            (start, bytes) = (at, 0);
        }
        bytes += size;
    }
    if start < versions.len() {
        batches.push(&versions[start..]);
    }
    batches
}

/// Add what the node said of one batch to what it said of those before.
fn add_to(total: &mut Value, done: &Value) {
    for field in ["carried", "held", "higher", "deletes", "by_other_keys"] {
        let sum = total[field].as_u64().unwrap_or(0) + done[field].as_u64().unwrap_or(0);
        total[field] = sum.into();
    }
    for field in ["ties", "above"] {
        let more: Vec<Value> = list(done, field).cloned().collect();
        if let Some(all) = total[field].as_array_mut() {
            all.extend(more);
        }
    }
}

/// A number of seconds, as minutes, in words.
fn minutes(secs: u64) -> String {
    match secs / 60 {
        1 => "a minute".to_string(),
        n => format!("{n} minutes"),
    }
}

/// What a carry of one name did, as the node answered it, in lines
/// (decision 2026-10-04 §7.3): how much was brought in; how much was left
/// because the new channel holds a higher revision; what a tie kept this
/// device from bringing; how much other keys signed, which comes in only
/// with the phrase; and what could not be read. Nothing where the node
/// said nothing of a carry.
///
/// A file's name is another device's word: it is printed as local
/// history prints names.
pub(crate) fn carried_lines(done: &Value) -> Vec<String> {
    let Some(name) = done["name"].as_str() else {
        return Vec::new();
    };
    let name = file_shown(name);
    let number = |field: &str| done[field].as_u64().unwrap_or(0) as usize;
    let mut lines = Vec::new();
    if let Some(nothing) = done["nothing"].as_str() {
        lines.push(format!("{name}: nothing was carried: {nothing}."));
        return lines;
    }
    lines.push(match number("carried") {
        0 => format!("{name}: nothing to bring in from what was read."),
        carried => format!(
            "{name}: {} brought in, each as this device's own entry at the revision it had.",
            counted(carried, "version")
        ),
    });
    if done["held_anew"] == true {
        lines.push(format!(
            "  This device now holds {name} and lists it, with no folder mapped to it: it \
             sends what it carried, and carries the name at each later change."
        ));
    }
    if number("higher") > 0 {
        lines.push(format!(
            "  {} left: the new channel holds a higher revision of {}.",
            counted(number("higher"), "version"),
            match number("higher") {
                1 => "that file",
                _ => "those files",
            }
        ));
    }
    let ties: Vec<String> = list(done, "ties")
        .filter_map(Value::as_str)
        .map(file_shown)
        .collect();
    if !ties.is_empty() {
        lines.push(format!(
            "  {} left: {} with an entry of this device's own at that revision, and a device \
             has one entry for a file. Another device of yours can bring {}: {}.",
            counted(ties.len(), "version"),
            match ties.len() {
                1 => "it ties",
                _ => "they tie",
            },
            match ties.len() {
                1 => "it",
                _ => "them",
            },
            ties.join(", ")
        ));
    }
    if number("by_other_keys") > 0 {
        lines.push(format!(
            "  {} that other keys signed {} left behind. What a removed device wrote comes in \
             only with the recovery phrase: `cordelia sync carry {name} --from <its label, or \
             the first six words of its key's fingerprint>`.",
            counted(number("by_other_keys"), "entry").replace("entrys", "entries"),
            match number("by_other_keys") {
                1 => "was",
                _ => "were",
            }
        ));
    }
    let above: Vec<String> = list(done, "above")
        .filter_map(Value::as_str)
        .map(file_shown)
        .collect();
    if !above.is_empty() {
        lines.push(format!(
            "  {} left: {} above a version that the new channel holds, and {} in only on a \
             second yes, for a name that has a folder here: {}.",
            counted(above.len(), "version"),
            match above.len() {
                1 => "it stands",
                _ => "they stand",
            },
            match above.len() {
                1 => "comes",
                _ => "come",
            },
            above.join(", ")
        ));
    }
    if number("deletes") > 0 {
        lines.push(format!(
            "  {} not taken: a delete that a removed key signed never is.",
            match number("deletes") {
                1 => "1 delete was".to_string(),
                n => format!("{n} deletes were"),
            }
        ));
    }
    // What could not be read, by generation and relay.
    lines.extend(not_read_lines(done));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a carry of one name did is said in lines (decision 2026-10-04
    /// §7.3): what was brought in, what was left and why, and what could
    /// not be read; and nothing where the node said nothing of a carry.
    #[test]
    fn test_what_a_carry_did_is_said_in_lines() {
        assert!(carried_lines(&Value::Null).is_empty());
        let relay = |name: &str, read: &str| json!({ "relay": name, "read": read });
        let done = json!({
            "name": "lab",
            "held_anew": true,
            "generations": [
                { "number": 3, "relays": [relay("one", "whole"), relay("two", "not held")] },
                { "number": 2, "relays": [relay("one", "part"), relay("two", "not reached")] },
                { "number": 1, "relays": [] },
            ],
            "carried": 3,
            "held": 5,
            "higher": 2,
            "ties": ["notes.md"],
            "by_other_keys": 4,
            "read_all": false,
            "nothing": null,
        });
        let lines = carried_lines(&done);
        let all = lines.join("\n");
        assert_eq!(
            lines[0],
            "lab: 3 versions brought in, each as this device's own entry at the revision it had."
        );
        assert!(
            all.contains("This device now holds lab and lists it"),
            "{all}"
        );
        assert!(
            all.contains(
                "2 versions left: the new channel holds a higher revision of those files."
            ),
            "{all}"
        );
        assert!(
            all.contains("1 version left: it ties with an entry of this device's own"),
            "{all}"
        );
        assert!(all.contains("can bring it: notes.md."), "{all}");
        assert!(
            all.contains("4 entries that other keys signed were left behind"),
            "{all}"
        );
        assert!(all.contains("`cordelia sync carry lab --from"), "{all}");
        // What was read to its end is not said: what was not, is.
        assert!(!all.contains("change 3"), "{all}");
        assert!(
            all.contains("Could not read change 2 at one to its end (part)"),
            "{all}"
        );
        assert!(
            all.contains("Could not read change 2 at two to its end (not reached)"),
            "{all}"
        );
        assert!(
            all.contains("Could not read change 1: no relay was reached."),
            "{all}"
        );

        // One of each is said as one, and nothing as nothing.
        let one = json!({
            "name": "lab", "held_anew": false, "generations": [], "carried": 1,
            "higher": 1, "ties": ["a.md", "b.md"], "by_other_keys": 1, "nothing": null,
        });
        let all = carried_lines(&one).join("\n");
        assert!(all.contains("lab: 1 version brought in"), "{all}");
        assert!(
            all.contains("1 version left: the new channel holds a higher revision of that file.")
        );
        assert!(all.contains("2 versions left: they tie with"), "{all}");
        assert!(all.contains("can bring them: a.md, b.md."), "{all}");
        assert!(
            all.contains("1 entry that other keys signed was left behind"),
            "{all}"
        );
        assert!(!all.contains("now holds"), "{all}");
        let none = json!({
            "name": "lab", "generations": [], "carried": 0, "higher": 0, "ties": [],
            "by_other_keys": 0, "nothing": null,
        });
        assert_eq!(
            carried_lines(&none),
            ["lab: nothing to bring in from what was read."]
        );
        let nothing = json!({ "name": "lab", "nothing": "this device holds no secret" });
        assert_eq!(
            carried_lines(&nothing),
            ["lab: nothing was carried: this device holds no secret."]
        );
        // A name, and a file's name, are printed safely.
        let odd = json!({
            "name": "la\u{1b}[2Jb", "generations": [], "carried": 0, "higher": 0,
            "ties": ["a\u{202e}.md"], "by_other_keys": 0, "nothing": null,
        });
        let all = carried_lines(&odd).join("\n");
        assert!(!all.chars().any(|c| c.is_control() && c != '\n'), "{all:?}");
        assert!(!all.contains('\u{202e}'), "{all:?}");
    }

    /// What `--from` found is said before anything is asked (decision
    /// 2026-10-04 §7.3): the keys, each by six words that are worked out
    /// from the key itself, with its label quoted; how many versions
    /// would go into slots where the new channel holds none; which stand
    /// above a version that it holds, and that those need a second yes,
    /// or a folder; the deletes that are never taken; and that a device
    /// in someone else's hands may have written any of them since.
    #[test]
    fn test_what_from_found_is_said_before_anything_is_asked() {
        let key = [7u8; 32];
        let found = |above: Value, has_folder: bool| {
            json!({
                "keys": [{
                    "key": hex::encode(key),
                    // The node's word of the words is not what is shown.
                    "words": "not these words",
                    "label": "desk\u{1b}top",
                }],
                "under": hex::encode([3u8; 32]),
                "empty": 2, "above": above, "deletes": 1, "held": 1, "higher": 1,
                "ties": ["t.md"], "has_folder": has_folder,
            })
        };
        let read = Found::of(&found(json!(["a.md", "b\u{202e}.md"]), true)).unwrap();
        assert_eq!(read.keys, [key]);
        assert_eq!(read.under, [3u8; 32]);
        assert_eq!((read.empty, read.deletes), (2, 1));
        let all = read.lines("lab").join("\n");
        assert!(
            all.contains("What this removed key signed in lab:"),
            "{all}"
        );
        assert!(all.contains(&carry::naming_words(&key)), "{all}");
        assert!(!all.contains("not these words"), "{all}");
        assert!(
            all.contains("2 versions would go into slots where the new channel holds nothing."),
            "{all}"
        );
        assert!(
            all.contains("2 versions stand above a version that the new channel holds: a.md,"),
            "{all}"
        );
        assert!(
            all.contains("Those come in only on a second yes, which names them."),
            "{all}"
        );
        assert!(
            all.contains("1 delete is not taken: a delete that a removed key signed never is."),
            "{all}"
        );
        assert!(all.contains("3 versions are nothing to bring"), "{all}");
        assert!(
            all.contains("A device in someone else's hands may have written any of these since"),
            "{all}"
        );
        // A label, and a file's name, are printed safely.
        assert!(!all.chars().any(|c| c.is_control() && c != '\n'), "{all:?}");
        assert!(!all.contains('\u{202e}'), "{all:?}");

        // With no folder, what stands above is not brought in, and that
        // is said.
        let no_folder = Found::of(&found(json!(["a.md"]), false)).unwrap();
        let all = no_folder.lines("lab").join("\n");
        assert!(all.contains("1 version stands above a version"), "{all}");
        assert!(all.contains("Those are not brought in: no folder"), "{all}");
        assert!(!all.contains("second yes"), "{all}");
        // Two keys: the newest version of each file among them.
        let mut two = found(json!([]), true);
        two["keys"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "key": hex::encode([8u8; 32]), "label": "" }));
        let all = Found::of(&two).unwrap().lines("lab").join("\n");
        assert!(
            all.contains("these removed keys, the newest version of each file among them"),
            "{all}"
        );
        assert!(!all.contains("stand above"), "{all}");
        // A key, or what the word is given under, that is none is
        // refused.
        let mut bad = found(json!([]), true);
        bad["keys"][0]["key"] = "zz".into();
        assert!(Found::of(&bad).is_err());
        let mut bad = found(json!([]), true);
        bad["under"] = "00".into();
        assert!(Found::of(&bad).is_err());
    }

    /// With no key, `--from` lists each removed key that signed there,
    /// by six words worked out from the key, with its label and how much
    /// (decision 2026-10-04 §7.3); and says so where none signed.
    #[test]
    fn test_the_removed_keys_that_signed_are_listed_by_their_six_words() {
        let key = [7u8; 32];
        let found = json!({ "signed": [
            { "key": hex::encode(key), "words": "not these", "label": "desktop", "entries": 2 },
            { "key": hex::encode([8u8; 32]), "label": "", "entries": 1 },
            { "key": "no key", "label": "odd", "entries": 9 },
        ]});
        let lines = signed_lines(&found, "lab");
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines[0].starts_with("Removed keys that signed in lab"),
            "{lines:?}"
        );
        assert_eq!(
            lines[1],
            format!("  ({}) \"desktop\": 2 entries", carry::naming_words(&key))
        );
        assert_eq!(
            lines[2],
            format!(
                "  the device ({}): 1 entry",
                carry::naming_words(&[8u8; 32])
            )
        );
        let none = signed_lines(&json!({ "signed": [] }), "lab");
        assert_eq!(none.len(), 1);
        assert!(
            none[0].starts_with("No removed key signed anything"),
            "{none:?}"
        );
    }

    /// Versions are handed to the node a batch at a time, each within
    /// what one request carries, and one version at least; and what the
    /// node says of each batch is added up.
    #[test]
    fn test_versions_are_handed_in_batches_and_what_became_of_them_is_added_up() {
        let version = |name: &str, bytes: usize| Handed {
            name: name.into(),
            rev: 1,
            text: Some("x".repeat(bytes)),
            signer: String::new(),
            chain: None,
        };
        let all = vec![
            version("a", 40),
            version("b", 40),
            version("c", 200),
            version("d", 10),
        ];
        let sizes = |max: usize| -> Vec<usize> {
            batches(&all, max).iter().map(|batch| batch.len()).collect()
        };
        assert_eq!(sizes(1_000), [4]);
        assert_eq!(sizes(100), [2, 1, 1]);
        // A version over the bound goes alone.
        assert_eq!(sizes(10), [1, 1, 1, 1]);
        assert!(batches(&[], 100).is_empty());

        let mut total = json!({
            "carried": 1, "held": 0, "higher": 0, "ties": ["a.md"], "above": [],
            "deletes": 0, "by_other_keys": 2,
        });
        let done = json!({
            "carried": 2, "held": 1, "higher": 3, "ties": ["b.md"], "above": ["c.md"],
            "deletes": 1, "by_other_keys": 1,
        });
        add_to(&mut total, &done);
        assert_eq!(
            total,
            json!({
                "carried": 3, "held": 1, "higher": 3, "ties": ["a.md", "b.md"],
                "above": ["c.md"], "deletes": 1, "by_other_keys": 3,
            })
        );
    }

    /// What a carry with the phrase left is said too: what stands above
    /// a version that the new channel holds, and the deletes that were
    /// not taken.
    #[test]
    fn test_what_a_carry_with_the_phrase_left_is_said() {
        let done = json!({
            "name": "lab", "generations": [], "carried": 1, "higher": 0, "ties": [],
            "above": ["a.md", "b.md"], "deletes": 2, "by_other_keys": 0, "nothing": null,
        });
        let all = carried_lines(&done).join("\n");
        assert!(
            all.contains(
                "2 versions left: they stand above a version that the new channel holds, and \
                 come in only on a second yes, for a name that has a folder here: a.md, b.md."
            ),
            "{all}"
        );
        assert!(
            all.contains("2 deletes were not taken: a delete that a removed key signed never is."),
            "{all}"
        );
        let one = json!({
            "name": "lab", "generations": [], "carried": 0, "higher": 0, "ties": [],
            "above": ["a.md"], "deletes": 1, "by_other_keys": 0, "nothing": null,
        });
        let all = carried_lines(&one).join("\n");
        assert!(all.contains("1 version left: it stands above"), "{all}");
        assert!(all.contains("and comes in only on a second yes"), "{all}");
        assert!(all.contains("1 delete was not taken"), "{all}");
    }
}
