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

use std::time::Duration;

use serde_json::{Value, json};

use cordelia_core::protocol::{CARRY_FIRST_MAX_SECS, CARRY_READ_MAX_SECS};

use crate::api_post_within;
use crate::person_cmd::{counted, file_shown, list, look, text};

/// How long `cordelia sync map` waits for the node's answer: a device
/// that comes to sync a name carries it first, before the node answers.
pub(crate) const MAP_WAITS: Duration = Duration::from_secs(CARRY_FIRST_MAX_SECS + 30);

/// How long `cordelia sync carry` waits for the node's answer about one
/// name: the node reads for no longer than a carry may, and then waits
/// for the last page that it had asked for.
const CARRY_WAITS: Duration = Duration::from_secs(CARRY_READ_MAX_SECS + 90);

/// `cordelia sync carry [<name>]`: with a name, that name; with none,
/// every name that this device holds (decision 2026-10-04 §7.3).
pub(crate) fn carry(config_path: &str, name: Option<String>) -> anyhow::Result<()> {
    let names: Vec<String> = match name {
        // In its one spelling, as `map` sends a name that is typed.
        Some(name) => vec![cordelia_core::sync_name::tidy(&name)],
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
    // What could not be read, by generation and relay.
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
}
