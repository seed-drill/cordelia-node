//! What the remaining devices of a removal say, read (decision 2026-10-22
//! bar 10): which have applied the change, which relays hold it, and
//! whether each holds every version the others carried. Pure functions of
//! the devices' answers, so that their tests start no process.

use std::collections::HashMap;

/// What one round of the remaining devices' answers says of change `N`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Round {
    /// The devices that have applied it.
    pub applied: Vec<usize>,
    /// The relays a device that has applied it says hold it.
    pub holding: Vec<String>,
    /// Every remaining device has applied it, has nothing waiting to be
    /// sent, and says of each other remaining device that it has applied
    /// it and sent what it held.
    pub settled: bool,
}

/// Read one round: `seen` is what each remaining device answered of its
/// person (`POST /api/v1/devices/list`), by device; `keys` each remaining
/// device's key; `remaining` the devices that should answer.
///
/// A relay's `holds_latest` is about the change the answering device
/// keeps: a device still on the change before says true of that one. So a
/// relay is taken to hold change `N` only on the word of a device that has
/// applied `N`.
pub fn read_round(
    change: u64,
    remaining: &[usize],
    seen: &[(usize, serde_json::Value)],
    keys: &HashMap<usize, String>,
) -> Round {
    let mut round = Round {
        settled: remaining.iter().all(|d| seen.iter().any(|(s, _)| s == d)),
        ..Round::default()
    };
    for (d, seen) in seen {
        let applied = seen["change"].as_u64() == Some(change);
        if applied {
            round.applied.push(*d);
            for relay in seen["relays"].as_array().into_iter().flatten() {
                if relay["holds_latest"] == true
                    && let Some(name) = relay["relay"].as_str()
                    && !round.holding.iter().any(|h| h == name)
                {
                    round.holding.push(name.to_string());
                }
            }
        }
        let nothing_to_send = seen["names"]["to_go"]
            .as_array()
            .is_some_and(|a| a.is_empty())
            && seen["waiting"]
                .as_array()
                .is_some_and(|w| w.iter().all(|r| r["waits"] == 0));
        // Each row of the list holds a device's key at its top.
        let others_sent = remaining.iter().filter(|o| *o != d).all(|o| {
            seen["devices"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|listed| {
                    listed["key"].as_str() == keys.get(o).map(String::as_str)
                        && listed["applied"].as_u64() == Some(change)
                        && listed["sent"] == true
                })
        });
        round.settled &= applied && nothing_to_send && others_sent;
    }
    round
}

/// What a device holds of one name: each key's current version, as its
/// revision and its content, and the keys of the devices whose entries
/// hold it, from the local API (`POST /api/v1/channels/entries`).
pub type Held = HashMap<(String, String), Version>;

/// A version as a device holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub rev: u64,
    /// The content, as the route shows it (`null` for a delete).
    pub content: String,
    pub authors: Vec<String>,
}

/// Read one answer of the local entries route for `name` into `held`.
pub fn read_entries(name: &str, answer: &serde_json::Value, held: &mut Held) {
    for entry in answer["entries"].as_array().into_iter().flatten() {
        let (Some(key), Some(rev)) = (entry["key"].as_str(), entry["rev"].as_u64()) else {
            continue;
        };
        let authors = entry["authors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str().map(str::to_string))
            .collect();
        let version = Version {
            rev,
            content: entry["content"].to_string(),
            authors,
        };
        held.insert((name.to_string(), key.to_string()), version);
    }
}

/// Whether device `d`, which holds `held`, holds every version each other
/// remaining device carried (bar 10b): for each version `carried[o]`
/// lists (what `o` held at the change's line, which it carries), `d` holds
/// that key at a later revision, or the same version: at the same
/// revision, with the same content.
///
/// It is the version that is held, whoever's entry holds it: a device
/// that held a version by its own entry was seen not to store another
/// device's carried entry of it, and holds it all the same.
pub fn holds_what_was_carried(d: usize, held: &Held, carried: &HashMap<usize, Held>) -> bool {
    carried.iter().filter(|(o, _)| **o != d).all(|(_, theirs)| {
        theirs.iter().all(|(slot, carried)| {
            held.get(slot).is_some_and(|held| {
                held.rev > carried.rev
                    || (held.rev == carried.rev && held.content == carried.content)
            })
        })
    })
}
