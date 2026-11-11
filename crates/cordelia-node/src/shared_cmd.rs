//! The commands that make, share and take a shared channel (decision
//! 2026-10-10 §5.1 to §5.5): `cordelia shared new`, `shared list`, `shared
//! rename`, `shared drop`, `cordelia share`, `cordelia accept <key>
//! --channel <name>` and `cordelia label`; `cordelia subscribe` in a clone,
//! which follows its repository (decision 2026-11-06 (joining), rule 2);
//! and `cordelia id --words`.
//!
//! **Each yes is asked here, at a terminal,** and a command that asks one
//! refuses, before anything else, where its input is not one
//! ([`Terminal::at`]). What the yes is for is the node's text: the command
//! asks the node with `look`, shows what it answers, and hands that text
//! back with the yes; the node refuses where it would now do another thing.
//!
//! **A refusal of §5.5 is printed as the node words it,** on standard
//! error, and the command exits 1. A yes that is not given prints
//! [`NOT_A_YES`] on standard output, and the command exits 0.
//!
//! Each command that changes something refuses a node of another version
//! (decision 2026-10-04 §10.1, rule 6); `shared list` is answered beside
//! one, with the note.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use cordelia_core::protocol::{MEMBERS_LABELS_SHOWN, SHARED_MAX_KEYS};
use cordelia_crypto::bech32::decode_public_key;

use crate::person_cmd::{NOT_A_YES, list, own_key, text, time_of};
use crate::terminal::Terminal;
use crate::{Told, api_post_told, note_another_version, refuse_another_version};

/// How often the node is asked while `accept --channel` waits.
const ASK_EVERY: Duration = Duration::from_secs(1);

/// How long `cordelia accept --channel` stays and says what became of the
/// key (§3.3, as `cordelia accept` does): the node goes on asking for the
/// rest of the hour.
const ACCEPT_STAYS: Duration = Duration::from_secs(60);

/// How long a command waits for the node to answer.
const ANSWERED_WITHIN: Duration = Duration::from_secs(30);

/// Print `line` on standard error and exit 1: a refusal (§5.5).
fn refuse(line: &str) -> ! {
    eprintln!("{line}");
    std::process::exit(1)
}

/// Ask the node `path` with `body`: what it answers, or its refusal
/// printed as it words it, and the command ended.
fn asked(config_path: &str, path: &str, body: &Value) -> anyhow::Result<Value> {
    match api_post_told(config_path, path, body.clone(), Some(ANSWERED_WITHIN))? {
        Told::Yes(answer) => Ok(answer),
        Told::No { message, .. } => refuse(&message),
    }
}

/// A command that asks a yes (§5.2): the node is asked what the yes is
/// for, the person is asked it at `at`, and with a yes the node is asked to
/// do it, with the text the yes was for. `None` where no yes was given:
/// [`NOT_A_YES`] is printed.
fn with_a_yes(
    config_path: &str,
    at: &Terminal,
    path: &str,
    body: Value,
) -> anyhow::Result<Option<Value>> {
    let mut look = body.clone();
    look["look"] = true.into();
    let would = asked(config_path, path, &look)?;
    // A look that says something with no yes to ask: it is said, and
    // nothing more is done.
    let Some(asks) = would["asks"].as_str() else {
        print_said(&would);
        return Ok(None);
    };
    crate::person_cmd::names_this_device(&would, &own_key(config_path)?)?;
    if !at.yes(asks)? {
        println!("{NOT_A_YES}");
        return Ok(None);
    }
    let mut body = body;
    body["said_yes_to"] = asks.into();
    Ok(Some(asked(config_path, path, &body)?))
}

/// Print each line the node said.
fn print_said(answer: &Value) {
    for line in list(answer, "said").filter_map(Value::as_str) {
        println!("{}", crate::history_cmd::printable(line));
    }
}

// ── cordelia id --words ──────────────────────────────────────────────

/// `cordelia id --words` (§5.2): this device's key on its first line, and
/// the six words of its fingerprint on the second, with nothing else.
pub fn id_words(config_path: &str) -> anyhow::Result<()> {
    let own = own_key(config_path)?;
    println!("{}", cordelia_crypto::bech32::encode_public_key(&own)?);
    println!("{}", cordelia_api::sharing::six_words(&own));
    Ok(())
}

// ── cordelia shared new ──────────────────────────────────────────────

/// `cordelia shared new <name> [--relay <relay>]...` (§5.1, §5.2).
pub fn new(config_path: &str, name: &str, relays: &[String]) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let body = json!({ "name": name, "relays": relays });
    if let Some(made) = with_a_yes(config_path, &at, "/api/v1/shared/new", body)? {
        print_said(&made);
    }
    Ok(())
}

// ── cordelia share ───────────────────────────────────────────────────

/// `cordelia share <name> <key> [--words <four words>]` (§3.1, §5.2).
pub fn share(config_path: &str, name: &str, key: &str, words: Option<&str>) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let body = json!({ "name": name, "key": key, "words": words });
    if let Some(handed) = with_a_yes(config_path, &at, "/api/v1/shared/share", body)? {
        print_said(&handed);
    }
    Ok(())
}

// ── cordelia accept <key> --channel <name> ───────────────────────────

/// `cordelia accept <key> --channel <name>` (§3.2, §5.2): it shares no path
/// with `cordelia accept <key>`, and never reads a pair channel, takes a
/// hand-over or moves the device. The key is kept an hour with the name;
/// the command stays a minute and says what became of it.
pub fn accept(config_path: &str, key: &str, name: &str) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let body = json!({ "key": key, "name": name });
    let Some(typed) = with_a_yes(config_path, &at, "/api/v1/shared/accept", body)? else {
        return Ok(());
    };
    let until = typed["until"].as_i64().unwrap_or(0);
    let until = time_of(u64::try_from(until).unwrap_or(0));
    println!("\n{}", asking_line(text(&typed, "words"), &until));
    let typed_key = decode_public_key(key.trim()).ok();
    let typed_at = typed["typed_at"].as_i64();
    let ends = Instant::now() + ACCEPT_STAYS;
    loop {
        std::thread::sleep(ASK_EVERY);
        let listed = asked(config_path, "/api/v1/shared/list", &json!({}))?;
        let of_the_key = list(&listed, "typed").find(|row| {
            decode_public_key(text(row, "key")).ok() == typed_key
                && row["typed_at"].as_i64() == typed_at
        });
        let Some(of_the_key) = of_the_key else {
            anyhow::bail!(
                "the node keeps that key no longer: type it again (cordelia accept --channel)"
            );
        };
        if let Some(words) = of_the_key["taken"].as_str() {
            let channel = list(&listed, "channels").find(|channel| text(channel, "words") == words);
            let Some(channel) = channel else {
                println!("{}", taken_line(None, words, &[]));
                return Ok(());
            };
            let relays: Vec<&str> = list(channel, "relays")
                .map(|relay| text(relay, "shown"))
                .collect();
            let name = crate::history_cmd::printable(text(channel, "name"));
            println!("{}", taken_line(Some(&name), words, &relays));
            for line in list(channel, "wrote").filter_map(Value::as_str) {
                println!("{}", crate::history_cmd::printable(line));
            }
            return Ok(());
        }
        if let Some(says) = of_the_key["says"].as_str() {
            refuse(&crate::history_cmd::printable(says));
        }
        if Instant::now() >= ends {
            println!("{}", nothing_taken_line(&until));
            return Ok(());
        }
    }
}

/// What `accept --channel` says once it has its yes (§5.2): `words` are
/// the six of the typed key, `until` when it stops asking.
fn asking_line(words: &str, until: &str) -> String {
    format!("Asking your relays for what ({words}) hands over, until {until}.")
}

/// What `accept --channel` says of a share it took (§5.2): the name it is
/// filed under, its words and its relays, where the node lists it.
fn taken_line(name: Option<&str>, words: &str, relays: &[&str]) -> String {
    match name {
        Some(name) => format!(
            "Taken: \"{name}\" is channel {words}, at {}. The channel's words are its name, and \
             prove nothing.",
            relays.join(" and ")
        ),
        None => {
            format!("Taken: channel {words}. The channel's words are its name, and prove nothing.")
        }
    }
}

/// What `accept --channel` says where nothing was taken within its wait
/// (§5.5): on standard output, and it exits 0.
fn nothing_taken_line(until: &str) -> String {
    format!(
        "Nothing was taken yet. This device goes on asking until {until}: cordelia shared list \
         says what became of it."
    )
}

// ── cordelia label ───────────────────────────────────────────────────

/// `cordelia label <key> <label>`, or `--none` (§3.4, §5.2).
pub fn label(config_path: &str, key: &str, label: Option<&str>) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let body = json!({ "key": key, "label": label });
    if let Some(done) = with_a_yes(config_path, &at, "/api/v1/shared/label", body)? {
        print_said(&done);
    }
    Ok(())
}

// ── cordelia subscribe and unsubscribe ───────────────────────────────

/// `cordelia subscribe <name> [--words <four words>]` (§4.1, §5.2): the
/// agent of the folder it runs in, at a terminal, with a yes. No other
/// command subscribes.
pub fn subscribe(config_path: &str, name: &str, words: Option<&str>) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let (folder, _) = crate::msg_cmd::folder_of(config_path)?;
    let body = json!({ "folder": folder, "name": name, "words": words });
    if let Some(done) = with_a_yes(config_path, &at, "/api/v1/shared/subscribe", body)? {
        print_said(&done);
    }
    Ok(())
}

/// `cordelia subscribe [--new] [--remote <remote>]` with no name (decision
/// 2026-11-06 (joining), rules 2.3 and 2.4): this device follows the
/// repository of the folder it runs in, at a terminal, with a yes. The
/// node reads the clone; with `--new` it makes the repository's channel,
/// and says the lines to add to the list.
pub fn follow(config_path: &str, new: bool, remote: Option<&str>) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let (folder, _) = crate::msg_cmd::folder_of(config_path)?;
    let body = json!({ "folder": folder, "remote": remote, "new": new });
    if let Some(done) = with_a_yes(config_path, &at, "/api/v1/shared/follow", body)? {
        print_said(&done);
    }
    Ok(())
}

/// `cordelia unsubscribe <name> [--agent <agent>] [--words <four words>]`
/// (§4.1, §5.2): no yes; in the folder, or for the agent named from
/// anywhere.
pub fn unsubscribe(
    config_path: &str,
    name: &str,
    agent: Option<&str>,
    words: Option<&str>,
) -> anyhow::Result<()> {
    refuse_another_version(config_path)?;
    let folder = match agent {
        Some(_) => None,
        None => Some(crate::msg_cmd::folder_of(config_path)?.0),
    };
    let body = json!({ "folder": folder, "agent": agent, "name": name, "words": words });
    print_said(&asked(config_path, "/api/v1/shared/unsubscribe", &body)?);
    Ok(())
}

/// `cordelia unsubscribe` with no name, in a clone (decision 2026-11-06
/// (joining), rule 2.5): no yes; this device follows the clone's
/// repository no more.
pub fn unfollow(config_path: &str) -> anyhow::Result<()> {
    refuse_another_version(config_path)?;
    let (folder, _) = crate::msg_cmd::folder_of(config_path)?;
    let body = json!({ "folder": folder });
    print_said(&asked(config_path, "/api/v1/shared/unfollow", &body)?);
    Ok(())
}

// ── cordelia shared anew, move and stay ──────────────────────────────

/// What `shared anew` asks of each key (decision 2026-10-10 §7).
fn stays_asked(form: &str) -> String {
    format!("Does {form} stay? Type keep or out, or out for the rest: ")
}

/// What `shared anew` says to an answer it does not take (§5.5).
pub const KEEP_OR_OUT: &str = "Type keep or out, or out for the rest.";

/// The answers of `shared anew` to each key it asks about, in order (§7):
/// `keep` or `out` typed for each, and `out for the rest` once, for that
/// key and every key not yet answered. **None is suggested:** anything else
/// is asked again, and a `keep` past 64 staying is asked again. Returns the
/// keys answered `keep`.
pub(crate) fn answers(
    asked: &[(String, String)],
    own_devices: usize,
    mut answer: impl FnMut(&str) -> anyhow::Result<Option<String>>,
) -> anyhow::Result<Vec<String>> {
    let mut keep = Vec::new();
    'keys: for (key, form) in asked {
        loop {
            let typed = answer(&stays_asked(form))?;
            match typed.as_deref() {
                Some("keep") if own_devices + keep.len() >= SHARED_MAX_KEYS => {
                    println!("{}", cordelia_api::shared_anew::STAY_PAST_64);
                }
                Some("keep") => {
                    keep.push(key.clone());
                    continue 'keys;
                }
                Some("out") => continue 'keys,
                Some("out for the rest") => break 'keys,
                Some(_) => println!("{KEEP_OR_OUT}"),
                None => anyhow::bail!(
                    "the input ended before every key was answered. Nothing was made."
                ),
            }
        }
    }
    Ok(keep)
}

/// `cordelia shared anew <name> [--relay <relay>]... [--words]` (§5.1, §7):
/// every key is listed before anything is asked; each is answered; then the
/// yes, naming how many stay and how many are left out.
pub fn anew(
    config_path: &str,
    name: &str,
    relays: &[String],
    words: Option<&str>,
) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let path = "/api/v1/shared/anew";
    let body = json!({ "name": name, "relays": relays, "words": words });
    let listed = asked(config_path, path, &body)?;
    crate::person_cmd::names_this_device(&listed, &own_key(config_path)?)?;
    for line in list(&listed, "listing").filter_map(Value::as_str) {
        println!("{}", crate::history_cmd::printable(line));
    }
    let ask: Vec<(String, String)> = list(&listed, "ask")
        .map(|key| {
            (
                text(key, "key").to_string(),
                crate::history_cmd::printable(text(key, "form")),
            )
        })
        .collect();
    let own_devices = listed["own_devices"].as_u64().unwrap_or(0) as usize;
    let keep = answers(&ask, own_devices, |asks| at.answer(asks))?;
    let mut body = body;
    body["keep"] = json!(keep);
    body["asked"] = json!(ask.iter().map(|(key, _)| key).collect::<Vec<_>>());
    if let Some(made) = with_a_yes(config_path, &at, path, body)? {
        print_said(&made);
    }
    Ok(())
}

/// `cordelia shared move <name> [--to <channel words>] [--words]` (§5.1,
/// §7).
pub fn move_to(
    config_path: &str,
    name: &str,
    to: Option<&str>,
    words: Option<&str>,
) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let body = json!({ "name": name, "to": to, "words": words });
    if let Some(moved) = with_a_yes(config_path, &at, "/api/v1/shared/move", body)? {
        print_said(&moved);
    }
    Ok(())
}

/// `cordelia shared stay <name> [--words]` (§5.1; decision 2026-10-24,
/// rule 26).
pub fn stay(config_path: &str, name: &str, words: Option<&str>) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let body = json!({ "name": name, "words": words });
    if let Some(stayed) = with_a_yes(config_path, &at, "/api/v1/shared/stay", body)? {
        print_said(&stayed);
    }
    Ok(())
}

// ── cordelia shared rename, drop and list ────────────────────────────

/// `cordelia shared rename <name> <new name> [--words <four words>]`
/// (§3.4): no yes.
pub fn rename(config_path: &str, name: &str, new: &str, words: Option<&str>) -> anyhow::Result<()> {
    refuse_another_version(config_path)?;
    let body = json!({ "name": name, "new_name": new, "words": words });
    print_said(&asked(config_path, "/api/v1/shared/rename", &body)?);
    Ok(())
}

/// `cordelia shared drop <name> [--words <four words>]` (§3.4, §5.2).
pub fn drop(config_path: &str, name: &str, words: Option<&str>) -> anyhow::Result<()> {
    let at = Terminal::at()?;
    refuse_another_version(config_path)?;
    let body = json!({ "name": name, "words": words });
    if let Some(dropped) = with_a_yes(config_path, &at, "/api/v1/shared/drop", body)? {
        print_said(&dropped);
    }
    Ok(())
}

/// `cordelia shared list [--keys]` (§5.1): the shared channels, their keys
/// (those refused for room among them, with `--keys`) and relays; the keys
/// typed for a channel and what became of each; the shares waiting.
pub fn show(config_path: &str, keys: bool, verbose: bool) -> anyhow::Result<()> {
    note_another_version(config_path);
    let listed = asked(config_path, "/api/v1/shared/list", &json!({ "keys": keys }))?;
    let mut lines = list_lines(&listed);
    let repositories: Vec<&Value> = list(&listed, "repositories").collect();
    if !repositories.is_empty() {
        lines.push("Repositories this device follows:".into());
    }
    for repository in repositories {
        lines.extend(
            repository_lines(repository, verbose, true)
                .into_iter()
                .map(|line| format!("  {line}")),
        );
    }
    for line in lines {
        println!("{}", crate::history_cmd::printable(&line));
    }
    Ok(())
}

/// The lines of one repository this device follows (decision 2026-11-06
/// (joining), rule 7), as the node gave it: first the repository and the
/// name its channel is filed under; then, each indented, when and from
/// where its list was read, the members by the list's labels, each in or
/// not yet where this device can see it, what waits unread, and each line
/// of rules 4 to 6, an amber one after the line's amber mark, with any
/// channel line it says to put in the list under it. The members, and the
/// keys new on the list (rule 4.5), are each said with `every`, and else
/// the first [`MEMBERS_LABELS_SHOWN`] and how many more. The fingerprint
/// words show only with `verbose` (#228).
pub fn repository_lines(repository: &Value, verbose: bool, every: bool) -> Vec<String> {
    let mut head = format!(
        "{}, for {}",
        text(repository, "identity"),
        text(repository, "name")
    );
    if verbose && let Some(words) = repository["words"].as_str() {
        head.push_str(&format!(" (channel {words})"));
    }
    let mut lines = vec![head];
    match repository["read"]["says"].as_str() {
        Some(says) => lines.push(format!("  {says}")),
        None => lines.push("  The list has not been read yet.".into()),
    }
    let all: Vec<&Value> = list(repository, "members").collect();
    let shown = match every {
        true => all.len(),
        false => all.len().min(MEMBERS_LABELS_SHOWN),
    };
    let mut members: Vec<String> = all[..shown]
        .iter()
        .map(|member| {
            let mut shown = text(member, "label").to_string();
            match member["in"].as_bool() {
                Some(true) => shown.push_str(" (in)"),
                Some(false) => shown.push_str(" (not yet)"),
                None => {}
            }
            if verbose {
                shown.push_str(&format!(" [{}]", text(member, "words")));
            }
            shown
        })
        .collect();
    if all.len() > shown {
        members.push(format!("and {} more", all.len() - shown));
    }
    if !members.is_empty() {
        lines.push(format!("  Members: {}.", members.join(", ")));
    }
    if repository["held"] == true {
        lines.push(format!(
            "  Unread: {} by you, {} by an agent.",
            repository["unread_by_a_person"].as_u64().unwrap_or(0),
            repository["unread_by_an_agent"].as_u64().unwrap_or(0)
        ));
    }
    for line in list(repository, "lines") {
        let labels: Vec<&str> = list(line, "devices")
            .map(|device| text(device, "label"))
            .collect();
        let says = match (every, line["commit"].as_str()) {
            (true, Some(commit)) if line["word"] == "joined" => {
                let name = text(repository, "name");
                cordelia_api::repository_status::joined_line(name, commit, &labels, labels.len())
            }
            _ => text(line, "says").to_string(),
        };
        lines.push(match line["amber"] == true {
            true => format!("  {} {says}", crate::indicator::AMBER_MARK),
            false => format!("  {says}"),
        });
        if let Some(put) = line["line"].as_str() {
            lines.push(format!("    {put}"));
        }
    }
    lines
}

/// What `cordelia shared seen` says where its input is not a terminal.
pub const SEEN_AT_A_TERMINAL: &str = "Run cordelia shared seen in a terminal: you clear these \
                                      notices, not an agent. Nothing was cleared.";

/// `cordelia shared seen <name> [<label>]` (decision 2026-11-06 (joining),
/// rules 4.5, 5 and 6): at a terminal, and with no yes, it clears on this
/// device the keys new on the list and the changed line of the repository
/// whose channel is `name`, or with `label` rule 5's notice of that key
/// alone. A person clears them, so it refuses where its input is not a
/// terminal, as an agent's is not.
pub fn seen(config_path: &str, name: &str, label: Option<&str>) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(SEEN_AT_A_TERMINAL);
    }
    refuse_another_version(config_path)?;
    let body = json!({ "name": name, "label": label });
    print_said(&asked(config_path, "/api/v1/shared/seen", &body)?);
    Ok(())
}

/// The lines of `shared list`, from what the node answered.
pub fn list_lines(listed: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let channels: Vec<&Value> = list(listed, "channels").collect();
    match channels.len() {
        0 => lines.push("No shared channel is held on your devices.".to_string()),
        n => lines.push(format!(
            "Shared channels: {n} of 16. Each lives at the relays named, known by their keys."
        )),
    }
    for channel in channels {
        let relays: Vec<&str> = list(channel, "relays")
            .map(|relay| text(relay, "shown"))
            .collect();
        let mut line = format!(
            "  \"{}\": channel {}, {} wrote there, {} labelled by you; at {}",
            text(channel, "name"),
            text(channel, "words"),
            cordelia_api::sharing::counted(channel["keys"].as_u64().unwrap_or(0), "key"),
            channel["labelled"].as_u64().unwrap_or(0),
            relays.join(" and "),
        );
        if channel["reached"] != true {
            line.push_str("; held, not reached from this device");
        }
        if channel["also_a_name"] == true {
            line.push_str("; also a name you sync");
        }
        lines.push(line);
        if let Some(from) = channel["came"]["taken_from"].as_str() {
            lines.push(format!("    taken from {from}"));
        }
        for key in list(channel, "table") {
            if let Some(first) = key["first_held"].as_str() {
                lines.push(format!(
                    "    {}: first held on this device on {first}",
                    text(key, "form")
                ));
            }
            if let Some(first) = key["first_refused"].as_str() {
                lines.push(format!(
                    "    refused for room: {}, first refused on this device on {first}, {} bytes, \
                     key {}",
                    text(key, "form"),
                    key["bytes_refused"].as_u64().unwrap_or(0),
                    text(key, "key")
                ));
            }
        }
        let let_go = channel["rows_let_go"].as_u64().unwrap_or(0);
        if let_go > 0 {
            // An upper bound: a key whose row went and that wrote again
            // since is in the table and counted here too (§6.3).
            lines.push(format!(
                "    no longer known on this device: up to {}",
                cordelia_api::sharing::counted(let_go, "key")
            ));
        }
    }
    for name in list(listed, "past_a_bound").filter_map(Value::as_str) {
        lines.push(format!("  \"{name}\": past a bound, and not held"));
    }
    let typed: Vec<&Value> = list(listed, "typed").collect();
    if !typed.is_empty() {
        lines.push("Keys typed for a shared channel:".into());
    }
    for row in typed {
        let until = time_of(row["until"].as_u64().unwrap_or(0));
        let became = match (row["taken"].as_str(), row["says"].as_str()) {
            (Some(words), _) => format!("taken: channel {words}"),
            (None, Some(says)) => format!("nothing taken: {says}"),
            (None, None) if row["asking"] == true => format!("asking until {until}"),
            (None, None) => "nothing was taken within its hour".into(),
        };
        lines.push(format!(
            "  {} for \"{}\": {became}",
            text(row, "form"),
            text(row, "name")
        ));
    }
    let shares: Vec<&Value> = list(listed, "shares").collect();
    if !shares.is_empty() {
        lines.push("Shares this device made:".into());
    }
    for share in shares {
        let until = time_of(share["until"].as_u64().unwrap_or(0));
        let state = match (share["taken"] == true, share["waiting"] == true) {
            (true, _) => "taken".to_string(),
            (false, true) => format!("waiting until {until}"),
            (false, false) => "the key took nothing".into(),
        };
        let name = match share["channel"].as_str() {
            Some(name) => format!("\"{name}\""),
            None => format!("channel {}", text(share, "words")),
        };
        lines.push(format!("  {name} to {}: {state}", text(share, "form")));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Commands, SharedCommand};
    use clap::{CommandFactory, Parser};

    /// The record, as it is in the repository.
    const RECORD: &str =
        include_str!("../../../docs/decisions/2026-10-10-a-shared-channel-for-messages.md");

    /// `template` as the record writes it, each placeholder in angle
    /// brackets filled by `values` in turn; the record must say it.
    fn says(template: &str, values: &[&str]) -> String {
        assert!(
            RECORD.contains(template),
            "the record does not say: {template}"
        );
        let mut out = String::new();
        let mut rest = template;
        let mut values = values.iter();
        while let (Some(at), Some(end)) = (rest.find('<'), rest.find('>')) {
            out.push_str(&rest[..at]);
            out.push_str(values.next().expect("a value for each placeholder"));
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        assert!(values.next().is_none(), "a value too many for {template}");
        out
    }

    /// The command's own lines of §5.2 to §5.5, byte for byte (decision
    /// 2026-10-10 §13, "The commands' words"), beside the node's, which
    /// `cordelia-api/src/sharing/words.rs` tests; and the changed help of
    /// `cordelia channels`.
    #[test]
    fn the_shared_commands_say_what_this_record_says_at_the_command() {
        let six = "able bake cold dune east fair";
        let four = "gold hill iron jade";
        let relay = "relay.example.org:9474 (kind lamp mint nest)";
        assert_eq!(
            asking_line(six, "14:00"),
            says(
                "Asking your relays for what (<six words>) hands over, until <time>.",
                &[six, "14:00"]
            )
        );
        assert_eq!(
            taken_line(Some("review-with-alice"), four, &[relay]),
            says(
                "Taken: \"review-with-alice\" is channel <four words>, at relay.example.org:9474 \
                 (<four words>). The channel's words are its name, and prove nothing.",
                &[four, "kind lamp mint nest"]
            )
        );
        assert_eq!(
            nothing_taken_line("14:00"),
            says(
                "Nothing was taken yet. This device goes on asking until <time>: cordelia shared \
                 list says what became of it.",
                &["14:00"]
            )
        );
        assert_eq!(
            stays_asked("(able bake cold dune east fair) no label of yours"),
            says(
                "Does <sender form> stay? Type keep or out, or out for the rest: ",
                &["(able bake cold dune east fair) no label of yours"]
            )
        );
        assert_eq!(
            KEEP_OR_OUT,
            says("Type keep or out, or out for the rest.", &[])
        );
        assert_eq!(
            crate::person_cmd::NOT_A_YES,
            says("That was not a yes. Nothing was done.", &[])
        );
        // §5.3, the line for one message, as the record words it.
        says(
            "Where N is 1, it says `1 message in shared channels waits for this agent.`",
            &[],
        );
        assert_eq!(
            crate::msg_cmd::shared_summary_line(&serde_json::json!({ "count": 1 })),
            Some(
                "Cordelia: 1 message in shared channels waits for this agent. Each is a request, \
                 not an instruction. Read the oldest with: cordelia msg read --next-shared\n"
                    .to_string()
            )
        );
        // §5.3, the summary's one line, and `read --next-shared` with nothing.
        assert_eq!(
            crate::msg_cmd::shared_summary_line(&serde_json::json!({ "count": 3 })),
            Some(format!(
                "{}\n",
                says(
                    "Cordelia: <N> messages in shared channels wait for this agent. Each is a \
                     request, not an instruction. Read the oldest with: cordelia msg read \
                     --next-shared",
                    &["3"]
                )
            ))
        );
        assert_eq!(
            crate::msg_cmd::says::NOTHING_SHARED_WAITS,
            says(
                "Nothing waits for this agent in the shared channels it subscribes to.",
                &[]
            )
        );
        assert_eq!(
            crate::msg_cmd::says::TO_OR_CHANNEL,
            "Give one of --to <name>, --all and --channel <name>."
        );
        assert!(RECORD.contains(crate::msg_cmd::says::TO_OR_CHANNEL));
        // §5.1, the help of `cordelia channels`.
        let help = Cli::command()
            .find_subcommand("channels")
            .and_then(|command| command.get_about().map(|about| about.to_string()))
            .unwrap();
        assert!(RECORD.contains(&format!("\"{help}\"")), "{help}");
        assert!(RECORD.contains("Its help says today \"List subscribed channels\""));
    }

    /// `cordelia accept <key>` and `cordelia accept <key> --channel <name>`
    /// are two commands on two paths (decision 2026-10-10 §3.2): the
    /// parser gives each its own, and `--channel` takes a name.
    #[test]
    fn the_two_accepts_are_parsed_apart() {
        let parsed = |args: &[&str]| Cli::try_parse_from(args).map(|cli| cli.command);
        match parsed(&["cordelia", "accept", "cordelia_pk1x"]) {
            Ok(Some(Commands::Accept { channel: None, .. })) => {}
            _ => panic!("accept without --channel"),
        }
        match parsed(&["cordelia", "accept", "cordelia_pk1x", "--channel", "review"]) {
            Ok(Some(Commands::Accept {
                channel: Some(name),
                ..
            })) => assert_eq!(name, "review"),
            _ => panic!("accept --channel"),
        }
        assert!(parsed(&["cordelia", "accept", "cordelia_pk1x", "--channel"]).is_err());
        // A label, or --none, and not both.
        assert!(parsed(&["cordelia", "label", "cordelia_pk1x"]).is_err());
        assert!(parsed(&["cordelia", "label", "cordelia_pk1x", "bob", "--none"]).is_err());
        assert!(parsed(&["cordelia", "label", "cordelia_pk1x", "--none"]).is_ok());
        match parsed(&[
            "cordelia", "shared", "new", "review", "--relay", "a:1", "--relay", "b:2",
        ]) {
            Ok(Some(Commands::Shared {
                what: SharedCommand::New { relays, .. },
            })) => assert_eq!(relays, ["a:1", "b:2"]),
            _ => panic!("shared new"),
        }
        match parsed(&["cordelia", "id", "--words"]) {
            Ok(Some(Commands::Id { words: true })) => {}
            _ => panic!("id --words"),
        }
    }

    /// `cordelia subscribe` takes a name, as before, or none, which follows
    /// the repository it is run in (decision 2026-11-06 (joining), rule 2):
    /// `--new` and `--remote` go only with no name, and `--words` only with
    /// one.
    #[test]
    fn subscribe_with_a_name_or_none_is_parsed_apart() {
        let parsed = |args: &[&str]| Cli::try_parse_from(args).map(|cli| cli.command);
        match parsed(&["cordelia", "subscribe", "review", "--words", "a b c d"]) {
            Ok(Some(Commands::Subscribe {
                name: Some(name),
                words: Some(words),
                new: false,
                remote: None,
            })) => assert_eq!((name.as_str(), words.as_str()), ("review", "a b c d")),
            _ => panic!("subscribe <name>"),
        }
        match parsed(&["cordelia", "subscribe"]) {
            Ok(Some(Commands::Subscribe {
                name: None,
                words: None,
                new: false,
                remote: None,
            })) => {}
            _ => panic!("subscribe"),
        }
        match parsed(&["cordelia", "subscribe", "--new", "--remote", "upstream"]) {
            Ok(Some(Commands::Subscribe {
                name: None,
                new: true,
                remote: Some(remote),
                ..
            })) => assert_eq!(remote, "upstream"),
            _ => panic!("subscribe --new --remote"),
        }
        for refused in [
            &["cordelia", "subscribe", "review", "--new"][..],
            &["cordelia", "subscribe", "review", "--remote", "upstream"],
            &["cordelia", "subscribe", "--words", "a b c d"],
            &["cordelia", "subscribe", "--new", "--words", "a b c d"],
            &[
                "cordelia",
                "subscribe",
                "--remote",
                "upstream",
                "--words",
                "a b c d",
            ],
        ] {
            assert!(parsed(refused).is_err(), "{refused:?}");
        }
    }

    /// `shared anew` asks of each key in turn and suggests nothing
    /// (decision 2026-10-10 §7, property 7): an empty line and `yes` are
    /// asked again; `out for the rest`, typed at the first question, leaves
    /// out every key not yet answered; a `keep` past 64 staying is asked
    /// again.
    #[test]
    fn each_key_is_answered_and_out_for_the_rest_leaves_out_the_rest() {
        let asked: Vec<(String, String)> = (0..100)
            .map(|k| (format!("key{k}"), format!("form{k}")))
            .collect();
        let script = |typed: Vec<&'static str>| {
            let mut typed = typed.into_iter();
            let mut questions = Vec::new();
            let keep = answers(&asked, 2, |asks| {
                questions.push(asks.to_string());
                Ok(typed.next().map(str::to_string))
            })
            .unwrap();
            (keep, questions)
        };
        let (keep, questions) = script(vec!["", "yes", "keep", "out", "out for the rest"]);
        assert_eq!(keep, ["key0"]);
        assert_eq!(
            questions[0],
            "Does form0 stay? Type keep or out, or out for the rest: "
        );
        // Asked of form0 three times, then form1, then form2.
        assert_eq!(questions.len(), 5);
        assert!(questions[2].starts_with("Does form0 stay?"));
        assert!(questions[3].starts_with("Does form1 stay?"));
        assert!(questions[4].starts_with("Does form2 stay?"));
        let (keep, _) = script(vec!["out for the rest"]);
        assert!(keep.is_empty());
        // 62 kept beside 2 of the person's own: a 63rd keep is asked again.
        let mut typed = vec!["keep"; 63];
        typed.push("out for the rest");
        let (keep, questions) = script(typed);
        assert_eq!(keep.len(), 62);
        assert!(questions[62].starts_with("Does form62 stay?"));
        assert!(questions[63].starts_with("Does form62 stay?"));
        // The input ends: nothing is made.
        let mut none = answers(&asked, 2, |_| Ok(None));
        assert!(none.as_mut().is_err());
    }

    /// `cordelia channels` is said for what it does now (decision
    /// 2026-10-10 §5.1): "List subscribed channels" no more.
    #[test]
    fn the_help_of_channels_says_what_it_lists() {
        let help = Cli::command()
            .find_subcommand("channels")
            .and_then(|command| command.get_about().map(|about| about.to_string()))
            .unwrap();
        assert_eq!(
            help,
            "List the names this device holds, or a relay's channels"
        );
    }

    /// `shared list` says each channel by its words and relays, whether it
    /// is reached, and what became of each key typed and each share.
    #[test]
    fn the_lines_of_shared_list() {
        let listed = json!({
            "channels": [{
                "name": "review", "words": "a b c d", "keys": 1, "labelled": 0,
                "reached": false, "also_a_name": true, "rows_let_go": 0,
                "relays": [{ "shown": "relay.example.org:9474 (e f g h)" }],
                "came": { "taken_from": "(one two three four five six) no label of yours" },
            }],
            "typed": [{ "form": "(x) no label of yours", "name": "design", "until": 0,
                        "asking": false, "taken": null, "says": "Your devices hold it." }],
            "shares": [{ "form": "(y) \"bob\"", "channel": "review", "until": 0,
                         "waiting": true, "taken": false }],
            "past_a_bound": [],
        });
        let lines = list_lines(&listed);
        assert_eq!(
            lines[0],
            "Shared channels: 1 of 16. Each lives at the relays named, known by their keys."
        );
        assert_eq!(
            lines[1],
            "  \"review\": channel a b c d, 1 key wrote there, 0 labelled by you; at \
             relay.example.org:9474 (e f g h); held, not reached from this device; also a name \
             you sync"
        );
        assert!(
            lines.contains(
                &"  (x) no label of yours for \"design\": nothing taken: Your devices hold it."
                    .to_string()
            )
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("  \"review\" to (y) \"bob\": waiting until"))
        );
        assert_eq!(
            list_lines(&json!({}))[0],
            "No shared channel is held on your devices."
        );
        // The rows let go, said with the noun of a count of one, as an
        // upper bound (decision 2026-10-10 §7).
        let mut one_let_go = listed.clone();
        one_let_go["channels"][0]["rows_let_go"] = json!(1);
        assert!(
            list_lines(&one_let_go)
                .contains(&"    no longer known on this device: up to 1 key".to_string())
        );
    }

    /// Each repository this device follows is said with its read, its
    /// members by the list's labels, what waits unread and its lines, an
    /// amber one after "To know:" with the channel line it says to put
    /// under it (decision 2026-11-06 (joining), rule 7). The fingerprint
    /// words show only with `-v` (#228). A joiner, which cannot see who is
    /// in the channel, says each member by its label alone, and nothing of
    /// what waits unread.
    #[test]
    fn the_lines_of_a_repository_followed() {
        let repository = json!({
            "identity": "example.org/team/project", "name": "team/project", "held": true,
            "words": "a b c d",
            "read": { "says": "List of example.org/team/project read from your clone, fetched \
                               2 hours ago. Read 5 minutes ago, at commit aaaa." },
            "members": [
                { "label": "alice-laptop", "words": "one two three four five six", "in": true },
                { "label": "bob-desktop", "words": "six five four three two one", "in": false },
            ],
            "unread_by_a_person": 2, "unread_by_an_agent": 1,
            "lines": [
                { "word": "handing", "says": "Handing team/project to bob-desktop: waiting for \
                                              that device to take it.", "amber": false },
                { "word": "put_the_line", "says": "team/project was made anew here: put its new \
                                                   channel line in .cordelia/members, in a pull \
                                                   request",
                  "amber": true, "line": "channel 00 cordelia_pk1x without 0" },
            ],
        });
        let lines = repository_lines(&repository, false, false);
        assert_eq!(
            lines,
            [
                "example.org/team/project, for team/project",
                "  List of example.org/team/project read from your clone, fetched 2 hours ago. \
                 Read 5 minutes ago, at commit aaaa.",
                "  Members: alice-laptop (in), bob-desktop (not yet).",
                "  Unread: 2 by you, 1 by an agent.",
                "  Handing team/project to bob-desktop: waiting for that device to take it.",
                "  ◆ team/project was made anew here: put its new channel line in \
                 .cordelia/members, in a pull request",
                "    channel 00 cordelia_pk1x without 0",
            ]
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("a b c d") || line.contains("one two"))
        );
        let verbose = repository_lines(&repository, true, false);
        assert_eq!(
            verbose[0],
            "example.org/team/project, for team/project (channel a b c d)"
        );
        assert_eq!(
            verbose[2],
            "  Members: alice-laptop (in) [one two three four five six], bob-desktop (not yet) \
             [six five four three two one]."
        );
        let mut joiner = repository.clone();
        joiner["held"] = json!(false);
        joiner["read"] = json!(null);
        for member in joiner["members"].as_array_mut().unwrap() {
            member["in"] = json!(null);
        }
        let lines = repository_lines(&joiner, false, false);
        assert_eq!(lines[1], "  The list has not been read yet.");
        assert_eq!(lines[2], "  Members: alice-laptop, bob-desktop.");
        assert!(!lines.iter().any(|line| line.starts_with("  Unread")));
        // The plain status shows the first few labels and how many more;
        // `shared list` shows each.
        let mut many = joiner.clone();
        many["members"] = (1..=9)
            .map(|n| json!({ "label": format!("m{n}"), "in": null }))
            .collect();
        assert_eq!(
            repository_lines(&many, false, false)[2],
            "  Members: m1, m2, m3, m4, m5, m6, and 3 more."
        );
        assert_eq!(
            repository_lines(&many, false, true)[2],
            "  Members: m1, m2, m3, m4, m5, m6, m7, m8, m9."
        );
        // The keys new on the list at a commit (rule 4.5): the status says
        // the line the node gave, and `shared list` names every key.
        let commit = "c".repeat(40);
        let labels: Vec<String> = (1..=8).map(|n| format!("m{n}")).collect();
        let said = cordelia_api::repository_status::joined_line(
            "team/project",
            &commit,
            &labels.iter().map(String::as_str).collect::<Vec<_>>(),
            MEMBERS_LABELS_SHOWN,
        );
        many["lines"] = json!([{
            "word": "joined", "says": said, "amber": true, "line": null, "commit": commit,
            "devices": labels.iter().map(|label| json!({ "label": label })).collect::<Vec<_>>(),
        }]);
        assert_eq!(
            repository_lines(&many, false, false)[3],
            "  ◆ New on the list of team/project at cccccccccccc: m1, m2, m3, m4, m5, m6 and 2 \
             more"
        );
        assert_eq!(
            repository_lines(&many, false, true)[3],
            "  ◆ New on the list of team/project at cccccccccccc: m1, m2, m3, m4, m5, m6, m7 and \
             m8"
        );
    }

    /// `cordelia unsubscribe` takes a name, as before, or none, in a clone,
    /// to stop following its repository (decision 2026-11-06 (joining),
    /// rule 2.5): `--agent` and `--words` go only with a name.
    #[test]
    fn unsubscribe_with_a_name_or_none_is_parsed_apart() {
        let parsed = |args: &[&str]| Cli::try_parse_from(args).map(|cli| cli.command);
        match parsed(&["cordelia", "unsubscribe"]) {
            Ok(Some(Commands::Unsubscribe {
                name: None,
                agent: None,
                words: None,
            })) => {}
            _ => panic!("unsubscribe"),
        }
        match parsed(&["cordelia", "unsubscribe", "review", "--agent", "notes"]) {
            Ok(Some(Commands::Unsubscribe {
                name: Some(name),
                agent: Some(agent),
                ..
            })) => assert_eq!((name.as_str(), agent.as_str()), ("review", "notes")),
            _ => panic!("unsubscribe <name> --agent"),
        }
        for refused in [
            &["cordelia", "unsubscribe", "--agent", "notes"][..],
            &["cordelia", "unsubscribe", "--words", "a b c d"],
        ] {
            assert!(parsed(refused).is_err(), "{refused:?}");
        }
    }

    /// `cordelia shared seen <name>` takes a name, and `shared list` and
    /// `status` take `-v` (decision 2026-11-06 (joining), rule 7).
    #[test]
    fn shared_seen_and_v_are_parsed() {
        let parsed = |args: &[&str]| Cli::try_parse_from(args).map(|cli| cli.command);
        match parsed(&["cordelia", "shared", "seen", "team/project"]) {
            Ok(Some(Commands::Shared {
                what: SharedCommand::Seen { name, label: None },
            })) => assert_eq!(name, "team/project"),
            _ => panic!("shared seen"),
        }
        match parsed(&["cordelia", "shared", "seen", "team/project", "bob-desktop"]) {
            Ok(Some(Commands::Shared {
                what:
                    SharedCommand::Seen {
                        name,
                        label: Some(label),
                    },
            })) => assert_eq!(
                (name.as_str(), label.as_str()),
                ("team/project", "bob-desktop")
            ),
            _ => panic!("shared seen <name> <label>"),
        }
        assert!(parsed(&["cordelia", "shared", "seen"]).is_err());
        match parsed(&["cordelia", "shared", "list", "-v"]) {
            Ok(Some(Commands::Shared {
                what: SharedCommand::List { verbose: true, .. },
            })) => {}
            _ => panic!("shared list -v"),
        }
        match parsed(&["cordelia", "status", "-v"]) {
            Ok(Some(Commands::Status { verbose: true, .. })) => {}
            _ => panic!("status -v"),
        }
    }
}
