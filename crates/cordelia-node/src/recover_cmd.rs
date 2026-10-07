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
//!    device, up to 256, each with the first words of its key's
//!    fingerprint and how much it signed there, and asks of each one of
//!    three things: the person still has it, it is lost or broken, or it
//!    may be in someone else's hands. No answer is suggested.
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
use cordelia_core::protocol::{RECOVERY_MAX_DEVICES_SHOWN, RECOVERY_MAX_NAMES};
use cordelia_crypto::entry::CheckedEntry;
use cordelia_crypto::statement::{Device, Statement, StatementError};
use cordelia_crypto::{derive, fingerprint, proof};

use crate::carry_cmd::read_through_the_node;
use crate::person_cmd::{
    NOT_A_YES, counted, default_label, file_shown, list, look, made_all_the_same, named,
    names_this_device, own_key, text, time_of, typed_phrase,
};
use crate::terminal::Terminal;
use crate::{Told, api_post_told, refuse_before_a_phrase};

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

/// A proof of the key of the channel whose secret is `secret`, for each
/// connection that has a session, as the node is handed them.
fn proofs_for(
    secret: &[u8; 32],
    sessions: &[(String, [u8; 32])],
    own: &[u8; 32],
) -> anyhow::Result<Vec<Value>> {
    let mut proofs = Vec::new();
    for (relay, session) in sessions {
        let proof = proof::make(secret, session, own)?;
        proofs.push(json!({ "relay": relay, "proof": hex::encode(proof) }));
    }
    Ok(proofs)
}

/// Read the channel whose secret is `secret` at every relay, through the
/// node, and say of which relay it could not be read to its end.
fn read_channel(
    config_path: &str,
    secret: &[u8; 32],
    sessions: &[(String, [u8; 32])],
    own: &[u8; 32],
    what: &str,
) -> anyhow::Result<Vec<CheckedEntry>> {
    let channel = derive::channel_id(secret)?;
    let proofs = proofs_for(secret, sessions, own)?;
    let (entries, relays) = read_through_the_node(config_path, &channel, proofs)?;
    for relay in &relays {
        let read = text(relay, "read");
        if !matches!(read, "whole" | "not held") {
            println!(
                "  Could not read {what} at {} to its end ({read}).",
                text(relay, "relay")
            );
        }
    }
    Ok(entries)
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
/// signed in the personal channel.
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
            match row.counts {
                true => "",
                false => ", by a record that does not count",
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
/// §9): from whom the look takes and from whom it takes nothing; the
/// names that are carried, and those that are left; and what stops.
fn will_do_lines(
    generation: &Generation,
    answers: &[Answer],
    names: &recover::Names,
    own: &[u8; 32],
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
    let nothing: Vec<&Row> = rows
        .iter()
        .enumerate()
        .filter(|(at, row)| {
            row.counts && recover::in_other_hands(rows, answers, *at) && row.key != *own
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
    if generation.not_shown > 0 {
        lines.push(format!(
            "{} more could not be shown: the look takes nothing from those, and each is in no \
             list.",
            counted(generation.not_shown, "record of an addition")
                .replace("record of an additions", "records of additions")
        ));
    }
    let said = |all: &[String]| -> String {
        let all: Vec<String> = all.iter().map(|name| file_shown(name)).collect();
        all.join(", ")
    };
    match names.carried.is_empty() {
        true => lines.push("No name is carried: none is listed.".to_string()),
        false => lines.push(format!(
            "{} carried: {}.",
            match names.carried.len() {
                1 => "1 name is".to_string(),
                n => format!("{n} names are"),
            },
            said(&names.carried)
        )),
    }
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
            "{} left, which only a device listed from which nothing is taken: {}.",
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
    let mut sessions: Vec<(String, [u8; 32])> = Vec::new();
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
    let handed = {
        let secret = phrase.channel_secret()?;
        read_channel(config_path, &secret, &sessions, &own, "it")?
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
        anyhow::bail!(
            "no relay that was reached holds a change of this recovery phrase: there is nothing \
             to recover from. Either these are not the words of your devices' phrase, or the \
             relays have dropped what they held: a relay keeps what nobody has used for 90 days, \
             and no longer. Nothing was done."
        );
    };
    let (from, apart) = match found.apart.first() {
        None => (found.from, None),
        Some(other) => {
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
            if found.apart.len() > 1 {
                println!(
                    "\n{} besides those is on neither's chain, and is not settled by this \
                     recovery.",
                    match found.apart.len() - 1 {
                        1 => "1 more change".to_string(),
                        n => format!("{n} more changes"),
                    }
                );
            }
            println!(
                "\nThe recovery is made from one of them, and the change it makes settles the \
                 two: every key that either removed stays removed. The devices of the other \
                 that are not asked about here are in no list after it."
            );
            loop {
                let typed = at.answer("  Type `1` or `2`, the one to recover from: ")?;
                match typed.as_deref() {
                    Some("1") => break (found.from, Some(other.clone())),
                    Some("2") => break (other.clone(), Some(found.from)),
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
    let generation = {
        let personal = Zeroizing::new(derive::personal_secret(&for_phrase.secret)?);
        let handed = read_channel(
            config_path,
            &personal,
            &sessions,
            &own,
            "the personal channel",
        )?;
        let now = chrono::Utc::now().timestamp();
        recover::read_generation(&from, &statement_key, &for_phrase.secret, &handed, now)?
    };
    let rows = &generation.rows;
    println!(
        "\nThe devices of change {}, and those added since, each with the first words of its \
         key's fingerprint. A label is what the device that added it called it: the words are \
         what tells two apart.\n\n{THREE_ANSWERS}",
        statement.number
    );
    let mut answers: Vec<Answer> = Vec::new();
    for at_row in 0..rows.len() {
        let says = row_says(rows, at_row, statement.number);
        if rows[at_row].key == own {
            println!("{says}\n  It is this machine: it is the one device of the change.");
            answers.push(Answer::Have);
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
    if generation.not_shown > 0 {
        println!(
            "\n{} beyond the {RECOVERY_MAX_DEVICES_SHOWN} that are shown: nothing is asked of \
             those.",
            counted(generation.not_shown, "more record")
        );
    }

    // The names: those of this generation, and those of the generations
    // before, where a key in either list of this statement listed them.
    let excluded: Vec<[u8; 32]> = (0..rows.len())
        .filter(|at_row| recover::in_other_hands(rows, &answers, *at_row))
        .map(|at_row| rows[at_row].key)
        .collect();
    let mut before: Vec<Vec<String>> = Vec::new();
    for earlier in &for_phrase.earlier {
        let personal = Zeroizing::new(derive::personal_secret(&earlier.secret)?);
        let what = format!("the personal channel of change {}", earlier.number);
        let handed = read_channel(config_path, &personal, &sessions, &own, &what)?;
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
    for line in will_do_lines(&generation, &answers, &names, &own) {
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
    let mut left = vec![json!({
        "number": statement.number,
        "secret": hex::encode(for_phrase.secret),
    })];
    for earlier in &for_phrase.earlier {
        left.push(json!({ "number": earlier.number, "secret": hex::encode(earlier.secret) }));
    }
    drop(for_phrase);
    let labelled = |answer: fn(&Answer) -> bool| -> Vec<Value> {
        rows.iter()
            .zip(&answers)
            .filter(|(row, said)| answer(said) && row.key != own)
            .map(|(row, _)| json!({ "key": hex::encode(row.key), "label": row.label }))
            .collect()
    };
    let body = json!({
        "entry": hex::encode(entry.to_wire()),
        "statement_key": hex::encode(*statement_key),
        "left": left,
        "gone": labelled(|said| *said != Answer::Have),
        "still_have": labelled(|said| *said == Answer::Have),
        "word": word,
    });
    drop(statement_key);
    let made = api_post_told(
        config_path,
        "/api/v1/recover/make",
        body,
        Some(Duration::from_secs(60)),
    );
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
    let cut_short = generation.cut_short.map(|key| {
        let label = rows.iter().find(|row| row.key == key);
        named(
            &label.map(|row| row.label.clone()).unwrap_or_default(),
            &key,
        )
    });
    goes_on_in_a_new_process(config_path, signs.number, cut_short)
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
    cut_short: Option<String>,
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
                if let Some(cut_short) = &cut_short {
                    command.arg("--cut-short").arg(cut_short);
                }
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
        lines.push(format!(
            "  {} signed {} that the new channels lack, in: {}. It is brought in only with the \
             phrase: cordelia sync carry <name> --from \"{words}\"",
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
    cut_short: Option<String>,
) -> anyhow::Result<()> {
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
    if let Some(device) = cut_short {
        println!(
            "The device that this was recovered from, {device}, never wrote that it had sent \
             what it carried: a recovery, or a change, that was made on it was cut short. What \
             it had sent is brought back. What the devices that were gone before it wrote, in \
             the files it had not sent, is at the relays in the generation before: `cordelia \
             sync carry <name> --from <device>` brings it in, with the phrase, and lists those \
             devices where no device is named."
        );
    }
    let seen = look(config_path)?;
    for line in after_lines(&seen) {
        println!("{line}");
    }
    Ok(())
}

/// What is said once the look has ended, of what the node says of this
/// machine (decision 2026-10-04 §9, steps 5 and 6): which relay holds
/// the change; "keep this machine on" with how many names are still to
/// send; and, for each device that the person still has, how it is added
/// again.
fn after_lines(seen: &Value) -> Vec<String> {
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
    for relay in list(seen, "not_reached").filter_map(Value::as_str) {
        lines.push(format!(
            "keep this machine on: {relay} is not connected, and what is still to send there is \
             not known until it is."
        ));
    }
    let to_go = list(&seen["names"], "to_go").count();
    lines.push(match to_go {
        0 => "Nothing is waiting to be sent to a relay that is connected. `cordelia devices` \
              shows what each relay holds."
            .to_string(),
        to_go => format!(
            "keep this machine on: {} still to send",
            counted(to_go, "name")
        ),
    });
    let still: Vec<&Value> = list(seen, "left_out").collect();
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

    /// What a recovery will do is said before its yes (decision
    /// 2026-10-04 §9): from whom the look takes, and from whom it takes
    /// nothing, with the command that brings what they wrote; the names
    /// that are carried, and those that are left and why.
    #[test]
    fn test_what_a_recovery_will_do_is_said_before_its_yes() {
        let generation = Generation {
            rows: rows(),
            not_shown: 2,
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
        let all = will_do_lines(&generation, &answers, &names, &[9; 32]).join("\n");
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
                 those, and each is in no list."
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
                "1 name is left, which only a device listed from which nothing is taken: theirs."
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
        let all = will_do_lines(&generation, &none, &empty, &[9; 32]).join("\n");
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
        // What is no key is not shown.
        assert!(!all.contains("odd"), "{all}");

        // A look that found nothing more says the one line.
        let plain = json!({ "names": 1, "carried": 1, "carried_names": 1 });
        assert_eq!(
            look_lines(&plain),
            ["The look is made: 1 name read, and 1 version carried, in 1 name."]
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
            "names": { "to_go": ["a", "b", "c"], "sent": ["d"] },
            "left_out": [{ "label": "desktop", "words": "w1 w2 w3 w4", "number": 3 }],
        });
        let lines = after_lines(&seen);
        let all = lines.join("\n");
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

        // With nothing to send, and nobody to add again.
        let done = json!({
            "this_device": "k", "relays": [{ "relay": "one", "holds_latest": true }],
            "names": { "to_go": [], "sent": ["a"] }, "left_out": [],
        });
        let all = after_lines(&done).join("\n");
        assert!(all.contains("Nothing is waiting to be sent"), "{all}");
        assert!(!all.contains("keep this machine on"), "{all}");
        assert!(!all.contains("added again"), "{all}");
        let one = json!({ "relays": [], "names": { "to_go": ["a"] } });
        assert!(
            after_lines(&one).contains(&"keep this machine on: 1 name still to send".to_string())
        );
    }
}
