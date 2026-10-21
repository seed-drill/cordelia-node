#!/usr/bin/env python3
"""Mutation checks for slice 3 of a relay out of reach: the wait after a
change and its three ends, with their exit statuses; `word_to_come` and
each relay's reach in the look, read by the command and never worked out
again; how the node tries each relay; every line of the wait, word for
word; and the help of each command that waits (decision 2026-10-19 §4,
rules 8 and 14; §5, S1 to S11, H1 and H2; appendix A). A part for each
rule of the slice: put each fault in, and confirm the test named for it
fails on an assertion. Run from the root of a checkout that nothing else
edits."""
import re, subprocess, sys

# One name for each file a part edits.
STATE = 'crates/cordelia-api/src/state.rs'
LOOK = 'crates/cordelia-api/src/look.rs'
COMMANDS = 'crates/cordelia-api/src/commands.rs'
REACH = 'crates/cordelia-node/src/device_entries/reach.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
CMD = 'crates/cordelia-node/src/person_cmd.rs'
WAIT = 'crates/cordelia-node/src/person_cmd/wait.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
ORIG = {f: open(f).read() for f in (STATE, LOOK, COMMANDS, REACH, P2P, CMD, WAIT, MAIN, DEVICE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
API_ROUTES = ("cordelia-api", ["--test", "commands_api"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
PERSON_E2E = ("cordelia-node", ["--test", "person_e2e"])
DEVICE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def device(test): return (DEVICE_E2E, test)
def look(test): return (API, "look::tests::" + test)
def commands(test): return (API, "commands::tests::" + test)
def routes(test): return (API_ROUTES, test)
def p2p(test): return (BIN, "p2p::tests::" + test)
def cmd(test): return (BIN, "person_cmd::tests::" + test)
def wait(test): return (BIN, "person_cmd::wait::tests::" + test)
def e2e(test): return (PERSON_E2E, test)

CARRIED = look("the_look_carries_word_to_come_and_each_relays_reach")
TRIED = commands("test_the_look_says_how_the_node_tries_each_relay")
ROUTE = routes("test_the_look_carries_the_word_to_come_each_class_and_how_each_relay_is_tried")
UNRESOLVED = p2p("a_relay_whose_name_does_not_resolve_is_listed_with_the_others")
WRONG_KEY = p2p("one_name_given_twice_with_two_keys_is_listed_by_its_key")
ENDS = wait("the_ends_are_safe_and_live_over_every_state")
NOT_ON_THE_WORD = wait("end_three_does_not_wait_on_the_word_where_a_relay_lacks_the_change")
TABLE = wait("each_case_of_the_table_of_rule_8_reaches_its_end")
NEVER = wait("the_wait_never_says_may_be_closed_or_ends_with_0_while_a_relay_lacks_the_change")
READS = wait("the_command_reads_word_to_come_from_the_node")
WORDS = wait("each_line_word_for_word")
STATUSES = cmd("the_statuses")
MISSING = cmd("the_wait_says_what_is_missing_of_each_relay_and_of_what_is_sent")
OVERLAP = cmd("held_and_not_yet_never_overlap")
CANNOT_START = e2e("the_wait_that_cannot_start_ends_with_3")
ERROR = e2e("the_wait_ends_with_3_on_an_error_and_where_another_change_was_applied")
BEFORE = wait("a_look_whose_classes_are_about_the_entry_before_ends_nothing")
UNREADABLE = wait("a_look_that_cannot_be_read_ends_the_wait_as_an_error")
ANSWERS = device("each_answer_that_says_writes_over_the_one_before")
REFUSED_ENTRY = device("a_relay_that_holds_a_change_the_device_refuses_is_said_to")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The look carries what the command reads (rule 8) ────────────
    ("L1 the look does not carry the word to come", LOOK,
     '''            word_to_come: at_relays.word_to_come,''',
     '''            word_to_come: false,''',
     [CARRIED, ROUTE]),
    ("L2 the look does not carry a relay's class", LOOK,
     '''                class: relay.reach.class,''',
     '''                class: None,''',
     [CARRIED, ROUTE]),
    ("L3 the look does not carry since when a relay refused what waits", LOOK,
     '''                refusing_waits_since: relay.reach.refusing_waits_since,''',
     '''                refusing_waits_since: None,''',
     [CARRIED]),
    ("L4 the look does not carry a relay's refusal for room", LOOK,
     '''                no_room: relay.no_room,''',
     '''                no_room: None,''',
     [CARRIED]),
    ("L5 the node gives no time at which a STUCK relay began refusing", REACH,
     '''            let refusing_waits_since = of
                .refusing_waits_since
                .filter(|_| reached && of.waits == Some(true))
                .map(|since| Moment::back_from(now, since).wall);''',
     '''            let refusing_waits_since: Option<i64> = None;''',
     [NEVER]),
    ("L6 the classes are written by another name", STATE,
     '''#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {''',
     '''#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Class {''',
     [CARRIED]),

    # ── How the node tries each relay (S9) ──────────────────────────
    ("T1 a connected relay is said to be dialled", COMMANDS,
     '''                Some(listed) if listed.state == "connected" => "connected",''',
     '''                Some(listed) if listed.state == "connected" => "dialled",''',
     [TRIED, ROUTE]),
    ("T2 a name that does not resolve is said to be dialled", COMMANDS,
     '''                Some(listed) if listed.tried == Tried::LookedUp => "looked_up",''',
     '''                Some(listed) if listed.tried == Tried::LookedUp => "dialled",''',
     [TRIED, ROUTE]),
    ("T3 a relay that is not dialled is said to be dialled", COMMANDS,
     '''                Some(listed) if listed.tried == Tried::NotDialled => "not_dialled",''',
     '''                Some(listed) if listed.tried == Tried::NotDialled => "dialled",''',
     [TRIED, ROUTE]),
    ("T4 a relay is found by its name alone", COMMANDS,
     '''                known.host == relay.relay && key == relay.reach.key''',
     '''                known.host == relay.relay && (key == relay.reach.key || true)''',
     [TRIED]),
    ("T5 the route gives every relay as dialled", COMMANDS,
     '''        relay["dial"] = dial.get(at).copied().unwrap_or("dialled").into();''',
     '''        relay["dial"] = "dialled".into();''',
     [ROUTE]),
    ("T6 the dial loop does not mark a name that does not resolve", P2P,
     '''                    tried: cordelia_api::state::Tried::LookedUp,''',
     '''                    tried: cordelia_api::state::Tried::Dialled,''',
     [UNRESOLVED]),
    ("T7 the dial loop does not mark a relay that it does not dial", P2P,
     '''                    true => cordelia_api::state::Tried::NotDialled,''',
     '''                    true => cordelia_api::state::Tried::Dialled,''',
     [WRONG_KEY]),

    # ── The three ends (rule 8; appendix A) ─────────────────────────
    ("E1 end 1 does not ask for `sent`", WAIT,
     '''    !relays.is_empty() && relays.iter().all(is(Class::Ok)) && word == OwnWord::Sent''',
     '''    !relays.is_empty() && relays.iter().all(is(Class::Ok)) && word != OwnWord::None''',
     [READS]),
    ("E2 end 1 holds with no relay", WAIT,
     '''    !relays.is_empty() && relays.iter().all(is(Class::Ok)) && word == OwnWord::Sent''',
     '''    relays.iter().all(is(Class::Ok)) && word == OwnWord::Sent''',
     [NOT_ON_THE_WORD]),
    ("E3 end 2 does not take a relay that is STUCK", WAIT,
     '''        .all(|(class, _)| matches!(class, Some(Class::Ok | Class::Stuck | Class::OutHolding)));''',
     '''        .all(|(class, _)| matches!(class, Some(Class::Ok | Class::OutHolding)));''',
     [ENDS, TABLE]),
    ("E4 end 2 takes a relay that is OUT and lacking", WAIT,
     '''        .all(|(class, _)| matches!(class, Some(Class::Ok | Class::Stuck | Class::OutHolding)));''',
     '''        .all(|(class, _)| matches!(class, Some(Class::Ok | Class::Stuck | Class::OutHolding | Class::OutLacking)));''',
     [ENDS, NEVER]),
    ("E5 end 2 does not ask that a relay be OK", WAIT,
     '''    every_holds && relays.iter().any(is(Class::Ok)) && !word_to_come''',
     '''    every_holds && !word_to_come''',
     [ENDS]),
    ("E6 end 2 does not wait for the word to come", WAIT,
     '''    every_holds && relays.iter().any(is(Class::Ok)) && !word_to_come''',
     '''    every_holds && relays.iter().any(is(Class::Ok))''',
     [READS]),
    ("E7 end 3 holds with a relay in no class", WAIT,
     '''    every_classed && (one_lacks || (none_ok && !word_to_come))''',
     '''    (one_lacks || (none_ok && !word_to_come))''',
     [NOT_ON_THE_WORD]),
    ("E8 end 3 waits on the word where a relay lacks the change", WAIT,
     '''    every_classed && (one_lacks || (none_ok && !word_to_come))''',
     '''    every_classed && ((one_lacks && !word_to_come) || (none_ok && !word_to_come))''',
     [ENDS, NOT_ON_THE_WORD]),
    ("E9 end 3 does not wait for the word where none is OK", WAIT,
     '''    every_classed && (one_lacks || (none_ok && !word_to_come))''',
     '''    every_classed && (one_lacks || none_ok)''',
     [NOT_ON_THE_WORD, READS]),
    ("E10 end 3 holds where no relay lacks and one is OK", WAIT,
     '''    let none_ok = !relays.iter().any(is(Class::Ok));''',
     '''    let none_ok = true;''',
     [ENDS]),
    ("E11 the ends are tried in another order", WAIT,
     '''    if ends_done(relays, word) {
        Some(End::Done)
    } else if ends_warned(relays, word_to_come) {''',
     '''    if ends_warned(relays, word_to_come) {
        Some(End::Warned)
    } else if ends_done(relays, word) {
        Some(End::Done)
    } else if false {''',
     [READS]),
    ("E12 a relay in the third state is taken to hold the change", WAIT,
     '''            .is_some_and(|reach| reach.holds == Holds::Holds)''',
     '''            .is_some_and(|reach| reach.holds != Holds::Lacks)''',
     [READS]),
    ("E13 the command reads no relay's reach", WAIT,
     '''                reach: Some(reach),''',
     '''                reach: Some(reach).filter(|_| false),''',
     [NEVER, READS]),
    ("E14 the command reads `sent` as not sent", WAIT,
     '''    if rows().any(|device| device["sent"] == true) {''',
     '''    if rows().any(|device| device["sent"] == false) {''',
     [NEVER]),
    ("E15 the command does not read the word to come", WAIT,
     '''    let end = end_of(&classes, word, word_to_come);''',
     '''    let end = end_of(&classes, word, false);''',
     [READS]),
    ("E16 the command reads a relay that is looked up as dialled", WAIT,
     '''                Some("looked_up") => Dial::LookedUp,''',
     '''                Some("looked_up") => Dial::Dialled,''',
     [READS]),

    # ── The statuses (rule 8) ───────────────────────────────────────
    ("S1 end 3 gives status 0", WAIT,
     '''            End::NotDone => NOT_AT_EVERY_RELAY_STATUS,''',
     '''            End::NotDone => 0,''',
     [TABLE, STATUSES]),
    ("S2 ends 1 and 2 give status 3", WAIT,
     '''            End::Done | End::Warned => 0,''',
     '''            End::Done | End::Warned => 3,''',
     [TABLE, STATUSES]),
    ("S3 the status of a change made and not known to be at every relay is 1", CMD,
     '''pub const NOT_AT_EVERY_RELAY_STATUS: i32 = 3;''',
     '''pub const NOT_AT_EVERY_RELAY_STATUS: i32 = 1;''',
     [STATUSES, WORDS]),
    ("S4 another change applied since gives status 0", CMD,
     '''        Ok(Waited::Another | Waited::NoLongerStands) | Err(_) => NOT_AT_EVERY_RELAY_STATUS,''',
     '''        Ok(Waited::Another) => 0,
        Ok(Waited::NoLongerStands) | Err(_) => NOT_AT_EVERY_RELAY_STATUS,''',
     [STATUSES, ERROR]),
    ("S5 an error in the wait gives status 1", CMD,
     '''        Ok(Waited::Another | Waited::NoLongerStands) | Err(_) => NOT_AT_EVERY_RELAY_STATUS,''',
     '''        Ok(Waited::Another | Waited::NoLongerStands) => NOT_AT_EVERY_RELAY_STATUS,
        Err(_) => 1,''',
     [STATUSES, ERROR]),
    ("S6 a wait that cannot be started gives status 0", CMD,
     '''        NOT_AT_EVERY_RELAY_STATUS,
    )''',
     '''        0,
    )''',
     [STATUSES, CANNOT_START]),
    ("S7 the wait that cannot be started ends with success", CMD,
     '''    std::process::exit(status)''',
     '''    std::process::exit(0 * status)''',
     [CANNOT_START]),
    ("S8 the command's status is not the wait's", MAIN,
     '''            std::process::exit(person_cmd::change_made(&cli.config, number))''',
     '''            std::process::exit(0 * person_cmd::change_made(&cli.config, number))''',
     [ERROR]),
    ("S9 an error in the wait is not said", CMD,
     '''        eprintln!("{}", wait::could_not_go_on(number, e));''',
     '''        let _ = (number, e);''',
     [ERROR]),

    # ── The lines while the wait goes on (S2, S3) ───────────────────
    ("W1 a relay out of reach is said as one that does not hold the change", CMD,
     '''            (true, _) => wait::out_of_reach_line(relay, now_at),''',
     '''            (true, _) => format!("keep this machine on: {name} does not hold the change yet"),''',
     [MISSING]),
    ("W2 a relay out of reach is also said not to be connected", CMD,
     '''    for relay in not_reached.iter().filter(|name| !out_of_reach(name)) {''',
     '''    for relay in not_reached.iter() {''',
     [MISSING]),
    ("W3 names are not said to be sent beside a relay out of reach", CMD,
     '''    let all_reached = not_reached.iter().all(|name| out_of_reach(name))''',
     '''    let all_reached = not_reached.is_empty()''',
     [MISSING]),
    ("W4 a relay that lacks the change is said to hold it", CMD,
     '''            (false, false) => format!("keep this machine on: {name} does not hold the change yet"),''',
     '''            (false, false) => format!("{name} holds the change"),''',
     [MISSING]),

    # ── The words (S1 to S11, `<since>`, `<when>`) ──────────────────
    ("V1 S1 says another word", WAIT,
     '''It ends sooner, with status {NOT_AT_EVERY_RELAY_STATUS}''',
     '''It ends early, with status {NOT_AT_EVERY_RELAY_STATUS}''',
     [WORDS]),
    ("V2 `<since>` takes a relay reached at its reference as not reached", LOOK,
     '''        Some(at) if at >= reach.reference => {''',
     '''        Some(at) if at > reach.reference => {''',
     [WORDS]),
    ("V3 `<when>` has no date where it is not today", LOOK,
     '''        Some(moment) if day(at) == day(now) => moment.format("%H:%M UTC").to_string(),''',
     '''        Some(moment) if day(at) == day(now) || at < now => moment.format("%H:%M UTC").to_string(),''',
     [WORDS]),
    ("V4 `<held>` leaves out a relay that has what was carried", WAIT,
     '''            || relay.has_what_was_carried == Some(true)''',
     '''            || relay.has_what_was_carried == Some(false)''',
     [WORDS, OVERLAP]),
    ("V5 on the `sent` path not every relay is in `<held>`", WAIT,
     '''        word == OwnWord::Sent
            || relay.has_what_was_carried''',
     '''        word == OwnWord::Carried
            || relay.has_what_was_carried''',
     [WORDS, OVERLAP]),
    ("V6 S7 gets its verb wrong", WAIT,
     '''            verb(not_yet.len(), "gets", "get"),''',
     '''            verb(not_yet.len(), "get", "gets"),''',
     [WORDS]),
    ("V7 S7 says what waits for a relay that is OK", WAIT,
     '''        .filter(|relay| matches!(relay.class(), Some(Class::OutHolding | Class::Stuck)))''',
     '''        .filter(|relay| matches!(relay.class(), Some(Class::OutHolding | Class::Stuck | Class::Ok)))''',
     [WORDS]),
    ("V8 S8 says nothing of why where the relay had no room for the change", WAIT,
     '''        Some(LacksFor::Room(refused)) => format!(''',
     '''        Some(LacksFor::Room(_)) if true => format!("  {} is reached.", relay.name),
        Some(LacksFor::Room(refused)) => format!(''',
     [WORDS]),
    ("V9 S8 swaps a full relay and an address over its allowance", WAIT,
     '''                false => "it is full",''',
     '''                false => "this address is over its allowance of new channels there",''',
     [WORDS]),
    ("V10 S9 says of a name that does not resolve that it is dialled", WAIT,
     '''    let looked_up = dialled_so(Dial::LookedUp);''',
     '''    let looked_up = dialled_so(Dial::NotDialled);''',
     [WORDS]),
    ("V11 S9 says nothing of a relay that is not dialled", WAIT,
     '''    let not_dialled = dialled_so(Dial::NotDialled);''',
     '''    let not_dialled = dialled_so(Dial::LookedUp);''',
     [WORDS]),
    ("V12 S9 is said where no relay is reached", WAIT,
     '''    if reached && !why.is_empty() {''',
     '''    if (reached || !lines.is_empty()) && !why.is_empty() {''',
     [WORDS]),
    ("V13 S11 says that none holds the change where one does", WAIT,
     '''            if !relays.iter().any(RelayAt::holds) {''',
     '''            if relays.iter().any(|relay| !relay.reached()) {''',
     [WORDS]),
    ("V14 S10b gets its verb wrong", WAIT,
     '''                verb(stuck.len(), "refuses", "refuse")''',
     '''                verb(stuck.len(), "refuse", "refuses")''',
     [WORDS]),
    ("V15 what is said on an error in the wait leaves out that the change is made", WAIT,
     '''        "The change is made (change {number}). This command could not go on: {error:#}. Do not \\''',
     '''        "This command could not go on (change {number}): {error:#}. Do not \\''',
     [WORDS, ERROR]),
    ("V16 S6 says a relay has all that was carried where it has not", WAIT,
     '''                lines.push(match held.iter().any(|at| at.name == relay.name) {''',
     '''                lines.push(match !held.is_empty() {''',
     [WORDS, OVERLAP]),

    # ── The help (rule 14) ──────────────────────────────────────────
    ("H1 settle says nothing of its end", MAIN,
     '''    /// phrase, on a device that has seen both. Asks at a terminal.
    ///
    /// Keep this machine on until the command says you can close it.''',
     '''    /// phrase, on a device that has seen both. Asks at a terminal.
    ///
    /// Keep this machine on.''',
     [WORDS]),
    ("H2 renew does not say that the change is made", MAIN,
     '''    /// that the change is made: do not make it again.
    Renew,''',
     '''    /// that the change is made.
    Renew,''',
     [WORDS]),
    ("H3 remove-device does not say that the change is made", MAIN,
     '''    /// that the change is made: do not make it again.
    ///
    /// You cannot remove''',
     '''    /// that the change is made.
    ///
    /// You cannot remove''',
     [WORDS]),
    ("H4 recover does not say its status", MAIN,
     '''    /// or refuses it, the command says so and ends with status 3. Any''',
     '''    /// or refuses it, the command says so and ends. Any''',
     [WORDS]),
    # ── The look is of the change (rule 8), and can be read ─────────
    ("N1 the node says of no relay which entry its reach is about", REACH,
     '''        let about = lock(&self.inner).kept.flatten();''',
     '''        let about: Option<[u8; 32]> = None;''',
     [NEVER]),
    ("N2 the look does not carry which entry a relay's reach is about", LOOK,
     '''                about: relay.reach.about.map(hex::encode),''',
     '''                about: None,''',
     [CARRIED]),
    ("N3 an end holds on classes from before the change", WAIT,
     '''    if !relays
        .iter()
        .all(|relay| is_about_the_kept_entry(relay, seen))
    {
        return Ok((relays, word, None));''',
     '''    if false {
        return Ok((relays, word, None));''',
     [BEFORE]),
    ("N4 a look that names no kept entry is taken to be of the change", WAIT,
     '''    kept.is_some()
        && relay''',
     '''    relay''',
     [BEFORE]),
    ("N5 the lines read a relay's reach from before the change", CMD,
     '''            relay.reach = None;''',
     '''            let _ = &relay.reach;''',
     [MISSING]),
    ("N6 a relay whose reach cannot be read is in no class, and no error", WAIT,
     '''            let reach = serde_json::from_value(relay["reach"].clone()).map_err(|e| {
                anyhow::anyhow!("the node says of {name} what this command cannot read ({e})")
            })?;
            Ok(RelayAt {
                name,
                reach: Some(reach),''',
     '''            let reach: Option<ReachLook> = serde_json::from_value(relay["reach"].clone()).ok();
            Ok(RelayAt {
                name,
                reach,''',
     [UNREADABLE, ERROR]),
    ("N7 a look that does not say whether a word is to come is read as none", WAIT,
     '''    let Some(word_to_come) = seen["word_to_come"].as_bool() else {''',
     '''    let Some(word_to_come) = seen["word_to_come"].as_bool().or(Some(false)) else {''',
     [UNREADABLE]),
    ("N8 the wait does not ask the node's version", CMD,
     '''        if let Some(note) = crate::node_of_another_version(config_path)? {''',
     '''        if let Some(note) = None::<String> {''',
     [ERROR]),
    ("N9 end 3 holds with no relay listed", WAIT,
     '''    let every_classed = !relays.is_empty() && relays.iter().all(|(class, _)| class.is_some());''',
     '''    let every_classed = relays.iter().all(|(class, _)| class.is_some());''',
     [NOT_ON_THE_WORD]),
    ("N10 `<when>` puts the date before the time", LOOK,
     '''        Some(moment) => moment.format("%H:%M UTC on %Y-%m-%d").to_string(),''',
     '''        Some(moment) => moment.format("%Y-%m-%d %H:%M UTC").to_string(),''',
     [WORDS]),
    ("N11 the own word is read of any change", WAIT,
     '''            .filter(|device| device["applied"].as_u64() == Some(number))''',
     '''            .filter(|device| device["applied"].as_u64().is_some() || number > 0)''',
     [READS]),
    ("N12 S8 says of a relay with no reason noted that it holds another change", WAIT,
     '''        None => format!("  {} is reached, and has not taken the change.", relay.name),''',
     '''        None => format!("  {} is reached, and holds another change.", relay.name),''',
     [WORDS]),
    ("N13 the look does not carry why a relay lacks the change", LOOK,
     '''                lacks_for: relay.reach.lacks_for.clone(),''',
     '''                lacks_for: None,''',
     [CARRIED]),
    ("N14 no room for the change is not noted as why the relay lacks it", DEVICE,
     '''                    self.lacks_for_room(link);''',
     '''''',
     [ANSWERS]),
    ("N15 why a relay lacked the change outlives its holding it", DEVICE,
     '''                of.lacks_for = None;''',
     '''''',
     [ANSWERS]),
    ("N16 why the device refuses the relay's entry is not why it lacks the change", DEVICE,
     '''                        why: Some(why.to_string()),''',
     '''                        why: None,''',
     [REFUSED_ENTRY]),
]
# Rules of the slice that no test can tell, each with why. Leave it
# empty unless the record itself says the rule cannot be tested.
UNTOLD = []

def edits(a, b):
    return list(zip(a, b)) if isinstance(a, list) else [(a, b)]

TEST_MAX_SECS = 1500
BASELINE_TRIES = 3

def run(where, test):
    import os, signal
    crate, args = where
    p = subprocess.Popen(["cargo", "test", "-p", crate, *args, test, "--", "--exact"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         start_new_session=True)
    try:
        out, _ = p.communicate(timeout=TEST_MAX_SECS)
        return out
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return (out or "") + "\ntest result: FAILED. 0 passed; 1 failed; THE TEST DID NOT END\n"

def verdict_of(text):
    if "error: could not compile" in text or "error[" in text:
        return "DID NOT COMPILE"
    if re.search(r"test result: FAILED\. \d+ passed; [1-9]\d* failed", text):
        return "detected (test failed)"
    passed = re.findall(r"test result: ok\. (\d+) passed", text)
    if passed and any(int(n) >= 1 for n in passed):
        return "NOT DETECTED (test passed)"
    return "NO TEST RAN"

if "--list" in sys.argv:
    print(" ".join(m[0].split()[0] for m in MUTATIONS))
    sys.exit(0)
if "--check" in sys.argv:
    bad = [(name, ORIG[f].count(old)) for name, f, a, b, tests in MUTATIONS
           for old, _ in edits(a, b) if ORIG[f].count(old) != 1]
    names = [m[0].split()[0] for m in MUTATIONS]
    twice = sorted({n for n in names if names.count(n) > 1})
    print(len(MUTATIONS), "mutations;", "all found once" if not bad else bad,
          "" if not twice else f"named twice: {twice}",
          "" if not UNTOLD else f"{len(UNTOLD)} that no test tells: {[u.split()[0] for u in UNTOLD]}")
    sys.exit(1 if bad or twice or UNTOLD else 0)
only = {a for a in sys.argv[1:] if not a.startswith("--")}
MUTATIONS = [m for m in MUTATIONS if m[4] and (not only or m[0].split()[0] in only)]
seen = set()
for _, _, _, _, tests in MUTATIONS:
    for where, test in tests:
        if test in seen:
            continue
        seen.add(test)
        tries = 0
        while True:
            tries += 1
            text = run(where, test)
            v = verdict_of(text)
            if v.startswith('NOT DETECTED') or tries == BASELINE_TRIES:
                break
            why = next((l.strip()[:200] for l in text.splitlines()
                        if "panicked at" in l or "timed out" in l), "")
            print(f"baseline-try | {test} | try {tries} did not pass | {why}", flush=True)
        print(f"baseline | {test} | {'passes' if v.startswith('NOT DETECTED') else 'DOES NOT PASS: ' + v}", flush=True)
        if not v.startswith('NOT DETECTED'):
            sys.exit(1)
try:
    for name, f, a, b, tests in MUTATIONS:
        mutated = ORIG[f]
        for old, new in edits(a, b):
            assert mutated.count(old) == 1, (name, mutated.count(old))
            mutated = mutated.replace(old, new)
        open(f, 'w').write(mutated)
        for where, test in tests:
            text = run(where, test)
            v = verdict_of(text)
            if v in ("DID NOT COMPILE", "NO TEST RAN"):
                print(text[-1500:])
            why = next((l.strip()[:150] for l in text.splitlines()
                        if "panicked at" in l or "timed out" in l), "")
            print(f"{name} | {test} | {v} | {why}", flush=True)
        open(f, 'w').write(ORIG[f])
finally:
    for f, text in ORIG.items():
        open(f, 'w').write(text)
