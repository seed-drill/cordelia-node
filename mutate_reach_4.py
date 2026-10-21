#!/usr/bin/env python3
"""Mutation checks for slice 4 of a relay out of reach: a recovery waits
for the change at each relay, with its two ends and their exit statuses,
and judges the device it recovers from by the carried word it reads
before its yes, by the keys of the relays it read to their end; R0 to R3
word for word (decision 2026-10-19 §4, rules 9 and 10; §5, R0 to R3;
appendix A, a recovery's wait). A part for each rule of the slice: put
each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
STATE_DOOR = 'crates/cordelia-node/src/device_entries.rs'
CARRYING = 'crates/cordelia-api/src/carrying.rs'
RECOVER = 'crates/cordelia-api/src/recover.rs'
WAIT = 'crates/cordelia-node/src/person_cmd/wait.rs'
RCMD = 'crates/cordelia-node/src/recover_cmd.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
ORIG = {f: open(f).read() for f in (STATE_DOOR, CARRYING, RECOVER, WAIT, RCMD, MAIN)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
API_ROUTES = ("cordelia-api", ["--test", "commands_api"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
DEVICE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
RECOVER_E2E = ("cordelia-node", ["--test", "recover_e2e"])
def recover(test): return (API, "recover::tests::" + test)
def carrying(test): return (API, "carrying::tests::" + test)
def routes(test): return (API_ROUTES, test)
def wait(test): return (BIN, "person_cmd::wait::tests::" + test)
def rcmd(test): return (BIN, "recover_cmd::tests::" + test)
def main(test): return (BIN, "tests::" + test)
def door(test): return (DEVICE_E2E, test)
def e2e(test): return (RECOVER_E2E, test)

FOUR_CASES = recover("a_recovery_reads_the_carried_word_of_the_one_device")
SAID_KEY = carrying("test_what_is_said_of_a_relay_says_how_many_entries_it_handed")
SET_UP = routes("test_a_recovery_is_made_at_the_route_and_its_look_is_begun")
DOOR_KEY = door("the_door_for_a_carry_reads_a_channel_that_was_left_and_stores_nothing")
ENDS = wait("the_ends_are_safe_and_live_over_every_state")
REC_ENDS = wait("a_recovery_ends_by_the_relays_that_lack_the_change")
CHANGE_WORDS = wait("each_line_word_for_word")
READ_BY = rcmd("the_relays_that_a_recovery_read_are_those_read_to_their_end_by_their_keys")
JUDGED = rcmd("a_recovery_says_nothing_of_a_device_whose_carried_word_names_a_relay_it_read")
R_WORDS = rcmd("r0_to_r3_word_for_word")
PENDING = rcmd("a_recovery_whose_look_stays_pending_ends_at_3")
WAITS = rcmd("a_recovery_waits_for_the_change_at_each_relay")
STATUSES = rcmd("the_statuses_of_a_recovery")
ONE_SHOT = rcmd("test_what_is_said_once_the_look_has_ended")
NOTHING_WAITS = rcmd("test_nothing_is_said_to_wait_only_where_nothing_does")
HANDED = main("test_what_a_recovery_hands_the_process_that_waits_is_read_there")
STALE_WAIT = wait("a_recoverys_look_whose_classes_are_about_the_entry_before_ends_nothing")
STALE = rcmd("a_recovery_ends_only_on_classes_of_its_change_and_with_3_on_what_it_cannot_read")
STATUS_E2E = e2e("a_recovery_ends_with_3_where_its_look_cannot_be_waited_for_or_on_an_error")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The two ends of a recovery's wait (rule 9) ──────────────────
    ("E1 a recovery ends at R1 where one relay holds the change", WAIT,
     '''    !relays.is_empty() && relays.iter().all(|(_, holds)| *holds)''',
     '''    !relays.is_empty() && relays.iter().any(|(_, holds)| *holds)''',
     [ENDS, REC_ENDS, PENDING]),
    ("E2 a recovery set up with no relay ends at R1", WAIT,
     '''    !relays.is_empty() && relays.iter().all(|(_, holds)| *holds)''',
     '''    relays.iter().all(|(_, holds)| *holds)''',
     [REC_ENDS]),
    ("E3 a relay that lacks the change in no class ends a recovery", WAIT,
     '''        lacking().all(|(class, _)| matches!(class, Some(Class::OutLacking | Class::Refusing)));''',
     '''        lacking().all(|(class, _)| matches!(class, Some(Class::OutLacking | Class::Refusing) | None));''',
     [REC_ENDS, WAITS]),
    ("E4 a relay OUT and lacking does not end a recovery", WAIT,
     '''        lacking().all(|(class, _)| matches!(class, Some(Class::OutLacking | Class::Refusing)));''',
     '''        lacking().all(|(class, _)| matches!(class, Some(Class::Refusing)));''',
     [ENDS, REC_ENDS, PENDING]),
    ("E5 a relay REFUSING does not end a recovery", WAIT,
     '''        lacking().all(|(class, _)| matches!(class, Some(Class::OutLacking | Class::Refusing)));''',
     '''        lacking().all(|(class, _)| matches!(class, Some(Class::OutLacking)));''',
     [ENDS, REC_ENDS, WAITS]),
    ("E6 not done for a recovery where no relay lacks the change", WAIT,
     '''    lacking().next().is_some() && each_settled''',
     '''    each_settled''',
     [ENDS, REC_ENDS]),
    ("E7 a look that lists no relay ends a recovery not done", WAIT,
     '''    lacking().next().is_some() && each_settled''',
     '''    relays.is_empty() || (lacking().next().is_some() && each_settled)''',
     [REC_ENDS]),
    ("E8 not done for a recovery has status 0", WAIT,
     '''            RecoveryEnd::NotDone => NOT_AT_EVERY_RELAY_STATUS,''',
     '''            RecoveryEnd::NotDone => 0,''',
     [ENDS, REC_ENDS, STATUSES]),
    ("E9 a recovery at R1 has a status other than 0", WAIT,
     '''            RecoveryEnd::Recovered => 0,''',
     '''            RecoveryEnd::Recovered => 1,''',
     [ENDS, REC_ENDS, STATUSES]),
    ("E10 the look's classes are not read for a recovery's end", WAIT,
     '''        .map(|relay| (relay.class(), relay.holds()))
        .collect();
    let end = recovery_end_of(&classes);''',
     '''        .map(|relay| (relay.class(), true))
        .collect();
    let end = recovery_end_of(&classes);''',
     [PENDING, WAITS]),

    # ── What a recovery's wait says (rule 9; §5, R0, R1, S2, S3, S8) ──
    ("S1 R0 loses its last sentence", WAIT,
     '''Stopping it stops nothing: the node goes on, \\
         and the recovery stays made."''',
     '''Stopping it stops nothing: the node goes on."''',
     [R_WORDS]),
    ("S2 R1 says that the machine may be closed", WAIT,
     '''        RecoveryEnd::Recovered => vec!["Every relay holds the change.".into()],''',
     '''        RecoveryEnd::Recovered => vec!["Every relay holds the change. You may close this machine.".into()],''',
     [R_WORDS, PENDING]),
    ("S3 a recovery says S8 of a relay that holds the change", WAIT,
     '''            let lacking: Vec<&RelayAt> = relays.iter().filter(|relay| !relay.holds()).collect();''',
     '''            let lacking: Vec<&RelayAt> = relays.iter().collect();''',
     [WAITS]),
    ("S4 the wait after a change says S8 only of a relay that lacks it", WAIT,
     '''                .filter(|relay| relay.class() != Some(Class::Ok))''',
     '''                .filter(|relay| !relay.holds())''',
     [CHANGE_WORDS]),
    ("S5 R0 is said where every relay holds the change", RCMD,
     '''        if first && end != Some(RecoveryEnd::Recovered) {''',
     '''        if first {''',
     [PENDING]),
    ("S6 R0 is never said", RCMD,
     '''            say(format!("\\n{}", wait::recovery_first_line()));''',
     '''            say(String::new());''',
     [PENDING, WAITS]),
    ("S7 S2 and S3 are not said as they come", RCMD,
     '''            .filter(|relay| relay.out_of_reach() && wait::is_about_the_kept_entry(relay, &seen))''',
     '''            .filter(|relay| relay.out_of_reach() && relay.name.is_empty())''',
     [WAITS]),
    ("S8 S2 and S3 are said again at each look", RCMD,
     '''            if !said.contains(line) {
                say(format!("  {line}"));''',
     '''            if !said.is_empty() || said.is_empty() {
                say(format!("  {line}"));''',
     [WAITS]),
    ("S9 the one-shot lines say again which relay holds the change", RCMD,
     '''fn after_lines(seen: &Value, to_come: usize) -> Vec<String> {
    let mut lines = Vec::new();''',
     '''fn after_lines(seen: &Value, to_come: usize) -> Vec<String> {
    let mut lines: Vec<String> = list(seen, "relays")
        .map(|relay| format!("{} holds the change.", text(relay, "relay")))
        .collect();''',
     [ONE_SHOT]),
    ("S10 nothing is said to wait where a relay lacks the change", RCMD,
     '''    let keep_on = !not_reached.is_empty() || wait::relays_of(seen).map_or(true, lacks);''',
     '''    let keep_on = !not_reached.is_empty();''',
     [NOTHING_WAITS]),

    # ── How a recovery's command ends (rule 9, its statuses) ────────
    ("T1 a recovery that has seen another change goes on", RCMD,
     '''        if seen["change"].as_u64() != Some(number) {
            say("This device has since applied another change: `cordelia devices` says.".into());''',
     '''        if seen["change"].as_u64() == Some(u64::MAX) {
            say("This device has since applied another change: `cordelia devices` says.".into());''',
     [STATUSES, STATUS_E2E]),
    ("T2 a recovery's end is not its status", RCMD,
     '''        Ok(Recovered::Ended(end)) => end.status(),''',
     '''        Ok(Recovered::Ended(_)) => 0,''',
     [STATUSES, PENDING]),
    ("T3 another change, or an error, gives 1", RCMD,
     '''        Ok(Recovered::Another | Recovered::NoLongerStands) | Err(_) => NOT_AT_EVERY_RELAY_STATUS,''',
     '''        Ok(Recovered::Another | Recovered::NoLongerStands) | Err(_) => 1,''',
     [STATUSES, STATUS_E2E]),
    ("T4 a look that cannot be waited for gives 0", RCMD,
     '''             this machine has still to send. Keep this machine on until nothing is left to send."
        ),
        NOT_AT_EVERY_RELAY_STATUS,''',
     '''             this machine has still to send. Keep this machine on until nothing is left to send."
        ),
        0,''',
     [STATUSES, STATUS_E2E]),
    ("T5 a look that cannot be waited for ends as before, with 0", RCMD,
     '''    let (said, status) = look_not_waited_for(&failed);
    println!("{said}");
    std::process::exit(status)''',
     '''    let (said, status) = look_not_waited_for(&failed);
    println!("{said}");
    let _ = status;
    Ok(())''',
     [STATUS_E2E]),
    ("T6 an error during the wait is not said", RCMD,
     '''        say_error(wait::could_not_go_on(number, e));''',
     '''        let _ = (&mut say_error, e);''',
     [STATUSES]),
    ("T7 the command's status is not its exit status", MAIN,
     '''            std::process::exit(recover_cmd::recover_made(&cli.config, number, cut_short))''',
     '''            recover_cmd::recover_made(&cli.config, number, cut_short);
            Ok(())''',
     [STATUS_E2E]),

    # ── The relays that a recovery read (rule 10) ───────────────────
    ("K1 the node gives no key of the connection a read was on", STATE_DOOR,
     '''                    let key = Some(link.relay().0);''',
     '''                    let key = None::<[u8; 32]>.filter(|_| link.relay().0 == [0; 32]);''',
     [DOOR_KEY]),
    ("K2 what is said of a read carries no key", CARRYING,
     '''            of_it["key"] = key.into();''',
     '''            let _ = key;''',
     [SAID_KEY]),
    ("K3 the recover look gives no relay's key", RECOVER,
     '''        .map(|relay| json!({ "relay": relay.name, "key": key(relay) }))''',
     '''        .map(|relay| json!({ "relay": relay.name, "key": key(relay).filter(|_| false) }))''',
     [SET_UP]),
    ("K4 a relay read in part counts as read", RCMD,
     '''        let whole = self.at(&[ReadAs::Whole]);''',
     '''        let whole = self.at(&[ReadAs::Whole, ReadAs::Part]);''',
     [READ_BY]),
    ("K5 the key read on does not follow the reading that reached the end", RCMD,
     '''            self.key = said
                .and_then(|said| said["key"].as_str())
                .map(str::to_string);''',
     '''            let _ = said;''',
     [READ_BY]),
    ("K6 the first round's key is not kept", RCMD,
     '''            key: said["key"].as_str().map(str::to_string),
        };''',
     '''            key: None,
        };''',
     [READ_BY]),
    ("K7 what is said of a relay read on carries no key", RCMD,
     '''            said["key"] = key.as_str().into();''',
     '''            let _ = key;''',
     [READ_BY]),
    ("K8 the keys of the node's answers are not read", RCMD,
     '''            let key = relay["key"].as_str()?;
            Some((text(relay, "relay").to_string(), key.to_string()))''',
     '''            let key = relay["the key"].as_str()?;
            Some((text(relay, "relay").to_string(), key.to_string()))''',
     [READ_BY, JUDGED]),
    ("K9 a relay's configured key is not known", RCMD,
     '''            let key = match relay["key"].as_str() {
                Some(key) => Some(key.to_string()),''',
     '''            let key = match relay["key"].as_str().filter(|_| false) {
                Some(key) => Some(key.to_string()),''',
     [READ_BY]),
    ("K10 a relay's key of the connection is not known", RCMD,
     '''                None => connected.map(|(_, key)| key.clone()),''',
     '''                None => connected.map(|(_, key)| key.clone()).filter(|_| false),''',
     [READ_BY]),

    # ── The judgement of the one device (rule 10) ───────────────────
    ("J1 a carried word that names a relay read is cut short", RECOVER,
     '''            Some(word) if word.keys.iter().any(|key| read.contains(key)) => {''',
     '''            Some(word) if word.keys.is_empty() && word.keys.iter().any(|key| read.contains(key)) => {''',
     [FOUR_CASES, JUDGED]),
    ("J2 a carried word is read as no word", RECOVER,
     '''            carried_word = device.and_then(|device| device.carried_word.clone());''',
     '''            carried_word = device.and_then(|device| device.carried_word.clone()).filter(|_| false);''',
     [FOUR_CASES]),
    ("J3 sent is not asked first", RECOVER,
     '''        if self.cut_short.is_none() {
            return Judged::Sent;
        }''',
     '''        if self.cut_short.is_none() && self.carried_word.is_some() {
            return Judged::Sent;
        }''',
     [FOUR_CASES]),
    ("J4 a word that names a relay read is still said", RCMD,
     '''            Judged::Sent | Judged::CarriedToARelayRead => return None,''',
     '''            Judged::Sent => return None,
            Judged::CarriedToARelayRead => None,''',
     [JUDGED]),
    ("J5 R3 is not said where the word names no relay read", RCMD,
     '''            Judged::CarriedElsewhere(word) => Some(CarriedTo::of(&word, known)),''',
     '''            Judged::CarriedElsewhere(_) => None,''',
     [JUDGED]),
    ("J6 R2 is not said before the yes", RCMD,
     '''        Judged::CarriedElsewhere(word) => cut_short
            .as_ref()
            .map(|cut| carried_elsewhere_says(&cut.device, &word, &known)),''',
     '''        Judged::CarriedElsewhere(word) => cut_short
            .as_ref()
            .map(|cut| carried_elsewhere_says(&cut.device, &word, &known))
            .filter(|_| false),''',
     [JUDGED]),
    ("J7 R2 is not among the lines before the yes", RCMD,
     '''    lines.extend(carried_elsewhere.map(str::to_string));''',
     '''    let _ = carried_elsewhere;''',
     [R_WORDS]),
    ("J8 the relays of a carried word are counted without the more", RCMD,
     '''            relays: word.keys.len() as u64 + word.more,''',
     '''            relays: word.keys.len() as u64,''',
     [JUDGED]),
    ("J9 R3 is not handed on to the process that waits", RCMD,
     '''        if let Some(to) = &self.carried_to {
            // Joined to its flag''',
     '''        if let Some(to) = self.carried_to.as_ref().filter(|_| false) {
            // Joined to its flag''',
     [JUDGED, HANDED]),
    ("J10 the count of relays handed is not read", RCMD,
     '''            relays: carried_relays,''',
     '''            relays: 1,''',
     [HANDED]),
    ("J11 the relays handed are not kept", RCMD,
     '''        device.map(|device| Self {
            device,
            read,
            carried_to,
        })''',
     '''        let _ = carried_to;
        device.map(|device| Self {
            device,
            read,
            carried_to: None,
        })''',
     [HANDED]),

    # ── Slice 3's review, in a recovery's wait (rule 9, as rule 8) ──
    ("B1 a recovery ends on classes from before its change", WAIT,
     '''    if !relays
        .iter()
        .all(|relay| is_about_the_kept_entry(relay, seen))
    {
        return Ok((relays, None));''',
     '''    if false {
        return Ok((relays, None));''',
     [STALE_WAIT, STALE]),
    ("B2 S2 and S3 are said of a reach from before the change", RCMD,
     '''            .filter(|relay| relay.out_of_reach() && wait::is_about_the_kept_entry(relay, &seen))''',
     '''            .filter(|relay| relay.out_of_reach())''',
     [STALE]),
    ("B3 a node of another version does not end a recovery's wait", RCMD,
     '''        if let Some(note) = node.another_version()? {''',
     '''        if let Some(note) = node.another_version()?.filter(|_| false) {''',
     [STALE, STATUS_E2E]),
    ("B4 the node's version is not asked during the wait", RCMD,
     '''        crate::node_of_another_version(self.0)''',
     '''        crate::node_of_another_version(self.0).map(|_| None)''',
     [STATUS_E2E]),
    ("B5 a relay whose reach cannot be read is passed over", WAIT,
     '''    let relays = relays_of(seen)?;
    if !relays
        .iter()
        .all(|relay| is_about_the_kept_entry(relay, seen))
    {
        return Ok((relays, None));''',
     '''    let relays = relays_of(seen).unwrap_or_default();
    if !relays
        .iter()
        .all(|relay| is_about_the_kept_entry(relay, seen))
    {
        return Ok((relays, None));''',
     [STALE_WAIT, STALE, STATUS_E2E]),
    ("B6 nothing is said to wait where a relay cannot be read", RCMD,
     '''wait::relays_of(seen).map_or(true, lacks);''',
     '''wait::relays_of(seen).map_or(false, lacks);''',
     [NOTHING_WAITS]),

    # ── R2 and R3, word for word (§5) ───────────────────────────────
    ("W1 R2's first ending names every relay with a key", RCMD,
     '''        .filter(|(_, key)| key.as_ref().is_some_and(|key| word.keys.contains(key)))''',
     '''        .filter(|(_, key)| key.is_some())''',
     [R_WORDS]),
    ("W2 R2 says nothing of a relay not yet sent to", RCMD,
     '''    if word.not_yet > 0 {
        said.push(format!(
            "It had not yet sent it to''',
     '''    if word.not_yet > 1 {
        said.push(format!(
            "It had not yet sent it to''',
     [R_WORDS]),
    ("W3 R2 says them of one relay", RCMD,
     '''    let them = match to.relays {
        1 => "it",''',
     '''    let them = match to.relays {
        0 => "it",''',
     [R_WORDS]),
    ("W4 R3 says them of one relay", RCMD,
     '''            let it = match to.relays {
                1 => "it",''',
     '''            let it = match to.relays {
                0 => "it",''',
     [R_WORDS]),
    ("W5 R2's second ending names no key", RCMD,
     '''            let key = word.keys.first().map(String::as_str).unwrap_or_default();''',
     '''            let key = "";''',
     [R_WORDS]),
    ("W6 R2's last sentence names no relay", RCMD,
     '''            relay
        }
        true => {''',
     '''            "that relay".to_string()
        }
        true => {''',
     [R_WORDS]),
    ("W7 R3 loses its last sentence", RCMD,
     '''is there. Once this machine reaches {it}, `cordelia sync carry <name> --from \\
                 <device>` brings it in, with the phrase.",''',
     '''is there.",''',
     [R_WORDS]),
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
