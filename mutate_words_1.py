#!/usr/bin/env python3
"""Mutation checks for the words of a change, rules 1 to 7 (decision
2026-10-24): the question to a device added since the last change, and
its answer word `list`; a relay named as it is configured in every
line, from the connection that the dial loop made to it; each line of
the wait with its time, the line that the wait is still waiting, and
the line that each end begins with; the count while a relay is waited
out; the plain status that says its label once; "since" that says since
what; and a relay out of reach that says that it cannot be reached. A
part for each rule of the slice: put each fault in, and confirm the test
named for it fails on an assertion. Run from the root of a checkout that
nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PERSON = 'crates/cordelia-node/src/person_cmd.rs'
WAIT = 'crates/cordelia-node/src/person_cmd/wait.rs'
RECOVER = 'crates/cordelia-node/src/recover_cmd.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
REACH = 'crates/cordelia-node/src/device_entries/reach.rs'
INDICATOR = 'crates/cordelia-node/src/indicator.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
COMMANDS = 'crates/cordelia-api/src/commands.rs'
LOOK = 'crates/cordelia-api/src/look.rs'
ORIG = {f: open(f).read() for f in (PERSON, WAIT, RECOVER, P2P, REACH, INDICATOR, MAIN,
                                    COMMANDS, LOOK)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NODE_BIN = ("cordelia-node", ["--bin", "cordelia"])
NODE_LIB = ("cordelia-node", ["--lib"])
PERSON_E2E = ("cordelia-node", ["--test", "person_e2e"])
API = ("cordelia-api", ["--lib"])
def person(test): return (NODE_BIN, "person_cmd::tests::" + test)
def wait(test): return (NODE_BIN, "person_cmd::wait::tests::" + test)
def recover(test): return (NODE_BIN, "recover_cmd::tests::" + test)
def p2p(test): return (NODE_BIN, "p2p::tests::" + test)
def indicator(test): return (NODE_BIN, "indicator::tests::" + test)
def main(test): return (NODE_BIN, "tests::" + test)
def reach(test): return (NODE_LIB, "device_entries::reach::tests::" + test)
def commands(test): return (API, "commands::tests::" + test)
def look(test): return (API, "look::tests::" + test)
def e2e(test): return (PERSON_E2E, test)

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── Rule 1: the question to a device added since the last change ──
    ("Q1 the question says what it said before, and not what a change is", PERSON,
     '''    let says = format!(
        "\\nA change is the list of your devices that your recovery phrase signs.\\n\\
         {signed_before} {} added this machine at {}, as {this}.\\n\\
         {makes} The machine that makes a change is always in it, so change {new} will list \\
         this machine as {this}.",
        named(&handed.label(&added.adder), &added.adder),
        time_of(added.at)
    );''',
     '''    let _ = (signed_before, makes, new);
    let says = format!(
        "\\nThis device is not in the last change: it was added since, as {this}, from {} at \\
         {}.\\nThe device that makes a change is always among its devices: this change lists \\
         it under that label.",
        named(&handed.label(&added.adder), &added.adder),
        time_of(added.at)
    );''',
     [person("a_device_added_since_is_told_the_change_that_will_list_it")]),
    ("Q2 the change a settlement makes is named one above the change applied", PERSON,
     '''        (Some((apart, _, _)), true) => applied.max(apart.statement.number) + 1,''',
     '''        (Some((_, _, _)), true) => applied + 1,''',
     [person("the_change_that_the_question_names_is_the_one_signed")]),
    ("Q3 the answer that lists this device is `stays` again", PERSON,
     '''const LISTS_THIS_MACHINE: &str = "list";''',
     '''const LISTS_THIS_MACHINE: &str = "stays";''',
     [e2e("a_device_added_since_the_last_change_is_asked_to_list_itself")]),
    # ── Rule 2: a relay named as it is configured ──
    ("N1 the dial loop says of no relay which connection is its own", P2P,
     '''            relay.connection = peer.map(|peer| peer.0);''',
     '''            relay.connection = peer.and(None);''',
     [p2p("each_connection_says_the_configured_relay_it_was_made_to")]),
    ("N2 a row names a relay given no key by nothing", COMMANDS,
     '''                None => relay.connection?,''',
     '''                None => None?,''',
     [commands("a_relay_given_no_key_is_named_in_its_row_as_configured")]),
    ("N3 the wait names a row by the address it was reached at", PERSON,
     '''    waits["name"].as_str().unwrap_or(UNNAMED_RELAY)''',
     '''    waits["relay"].as_str().unwrap_or(UNNAMED_RELAY)''',
     [e2e("the_wait_names_a_relay_as_configured")]),
    # ── Rule 3: each line of the wait carries its time ──
    ("W1 a line of the wait is said with no time", WAIT,
     '''    format!("  {}  {line}", clock(at))''',
     '''    let _ = clock(at);
    format!("  {line}")''',
     [person("each_line_of_the_wait_starts_with_its_time_and_is_said_once")]),
    ("W2 the wait never says that it is still waiting", WAIT,
     '''        if at.saturating_sub(self.last_said) < STILL_WAITING_SECS {''',
     '''        if at.saturating_sub(self.last_said) < STILL_WAITING_SECS || STILL_WAITING_SECS > 0 {''',
     [person("still_waiting_is_said_after_a_minute_with_no_new_line")]),
    ("W3 an end of the wait after a change says no line of its own first", PERSON,
     '''        if let Some(end) = end {
            say(wait::Told::ended(at));
            for line in wait::end_lines(end, &relays, word, at) {''',
     '''        if let Some(end) = end {
            for line in wait::end_lines(end, &relays, word, at) {''',
     [person("each_end_begins_with_the_wait_has_ended")]),
    ("W4 an end of a recovery's wait says no line of its own first", RECOVER,
     '''        let ended = |begun: bool| begun.then(|| wait::Told::ended(at));''',
     '''        let ended = |begun: bool| begun.then(|| wait::Told::ended(at)).and(None);''',
     [recover("each_end_of_a_recoverys_wait_begins_with_the_wait_has_ended")]),
    ("W5 S1 does not say that its lines have their times", WAIT,
     '''         goes on. {TIMES_SAID}"''',
     '''         goes on."''',
     [wait("each_line_word_for_word")]),
    # ── Rule 4: the count while a relay is waited out ──
    ("C1 no count is said of a relay waited out", WAIT,
     '''    let reach = relay.reach.as_ref().filter(|reach| reach.class.is_none())?;''',
     '''    let reach = relay.reach.as_ref().filter(|reach| reach.class.is_none() && now < 0)?;''',
     [person("the_count_of_a_relay_waited_out")]),
    # ── Rule 5: the plain status says its label once ──
    ("M1 the plain status says memory twice", MAIN,
     '''    format!("  Memory:    {}", indicator::without_memory(summary))''',
     '''    format!("  Memory:    {summary}")''',
     [main("the_plain_status_says_memory_once")]),
    # ── Rule 6: "since" says since what ──
    ("S1 since says since a moment, not since what", LOOK,
     '''        (_, ReferenceBy::Change) => "this device applied the change",
        (_, ReferenceBy::Start) => "this device started",
        (_, ReferenceBy::Sleep) => "this device woke from sleep",
    };
    let last = reach
        .last_reached
        .map(|at| format!(" (it was last reached at {})", when(at, now)))
        .unwrap_or_default();
    format!(
        "has not answered since {what} at {}{last}",
        when(reach.reference, now)
    )''',
     '''        _ => "",
    };
    let _ = what;
    format!("has not answered since {}", when(reach.reference, now))''',
     [look("since_says_since_what")]),
    ("S2 a new kept entry does not say that the reference is the change", REACH,
     '''            inner.common_by = ReferenceBy::Change;''',
     '''            inner.common_by = inner.common_by;''',
     [reach("the_reference_says_which_moment_it_is")]),
    # ── Rule 7: a relay out of reach says that it cannot be reached ──
    ("R1 S8 of a relay out of reach that lacks the change, as before", WAIT,
     '''                "  {} cannot be reached from here, and is not known to hold the change: it {}.",''',
     '''                "  {} is not known to hold the change, and {}.",''',
     [wait("each_line_word_for_word")]),
    ("R2 T2 as before", LOOK,
     '''                "{} cannot be reached from here, and is not known to hold the latest change: \\
                 it {}",''',
     '''                "{} is not known to hold the latest change, and {}",''',
     [look("each_line_word_for_word")]),
    ("R3 D4 as before", PERSON,
     '''                "cannot be reached from here, and is not known to hold the latest change: it {}. \\
                 A device of yours that reaches only it may not have heard of that change. If \\''',
     '''                "is not known to hold the latest change, and {}. \\
                 A device of yours that reaches only it may not have heard of that change. If \\''',
     [person("each_relay_line_by_its_case")]),
    ("R4 the status line counts no relay as out of reach", INDICATOR,
     '''        let out = lacking.iter().filter(|relay| relay.out_of_reach).count();''',
     '''        let out = lacking.iter().filter(|relay| relay.out_of_reach && false).count();''',
     [indicator("the_line_says_out_of_reach_where_every_relay_it_counts_is")]),
    ("R5 what the status reads of a relay does not say that it is out of reach", MAIN,
     '''                    out_of_reach: relay["reach"]["class"] == "out_lacking",''',
     '''                    out_of_reach: relay["reach"]["class"] == "out_holding",''',
     [main("test_what_a_status_goes_by_of_a_persons_devices")]),
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
