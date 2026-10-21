#!/usr/bin/env python3
"""Mutation checks for slice 5 of a relay out of reach: the status line
of a relay not known to hold the latest change and of a relay out of
reach, with what the node counts for it (for how long a relay has lacked
the change, when the device woke, and when its seven days begin); the
relay lines of `cordelia devices` and of a status (decision 2026-10-19,
rules 11 and 12; §5, D2 to D5 and T1 to T3). A part for each rule of the
slice: put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
LOOK = 'crates/cordelia-api/src/look.rs'
REACH = 'crates/cordelia-node/src/device_entries/reach.rs'
LEAVE = 'crates/cordelia-node/src/device_entries/leave.rs'
ENTRIES = 'crates/cordelia-node/src/device_entries.rs'
INDICATOR = 'crates/cordelia-node/src/indicator.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
CMD = 'crates/cordelia-node/src/person_cmd.rs'
ORIG = {f: open(f).read() for f in (LOOK, REACH, LEAVE, ENTRIES, INDICATOR, MAIN, CMD)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
NODE = ("cordelia-node", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
DEVICE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def look(test): return (API, "look::tests::" + test)
def reach(test): return (NODE, "device_entries::reach::tests::" + test)
def indicator(test): return (BIN, "indicator::tests::" + test)
def main(test): return (BIN, "tests::" + test)
def cmd(test): return (BIN, "person_cmd::tests::" + test)
def device(test): return (DEVICE_E2E, test)

COUNTS = reach("what_the_status_line_counts_of_a_relay_that_lacks_the_change")
WAKE = device("a_wake_after_no_connection_does_not_restart_the_ambers_five_minutes")
WOKE = device("the_status_says_when_the_device_woke")
CARRIED = look("the_look_carries_word_to_come_and_each_relays_reach")
SAID = look("test_what_the_node_says_of_its_relays_is_said")
SEVEN_FROM = look("the_seven_days_run_from_the_later_of_the_two_times")
T_WORDS = look("each_line_word_for_word")
AMBER = indicator("a_relay_that_lacks_the_change_is_amber_connected_or_not_with_sync_on_or_off")
SEVEN = indicator("for_seven_days_and_then_not")
PLACE = indicator("its_place_is_after_names_carried")
OUT = indicator("a_relay_out_of_reach_is_amber_last_only_with_folders_and_only_with_one_reached")
THIRD = main("a_relay_in_the_third_state_is_not_amber")
FACTS = main("test_what_a_status_goes_by_of_a_persons_devices")
D_LINES = cmd("each_relay_line_by_its_case")


def between(f, start, end):
    """The text of `f` from `start` up to `end`, which is left out."""
    text = ORIG[f]
    at = text.index(start)
    return text[at:text.index(end, at)]


# The amber of a relay not known to hold the change, and of a relay out
# of reach, as blocks that two parts move.
NOT_KNOWN_BLOCK = between(INDICATOR, "        // A relay that lacks the change, connected or not: nothing else",
                          "    }\n    if !of_folders {")
OUT_BLOCK = between(INDICATOR, "    // The warning of the ruling", "    out\n}\n\n/// What the facts take")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── What the node counts of a relay that lacks the change (rule 11) ─
    ("R1 a relay that held the change counts from the reference, not from when it came to lack it", REACH,
     '''                    .map_or(common.at, |since| since.at.max(common.at));''',
     '''                    .map_or(common.at, |_| common.at);''',
     [COUNTS]),
    ("R2 a sleep does not count again", REACH,
     '''                    .map_or(common.at, |since| since.at.max(common.at));''',
     '''                    .map_or(common.at, |since| since.at);''',
     [COUNTS, WAKE]),
    ("R3 being reached counts again", REACH,
     '''                    .map_or(common.at, |since| since.at.max(common.at));''',
     '''                    .map_or(of.reference(common).at, |since| since.at.max(of.reference(common).at));''',
     [COUNTS]),
    ("R4 a relay in the third state is counted", REACH,
     '''            let lacking_secs = (holds == Holds::Lacks).then(|| {''',
     '''            let lacking_secs = (holds != Holds::Holds).then(|| {''',
     [COUNTS]),
    ("R5 the status carries nothing of it", REACH,
     '''                lacking_secs,
                class: class(holds, reached, out, waits, refused_long),''',
     '''                lacking_secs: None,
                class: class(holds, reached, out, waits, refused_long),''',
     [COUNTS, WAKE]),

    # ── When the device woke (§5, D2 and T1) ────────────────────────
    ("W1 the wake is said a minute early", LEAVE,
     '''            .map(|woke| woke.wall)''',
     '''            .map(|woke| woke.wall - 60)''',
     [WOKE]),
    ("W2 with no relay reached, no time is said", LEAVE,
     '''            .or(inner.unwoken_since)''',
     '''            .or(None)''',
     [WOKE]),
    ("W3 the pass that finds no connection is not noted", LEAVE,
     '''            if inner.woke.take().is_some() {
                inner.unwoken_since = Some(wall);
            }''',
     '''            inner.woke = None;''',
     [WOKE]),
    ("W4 a sleep is not noted", LEAVE,
     '''        if slept || inner.last.is_none() {''',
     '''        if inner.last.is_none() {''',
     [WOKE]),
    ("W5 the start is not noted", LEAVE,
     '''        if slept || inner.last.is_none() {''',
     '''        if slept {''',
     [WOKE]),
    ("W6 the node does not say when it woke", ENTRIES,
     '''            woke_at: self.leave.woke_at(),''',
     '''            woke_at: None,''',
     [WOKE]),

    # ── The look (rule 11, §5) ──────────────────────────────────────
    ("K1 the look does not carry the wake", LOOK,
     '''            woke_at: at_relays.woke_at,''',
     '''            woke_at: None,''',
     [SAID]),
    ("K2 the look does not carry the start of the seven days", LOOK,
     '''            relays_known_since: relays_known_since(conn, now)?,''',
     '''            relays_known_since: None,''',
     [CARRIED]),
    ("K3 the seven days run from an entry noted before the one kept", LOOK,
     '''        (Some(entry), Some(noted)) if noted.entry == entry => Some(noted.since),''',
     '''        (Some(_), Some(noted)) => Some(noted.since),''',
     [SEVEN_FROM]),
    ("K4 an entry not yet noted has no time", LOOK,
     '''        (Some(_), _) => Some(now),''',
     '''        (Some(_), _) => None,''',
     [SEVEN_FROM, CARRIED]),
    ("K5 the earlier of the two times", LOOK,
     '''    Ok(kept_since.max(known.first_started))''',
     '''    Ok(kept_since.min(known.first_started))''',
     [SEVEN_FROM]),
    ("K6 the look does not carry how long a relay has lacked the change", LOOK,
     '''                lacking_secs: relay.reach.lacking_secs,''',
     '''                lacking_secs: None,''',
     [CARRIED]),
    ("K7 the look does not carry when a relay answered", LOOK,
     '''                answered_at: relay.reach.answered_at,''',
     '''                answered_at: None,''',
     [CARRIED]),

    # ── T1 to T3 (§5) ───────────────────────────────────────────────
    ("T1 a relay out of reach that lacks the change and was not heard since the wake is T1", LOOK,
     '''        if out && self.reach.holds == Holds::Lacks {''',
     '''        if self.heard_since_woke && out && self.reach.holds == Holds::Lacks {''',
     [T_WORDS]),
    ("T2 a relay out of reach that holds the change and was not heard since the wake is T1", LOOK,
     '''        } else if out && self.reach.holds == Holds::Holds {''',
     '''        } else if self.heard_since_woke && out && self.reach.holds == Holds::Holds {''',
     [T_WORDS]),
    ("T3 a relay in the third state out of reach is T2", LOOK,
     '''        if out && self.reach.holds == Holds::Lacks {''',
     '''        if out && self.reach.holds != Holds::Holds {''',
     [T_WORDS]),
    ("T4 T1 says no time", LOOK,
     '''            let at = woke_at.map(|at| format!(" at {}", when(at, now)));''',
     '''            let at: Option<String> = woke_at.map(|_| String::new());''',
     [T_WORDS, SAID]),
    ("T9 what is known of a relay about the entry before is said of this one", LOOK,
     '''        latest.is_some()
            && self.reach.about.as_deref() == latest
            && self.reach.out_of_reach_since.is_some()''',
     '''        self.reach.out_of_reach_since.is_some()''',
     [T_WORDS]),
    ("T5 out of reach is read as reached", LOOK,
     '''            && self.reach.out_of_reach_since.is_some()
    }''',
     '''            && self.reach.reached
    }''',
     [T_WORDS]),
    ("T6 T2 says that the relay does not hold the change", LOOK,
     '''                "{} is not known to hold the latest change, and {}",''',
     '''                "{} does not hold the latest change, and {}",''',
     [T_WORDS]),
    ("T7 T3 leaves out how this device sends", LOOK,
     '''                "{} {}: this device sends through the others",''',
     '''                "{} {}",''',
     [T_WORDS]),
    ("T8 T1 says the relay was off", LOOK,
     '''                "has not heard from {} since it started or woke{}: a change made while this \\
                 device was off may be there, and not have reached it",''',
     '''                "has not heard from {} since it started or woke{}: a change made while it \\
                 was off may not have reached it",''',
     [T_WORDS, SAID]),

    # ── The status line (rule 11) ───────────────────────────────────
    ("I1 the seven days are not kept", INDICATOR,
     '''            _ if !still_shown => {}''',
     '''            _ if still_shown && false => {}''',
     [SEVEN]),
    ("I2 the seventh day is not shown", INDICATOR,
     '''            .is_none_or(|secs| secs <= RELAY_NOT_KNOWN_SHOWN_SECS);''',
     '''            .is_none_or(|secs| secs < RELAY_NOT_KNOWN_SHOWN_SECS);''',
     [SEVEN]),
    ("I3 a node that does not say since when is not shown", INDICATOR,
     '''            .is_none_or(|secs| secs <= RELAY_NOT_KNOWN_SHOWN_SECS);''',
     '''            .is_some_and(|secs| secs <= RELAY_NOT_KNOWN_SHOWN_SECS);''',
     [SEVEN]),
    ("I4 fourteen days", INDICATOR,
     '''const RELAY_NOT_KNOWN_SHOWN_SECS: u64 = REMOVAL_SHOWN_SECS;''',
     '''const RELAY_NOT_KNOWN_SHOWN_SECS: u64 = REMOVAL_SHOWN_SECS * 2;''',
     [SEVEN]),
    ("I5 no five minutes", INDICATOR,
     '''        let lacking = d.not_known_to_hold_secs.iter().filter(|secs| long(secs));''',
     '''        let lacking = d.not_known_to_hold_secs.iter().filter(|_| true);''',
     [AMBER]),
    ("I6 only with sync on, a folder mapped and a report", INDICATOR,
     '''        let still_shown = d
            .known_since_secs''',
     '''        let still_shown = of_folders
            && d.known_since_secs''',
     [AMBER]),
    ("I7 several are said as one", INDICATOR,
     '''                format!("memory: {n} relays not known to hold the latest change"),''',
     '''                "memory: a relay not known to hold the latest change".into(),''',
     [AMBER]),
    ("I8 it comes first among the amber of a person's devices", INDICATOR,
     [NOT_KNOWN_BLOCK, '''        if d.removal_not_applied_secs'''],
     ['', NOT_KNOWN_BLOCK + '''        if d.removal_not_applied_secs'''],
     [PLACE]),
    ("I9 a relay out of reach is amber with none reached", INDICATOR,
     '''        _ if !d.one_reached => {}''',
     '''        _ if d.one_reached && false => {}''',
     [OUT]),
    ("I10 a relay out of reach is amber without folders", INDICATOR,
     [OUT_BLOCK, '''    if !of_folders {
        return out;
    }'''],
     ['', OUT_BLOCK + '''    if !of_folders {
        return out;
    }'''],
     [OUT]),
    ("I11 a relay out of reach comes before names", INDICATOR,
     [OUT_BLOCK, '''    let shown_still = |secs: &u64|'''],
     ['', OUT_BLOCK + '''    let shown_still = |secs: &u64|'''],
     [OUT]),
    ("I12 its minutes are half minutes", INDICATOR,
     '''                secs / 60,
                plural(secs / 60, "minute")''',
     '''                secs / 30,
                plural(secs / 30, "minute")''',
     [OUT]),

    # ── What the status takes from the look (rule 11) ───────────────
    ("M1 a relay in the third state is counted", MAIN,
     '''            .filter(|relay| relay["reach"]["holds"] == "lacks")''',
     '''            .filter(|relay| relay["reach"]["holds"] != "holds")''',
     [THIRD]),
    ("M2 how long it has been connected, not how long it has lacked the change", MAIN,
     '''            .filter_map(|relay| relay["reach"]["lacking_secs"].as_u64())''',
     '''            .filter_map(|relay| relay["connected_secs"].as_u64())''',
     [FACTS]),
    ("M3 a relay out of reach that lacks the change is the warning's", MAIN,
     '''            .filter(|relay| relay["reach"]["class"] == "out_holding")''',
     '''            .filter(|relay| relay["reach"]["class"] == "out_lacking")''',
     [FACTS]),
    ("M4 every relay must be reached", MAIN,
     '''        one_reached: list("relays").any(|relay| relay["reach"]["reached"] == true),''',
     '''        one_reached: list("relays").all(|relay| relay["reach"]["reached"] == true),''',
     [FACTS]),
    ("M5 the seven days are not read", MAIN,
     '''        known_since_secs: ago(&person["relays_known_since"]),''',
     '''        known_since_secs: None,''',
     [FACTS]),

    # ── `cordelia devices`, of each relay (rule 12) ─────────────────
    ("C1 a relay out of reach not heard since the wake is D3, not D4 or D5", CMD,
     '''    match out {
        Some(reach) if reach.holds == Holds::Lacks => {''',
     '''    match out.filter(|_| relay["heard_since_woke"] == true) {
        Some(reach) if reach.holds == Holds::Lacks => {''',
     [D_LINES]),
    ("C2 no D3", CMD,
     '''        (false, _) if out.is_some() => format!(''',
     '''        (false, _) if false => format!(''',
     [D_LINES]),
    ("C9 what is known of a relay about the entry before is said of this one", CMD,
     '''        latest.is_some() && reach.about.as_deref() == latest && reach.out_of_reach_since.is_some()''',
     '''        reach.out_of_reach_since.is_some()''',
     [D_LINES]),
    ("C3 D5 says not when the relay said it", CMD,
     '''                .map(|at| format!(" (as it said at {})", when(at, now)))''',
     '''                .map(|_| String::new())''',
     [D_LINES]),
    ("C4 what waits is said after a line of sentences", CMD,
     '''            Some(still) if holds.ends_with('.') => {''',
     '''            Some(still) if false => {''',
     [D_LINES]),
    ("C5 D2 says no time", CMD,
     '''    let woke = woke_at
        .map(|at| format!(" at {}", when(at, now)))''',
     '''    let woke = woke_at
        .map(|_| String::new())''',
     [D_LINES]),
    ("C6 the wake is not read from the look", CMD,
     '''    let woke_at = seen["woke_at"].as_i64();''',
     '''    let woke_at: Option<i64> = None;''',
     [D_LINES]),
    ("C7 D4 leaves out that the relay may serve another device", CMD,
     '''                 only because this machine cannot reach it: it may still serve a device that \\
                 does.",''',
     '''                 only because this machine cannot reach it.",''',
     [D_LINES]),
    ("C8 D2 says the relay was off", CMD,
     '''            "has not answered since this device started or woke{woke}. A change made while \\
             this device was off may be there, and not have reached it."''',
     '''            "has not answered since this device woke{woke}: a change made while it was off \\
             may not have reached it"''',
     [D_LINES]),
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
