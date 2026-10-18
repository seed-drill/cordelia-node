#!/usr/bin/env python3
"""Mutation checks for slice 8 of recovery and carrying: the typed
`discard` and a device that has stopped (decision 2026-10-17 §5, §4.4,
the lines of §4.6 and §5.3, properties 5, 8 and 9), and the label of a
row that does not count, by an adder that may be in someone else's
hands (§2.4). A part for each rule of the slice: put each fault in, and
confirm the test named for it fails on an assertion. Run from the root
of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
LET_GO = 'crates/cordelia-api/src/let_go.rs'
SYNC = 'crates/cordelia-api/src/sync.rs'
OWN_READ = 'crates/cordelia-api/src/own_read.rs'
RECOVER = 'crates/cordelia-api/src/recover.rs'
AT_RELAYS = 'crates/cordelia-storage/src/at_relays.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
ORIG = {f: open(f).read() for f in (LET_GO, SYNC, OWN_READ, RECOVER, AT_RELAYS, MAIN)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "carry_e2e"])
STORAGE = ("cordelia-storage", ["--lib"])
def sync(test): return (API, "sync::tests::" + test)
def let_go(test): return (API, "let_go::tests::" + test)
def own_read(test): return (API, "own_read::tests::" + test)
def main(test): return (BIN, "tests::" + test)
def recover_cmd(test): return (BIN, "recover_cmd::tests::" + test)
def e2e(test): return (E2E, test)
def storage(test): return (STORAGE, "at_relays::tests::" + test)

ONLY_READ = sync("test_a_let_go_lets_go_only_of_what_was_read")
STOPPED = sync("test_a_stopped_device_lets_go_at_once_where_its_notes_show_nothing_unsent")
ON_THE_WORD = sync("test_a_carried_name_that_no_relay_holds_is_let_go_only_on_the_word")
STOPPED_FLAG = sync("test_the_answer_to_a_folders_unmapping_says_whether_the_device_has_stopped")
WHERE = let_go("test_where_the_versions_a_discard_lets_go_of_may_still_be")
DAYS = let_go("test_the_days_left_of_the_latest_secret_left")
STOPPED_SAYS = let_go("test_what_a_device_that_has_stopped_says_before_a_discard")
GONE = own_read("test_a_read_kept_no_more_for_its_age_or_its_place_is_known_as_gone")
ON_A_STOPPED = main("test_what_unmap_says_on_a_device_that_has_stopped")
ASKS = main("test_what_unmap_asks_and_says_of_a_discard")
WHILE_READS = main("test_what_unmap_says_while_it_reads")
LABEL = recover_cmd(
    "test_a_row_that_does_not_count_shows_no_label_of_an_adder_in_someone_elses_hands")
OWN_ONLY = storage("test_what_was_sent_to_no_relay_counts_only_this_devices_own_entries")
DISCARD_E2E = e2e("a_carried_name_that_no_relay_takes_is_let_go_on_a_typed_discard")
REMOVED_E2E = e2e("a_removed_device_lets_go_of_a_carried_name_only_on_a_typed_discard")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The word lets go only of what was read (§5.2, property 9) ──
    ("D1 a discard with another number lets go", SYNC,
     """    if !bound || versions != found.not_held.len() {""",
     """    if !bound {""",
     [ONLY_READ, STOPPED]),
    ("D2 a discard after the store took something lets go", SYNC,
     """    let bound = channel == Some(kept.channel) && taken == found.taken;""",
     """    let bound = channel == Some(kept.channel);""",
     [ONLY_READ]),
    ("D3 a discard after the name's channel changed lets go", SYNC,
     """    let bound = channel == Some(kept.channel) && taken == found.taken;""",
     """    let bound = taken == found.taken;""",
     [ONLY_READ]),
    ("D4 a discard is timed by the wall of the call, not the monotonic time given", SYNC,
     """    let Some(kept) = reads.get(read, now) else {
        return Err(match reads.gone(read, now) {""",
     """    let Some(kept) = reads.get(read, std::time::Instant::now()) else {
        return Err(match reads.gone(read, now) {""",
     [ONLY_READ, STOPPED]),
    ("D5 a read too old is said to be one the node never made", SYNC,
     """            true => changed(),
            false => ApiError::Conflict(check::started_again_says(name)),""",
     """            true => ApiError::Conflict(check::started_again_says(name)),
            false => ApiError::Conflict(check::started_again_says(name)),""",
     [ONLY_READ, STOPPED]),
    ("D6 an unknown read is said to be too old", SYNC,
     """            true => changed(),
            false => ApiError::Conflict(check::started_again_says(name)),""",
     """            true => changed(),
            false => changed(),""",
     [ONLY_READ]),
    ("D7 a discard does not end its read", SYNC,
     """    reads.forget(read);
    let held = crate::names::stop(db, &state.identity, name, wall).map_err(refused)?;""",
     """    let held = crate::names::stop(db, &state.identity, name, wall).map_err(refused)?;""",
     [ONLY_READ]),
    ("D8 any word lets go", SYNC,
     """    let (Some(read), Some(versions), "discard") = (read, versions, word) else {""",
     """    let (Some(read), Some(versions), _) = (read, versions, word) else {""",
     [ONLY_READ]),
    ("D9 a discard of a name that no carry holds is looked at", SYNC,
     """    if !crate::names::carried(db).map_err(refused)?.contains(name) {
        return Ok(None);
    }""",
     """    if !crate::names::carried(db).map_err(refused)?.contains(name) && false {
        return Ok(None);
    }""",
     [ON_THE_WORD]),
    ("D10 what a read found is not kept for the word", LET_GO,
     """            reads.found(&read, found.clone(), Instant::now());""",
     """            let _ = &found;""",
     [ON_THE_WORD]),
    ("D11 a read that the node took the place of is not known as gone", OWN_READ,
     """        self.went(replaced.into_iter().collect());""",
     """        let _ = replaced;""",
     [GONE]),
    ("D12 a read that went for its age is not known as gone", OWN_READ,
     """            .filter(|(_, read)| !reads.contains_key(read))""",
     """            .filter(|_| false)""",
     [GONE]),
    ("D13 a read kept no more forgets nothing of its found", OWN_READ,
     """            found: None,
        };""",
     """            found: Some(crate::let_go::Found {
                asked: 0,
                not_held: Vec::new(),
                taken: 0,
            }),
        };""",
     [GONE]),
    # ── At a terminal, and not without one (§5.2, property 5) ──
    ("A1 the command at a terminal is refused as one without", SYNC,
     """                if body.asks && !found.each_held() && carried.contains(name) {""",
     """                if false && body.asks && !found.each_held() && carried.contains(name) {""",
     [ON_THE_WORD]),
    ("A2 a command with no terminal is asked the word", SYNC,
     """                if body.asks && !found.each_held() && carried.contains(name) {""",
     """                if !found.each_held() && carried.contains(name) {""",
     [ON_THE_WORD]),
    ("A3 the answer at a terminal says how to let go at a terminal", LET_GO,
     """pub fn not_held_says(name: &str, not_held: usize, relays: &[String]) -> String {
    format!(
        "{} {}",
        not_held_lines(name, not_held, relays),
        at_a_terminal_says(name, not_held)
    )
}""",
     """pub fn not_held_says(name: &str, not_held: usize, relays: &[String]) -> String {
    not_held_lines(name, not_held, relays)
}""",
     [ON_THE_WORD]),
    ("A4 the command tells the node that it asks, with no terminal", MAIN,
     """                let asked =
                    let_go_round_by_round(&name, at.is_some(), unmap, |line| println!("{line}"))?;""",
     """                let asked = let_go_round_by_round(&name, true, unmap, |line| println!("{line}"))?;""",
     [DISCARD_E2E]),
    ("A5 the command says nothing of asking on the next round", MAIN,
     """        asking = serde_json::json!({ "folder": name, "read": read, "asks": asks });""",
     """        asking = serde_json::json!({ "folder": name, "read": read });""",
     [WHILE_READS]),
    ("A6 Enter lets go", MAIN,
     """    if typed.as_deref() != Some("discard") {""",
     """    if typed.as_deref() == Some("yes") {""",
     [DISCARD_E2E]),
    # ── Where the versions may still be (§5.2, §5.3) ──
    ("W1 the days left are counted down, not up", LET_GO,
     """        (until.saturating_sub(now) + DAY - 1).div_euclid(DAY).max(1)""",
     """        until.saturating_sub(now).div_euclid(DAY).max(1)""",
     [DAYS]),
    ("W2 the days are of the first secret left, not the latest", LET_GO,
     """        .filter_map(|secret| secret.left_at)
        .max();""",
     """        .filter_map(|secret| secret.left_at)
        .min();""",
     [DAYS]),
    ("W3 the node's answer never says a folder keeps its files", LET_GO,
     """    let folder = crate::names::brought_in(conn)?.contains(name);""",
     """    let folder = false;""",
     [ON_THE_WORD]),
    ("W4 the node's answer always counts days", LET_GO,
     """    let days = left_secret_days(conn, now)?;""",
     """    let days = Some(90);""",
     [STOPPED]),
    ("W5 the folder's sentence is not said", LET_GO,
     """        true => format!(
            " A folder that was mapped to {name} keeps its files: what it wrote may still be there."
        ),""",
     """        true => String::new(),""",
     [WHERE]),
    ("W6 what was written here is not said to go for good", LET_GO,
     """since it was carried is on this device alone, and goes for good: this device does not \\""",
     """since it was carried is on this device alone: this device does not \\""",
     [WHERE]),
    ("W7 one version is said as those", LET_GO,
     """        1 => ("that version".to_string(), "it is"),""",
     """        1 => ("those 1 versions".to_string(), "they are"),""",
     [WHERE, STOPPED]),
    # ── A device that has stopped (§4.4, property 8) ──
    ("S1 a device that has stopped lets go at once whatever its notes say", SYNC,
     """                    if let Some((read, found)) = noted {""",
     """                    if let Some((read, found)) = noted.filter(|_| false) {""",
     [STOPPED]),
    ("S2 a device that has stopped asks with no terminal", SYNC,
     """                        if !body.asks {
                            let terminal""",
     """                        if false {
                            let terminal""",
     [STOPPED]),
    ("S3 a device that has stopped reads the relays", SYNC,
     """                if let crate::at_relays::Stands::Stopped(stopped) = stands {""",
     """                if let crate::at_relays::Stands::Stopped(stopped) = stands
                    && false
                {""",
     [STOPPED]),
    ("S4 the notes count another key's entries", LET_GO,
     """    let not_held = kept_rows::places_sent_to_no_relay(conn, &channel, &identity.public_key())?;""",
     """    let not_held = kept_rows::places_sent_to_no_relay(conn, &channel, &[0; 32])?;""",
     [STOPPED]),
    ("S5 the count from the notes is not kept for the word", LET_GO,
     """    reads.found(&read, found.clone(), now);
    Ok(Some((read, found)))""",
     """    Ok(Some((read, found)))""",
     [STOPPED]),
    ("S6 the count from the notes is bound to no place in the store", LET_GO,
     """        taken: kept_rows::last_taken(conn, &channel)?,
    };
    reads.found""",
     """        taken: 0,
    };
    reads.found""",
     [STOPPED]),
    ("S7 a removed device does not say that it was removed", LET_GO,
     """        State::Removed => "it was removed",""",
     """        State::Removed => "it stopped",""",
     [STOPPED, STOPPED_SAYS]),
    ("S8 every device that has stopped says it can be added again", LET_GO,
     """    if matches!(state, State::NotListed | State::NotOpened) {""",
     """    if true {""",
     [STOPPED_SAYS]),
    ("S9 a device that has stopped does not say it cannot read the relays", LET_GO,
     """        "This device has stopped ({why}), and sends nothing more. It cannot read the relays to \\
         learn whether they hold {name}.""",
     """        "This device has stopped ({why}), and sends nothing more. It does not read the relays \\
         for {name}.""",
     [STOPPED_SAYS, STOPPED]),
    ("S10 the places of the notes are in no order", AT_RELAYS,
     """         ORDER BY held.seq",""",
     """         ORDER BY held.seq DESC",""",
     [OWN_ONLY]),
    ("S11 the answer to a folder's unmapping says nothing of a device that has stopped", SYNC,
     """                status.still_held_stopped = stopped;""",
     """                status.still_held_stopped = stopped.map(|_| false);""",
     [STOPPED_FLAG]),
    ("S12 the command's line after a folder's unmapping is a sending device's", MAIN,
     """    if after["still_held_stopped"] == true {""",
     """    if false {""",
     [ON_A_STOPPED]),
    # ── What the command says (§5.3) ──
    ("C1 one version is asked of as them", MAIN,
     """    let them = match not_let_go["versions"].as_u64() {
        Some(1) => "it",""",
     """    let them = match not_let_go["versions"].as_u64() {
        Some(1) => "them",""",
     [ASKS]),
    ("C2 the prompt has no line between what was said and where", MAIN,
     """        "{}\\n\\n{}\\n  Type `discard` to let {} go with {them}. Anything else keeps it: ",""",
     """        "{}\\n{}\\n  Type `discard` to let {} go with {them}. Anything else keeps it: ",""",
     [ASKS]),
    ("C3 the others are never said to keep theirs", MAIN,
     """        false => " Your other devices keep what they hold of it.",
    };
    format!(
        "This device holds {} no longer, and {went} with it.{others}",""",
     """        false => "",
    };
    format!(
        "This device holds {} no longer, and {went} with it.{others}",""",
     [ASKS]),
    ("C4 another word says nothing was changed of another name", MAIN,
     """    format!("{} is still held. Nothing was changed.", sync_label(name))""",
     """    format!("{} is still held.", sync_label(name))""",
     [ASKS]),
    # ── The label of a row by an adder in someone else's hands (§2.4) ──
    ("L1 a row that does not count shows its adder's label", RECOVER,
     """        let adders_hands = !row.counts
            && row.added_by""",
     """        let adders_hands = false
            && row.added_by""",
     [LABEL]),
    ("L2 a row that counts hides its label too", RECOVER,
     """        let adders_hands = !row.counts
            && row.added_by""",
     """        let adders_hands = true
            && row.added_by""",
     [LABEL]),
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
