#!/usr/bin/env python3
"""Mutation checks for eight small fixes: a command that opens the database
asks the data directory's lock (decision 2026-10-04 §10.1, rule 6), the
data directory's mode (configuration.md §5.4), "not heard from yet" and a
relay with no key in `cordelia devices` (§8), "already brought back"
(§7.3), the first start's log line (§5.2, §10.1), and the one sentence
that says how the node is started. A part for each rule of the slice: put
each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
MAIN = 'crates/cordelia-node/src/main.rs'
PERSON_CMD = 'crates/cordelia-node/src/person_cmd.rs'
CARRYING = 'crates/cordelia-api/src/carrying.rs'
CARRY = 'crates/cordelia-api/src/carry.rs'
FIRST_START = 'crates/cordelia-api/src/first_start.rs'
COMMANDS = 'crates/cordelia-api/src/commands.rs'
ORIG = {f: open(f).read() for f in (MAIN, PERSON_CMD, CARRYING, CARRY, FIRST_START, COMMANDS)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
BIN = ("cordelia-node", ["--bin", "cordelia"])
API = ("cordelia-api", ["--lib"])
def main(test): return (BIN, "tests::" + test)
def person_cmd(test): return (BIN, "person_cmd::tests::" + test)
def api(module, test): return (API, module + "::tests::" + test)
def e2e(file, test): return (("cordelia-node", ["--test", file]), test)

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("F1a a command takes the lock for nobody's, and opens the database beside its node", MAIN,
     '''        Ok(file) => lock_tried(file.try_lock()) == Lock::AnotherNode,''',
     '''        Ok(file) => lock_tried(file.try_lock()) == Lock::AnotherNode && file.metadata().is_err(),''',
     [main("test_a_command_asks_the_lock_on_the_data_directory"),
      e2e("person_e2e", "a_command_that_opens_the_database_asks_the_data_directorys_lock"),
      e2e("first_start_e2e", "swarm_init_writes_nothing_beside_a_node_that_runs_on_its_data_directory")]),
    ("F1b a command reads beside a node of another version", MAIN,
     '''    if found != own {''',
     '''    if found != own && own == 0 {''',
     [main("test_a_command_asks_the_lock_on_the_data_directory"),
      e2e("person_e2e", "a_command_that_opens_the_database_asks_the_data_directorys_lock")]),
    ("F1c a command asks the port again, and refuses beside a node on another directory", MAIN,
     '''    let data_dir = config.data_dir();
    let db_path = data_dir.join("cordelia.db");
    if !a_node_holds(&data_dir) {''',
     '''    let data_dir = config.data_dir();
    let db_path = data_dir.join("cordelia.db");
    if let Ok(node) = local_api(config, false, "/api/v1/status", VERSION_ASKED_FOR)
        && let Some(note) = version_note(node["version"].as_str(), env!("CARGO_PKG_VERSION"))
    {
        anyhow::bail!("{note}");
    }
    if !a_node_holds(&data_dir) {''',
     [e2e("person_e2e", "a_command_that_opens_the_database_asks_the_data_directorys_lock")]),
    ("F2 swarm-init makes its data directory at the default mode", MAIN,
     '''    if let Some(says) = private_data_dir(&data_dir, owners_alone)? {
        eprintln!("{says}");
    }
    let identity_path''',
     '''    std::fs::create_dir_all(&data_dir)?;
    let identity_path''',
     [e2e("first_start_e2e", "swarm_init_makes_its_data_directory_its_owners_alone")]),
    ("F3a a directory shared with its group is taken for one open to others", MAIN,
     '''found.permissions().mode() & 0o007 != 0)''',
     '''found.permissions().mode() & 0o077 != 0)''',
     [main("test_a_node_that_starts_keeps_its_data_directory_private"),
      main("test_init_goes_on_where_the_data_directory_cannot_be_made_private"),
      e2e("first_start_e2e", "a_node_that_starts_makes_its_data_directory_its_owners_alone")]),
    ("F3b init sets a directory that is there whatever its mode", MAIN,
     '''    if there && !open_to_others(dir) {''',
     '''    if there && !open_to_others(dir) && !there {''',
     [main("test_init_goes_on_where_the_data_directory_cannot_be_made_private")]),
    ("F4a a time another device wrote holds the advice back", PERSON_CMD,
     '''    took || (added_here && device["at"].as_i64().is_some_and(just))''',
     '''    took || ((added_here || !added_here) && device["at"].as_i64().is_some_and(just))''',
     [person_cmd("a_device_not_heard_from_just_after_it_was_added_is_said_to_be_only_that"),
      e2e("person_e2e", "not_heard_from_yet_runs_only_from_a_time_of_this_devices_own")]),
    ("F4b a time ahead of this device's clock holds the advice back", PERSON_CMD,
     '''            .is_some_and(|ago| (0..STATUS_AMBER_WAIT_SECS as i64).contains(&ago))''',
     '''            .is_some_and(|ago| ago.unsigned_abs() < STATUS_AMBER_WAIT_SECS)''',
     [person_cmd("a_device_not_heard_from_just_after_it_was_added_is_said_to_be_only_that")]),
    ("F5 a relay with no key is matched by its name alone", PERSON_CMD,
     '''    let found_at: Vec<Vec<String>> = match waiting.iter().any(unnamed) {''',
     '''    let found_at: Vec<Vec<String>> = match waiting.iter().any(unnamed) && relays.is_empty() {''',
     [person_cmd("devices_lists_a_relay_with_no_key_once"),
      e2e("memory_e2e", "a_relay_set_up_with_no_key_is_one_line_in_devices")]),
    ("F6a a version under any higher revision is brought back", CARRYING,
     '''            carry::Brought::Higher if carry::later_by_its_author(conn, name, version)? => held += 1,''',
     '''            carry::Brought::Higher => held += 1,''',
     [api("carrying", "test_a_version_under_another_keys_later_revision_is_not_brought_back"),
      e2e("carry_e2e", "what_a_removed_device_wrote_comes_in_only_by_from_with_the_phrase")]),
    ("F6b a later revision carried from the same author is not its own", CARRY,
     '''                authors.contains(&entry.author) || authors.iter().any(carried_from)''',
     '''                authors.contains(&entry.author) || (authors.iter().any(carried_from) && authors.is_empty())''',
     [api("carrying", "test_a_version_under_another_keys_later_revision_is_not_brought_back")]),
    ("F7 the first start's line names two ways on", FIRST_START,
     '''        "first start on this version: the database was copied and moved on; this device is {}",
        look::NOT_ADDED.replace("\\n  - ", " ")''',
     '''        "first start on this version: the database was copied and moved on; this device \\
         follows no recovery phrase, and is added again with `cordelia phrase` here or \\
         `cordelia accept`{}",
        &look::NOT_ADDED[..0]''',
     [api("first_start", "the_line_of_a_first_start_names_the_ways_on_as_the_status_does"),
      e2e("devices_e2e", "a_swarm_channel_an_earlier_version_made_is_removed_when_the_node_starts")]),
    ("F8 the sentence that starts the node names `cordelia start` alone", COMMANDS,
     '''        "Start it with `{}`, or with `cordelia start` where it does not run as the service \\
         that the install script set up.",
        start_command(os)''',
     '''        "Start it with `cordelia start`.{}",
        &start_command(os)[..0]''',
     [api("commands", "test_the_sentence_that_starts_a_node_names_the_service_of_each_system"),
      main("test_every_sentence_that_starts_the_node_names_the_service"),
      e2e("devices_e2e", "cli_reports_when_the_node_is_not_running"),
      e2e("msg_e2e", "log_outside_a_terminal_shows_only_the_folders_agent")]),
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
