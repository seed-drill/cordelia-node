#!/usr/bin/env python3
"""Mutation checks for sync turned off and on again, which is to a folder
that stays mapped what a node stopped and started is: it keeps what it
agreed, and an edit made here meanwhile is sent with no conflict file
(the record of 2026-09-30, section 4.5, "A folder that stops syncing
starts afresh" and "A command that stops a folder syncing has stopped it
when it answers"). A part for each rule of the slice: put each fault
in, and confirm the test named for it fails on an assertion. Run from
the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
SYNC = 'crates/cordelia-api/src/sync.rs'
ORIG = {f: open(f).read() for f in (SYNC,)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
ADAPTER = ("cordelia-sync", ["--lib"])
def api(test): return (API, "sync::tests::" + test)
def adapter(test): return (ADAPTER, "claude::tests::" + test)
INTEGRATION = ("cordelia-sync", ["--test", "claude"])
def integration(test): return (INTEGRATION, test)

STOPPED = api("test_a_folder_that_is_stopped_forgets_what_it_agreed")
DIRECTORY = api("test_only_an_unmapping_and_a_change_of_directory_forget")
ON_AGAIN = adapter("a_folder_turned_off_and_on_again_sends_what_was_edited_while_off")
DELETED = integration("mapping_a_folder_again_does_not_replay_what_it_lost")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("SO1 turning sync off forgets what every folder agreed, as it did", SYNC,
     '''        // Nothing syncs now. A mapped folder keeps what it agreed, as it''',
     '''        sync_state::forget_folders_except(db, &[])?;
        // Nothing syncs now. A mapped folder keeps what it agreed, as it''',
     [STOPPED, ON_AGAIN, DELETED]),
    ("SO2 turning sync on from off forgets what every folder agreed, as it did", SYNC,
     '''        let dir_changed = was.as_deref().is_none_or(|was| was != dir);''',
     '''        let dir_changed = stored.is_none() || was.as_deref().is_none_or(|was| was != dir);''',
     [STOPPED, ON_AGAIN, DELETED]),
    ("SO3 turning sync on keeps what a folder unmapped while it was off agreed", SYNC,
     '''        } else if unmapped || stored.is_none() {''',
     '''        } else if unmapped {''',
     [STOPPED]),
    ("SO4 turned on at another directory than the one sync was last on, the folders keep what they agreed", SYNC,
     '''        let dir_changed = was.as_deref().is_none_or(|was| was != dir);''',
     '''        let dir_changed = stored.as_deref().is_some_and(|was| was != dir) || was.is_none();''',
     [DIRECTORY]),
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
