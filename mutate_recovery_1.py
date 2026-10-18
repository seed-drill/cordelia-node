#!/usr/bin/env python3
"""Mutation checks for the count before a yes, which counts only this
device's own entries as sent to no relay (decision 2026-10-17 §4.5,
property 12; slice 1 of section 10). A part for each rule of the slice:
put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
AT_RELAYS = 'crates/cordelia-storage/src/at_relays.rs'
NAMES = 'crates/cordelia-api/src/names.rs'
ORIG = {f: open(f).read() for f in (AT_RELAYS, NAMES)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
STORAGE = ("cordelia-storage", ["--lib"])
API = ("cordelia-api", ["--lib"])
def storage(test): return (STORAGE, "at_relays::tests::" + test)
def names(test): return (API, "names::tests::" + test)
def sync(test): return (API, "sync::tests::" + test)

OWN_ONLY = storage("test_what_was_sent_to_no_relay_counts_only_this_devices_own_entries")
COUNTED = storage("test_what_no_relay_was_sent_of_a_channel_is_counted")
EVERY_NAME = names("test_what_was_sent_to_no_relay_is_counted_over_every_name_held")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("R1A the count takes in every author's entries", AT_RELAYS,
     '''WHERE held.channel_id = ?1 AND held.author = ?3''',
     '''WHERE held.channel_id = ?1 AND ?3 = ?3''',
     [OWN_ONLY, EVERY_NAME]),
    ("R1B the count takes in every author's but the device's own", AT_RELAYS,
     '''WHERE held.channel_id = ?1 AND held.author = ?3''',
     '''WHERE held.channel_id = ?1 AND held.author != ?3''',
     [OWN_ONLY, COUNTED, EVERY_NAME]),
    ("R2 the count before a yes is asked of another key than the device's", NAMES,
     '''let waits = kept_rows::sent_to_no_relay(conn, &held.channel, &own)?;''',
     '''let waits = kept_rows::sent_to_no_relay(conn, &held.channel, &[0; 32])?;''',
     [EVERY_NAME]),
    ("R3 the check on an unmapping is asked of another key than the device's", NAMES,
     '''        &identity.public_key(),
    )?)''',
     '''        &[0; 32],
    )?)''',
     [EVERY_NAME,
      sync("test_a_folders_unmapping_does_not_let_go_of_a_name_that_a_carry_holds"),
      sync("test_a_name_that_a_carry_holds_with_no_folder_is_let_go")]),
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
