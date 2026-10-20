#!/usr/bin/env python3
"""Mutation checks for three small faults: what a device keeps in memory
of its personal channel is let go when it leaves or stops (decision
2026-10-04 §5.2), a node reads that channel ahead once as it starts, and
the bearer token of the local API is compared in constant time. A part
for each rule of the slice: put each fault in, and confirm the test named
for it fails on an assertion. Run from the root of a checkout that
nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
NAMES = 'crates/cordelia-api/src/names.rs'
ADDING = 'crates/cordelia-api/src/adding.rs'
PERSON = 'crates/cordelia-api/src/person.rs'
AUTH = 'crates/cordelia-api/src/auth.rs'
ORIG = {f: open(f).read() for f in (NAMES, ADDING, PERSON, AUTH)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
AT_START = ("cordelia-api", ["--test", "read_ahead_at_start"])
def names(test): return (API, "names::tests::" + test)
def auth(test): return (API, "auth::tests::" + test)
def at_start(test): return (AT_START, test)

FORGETS = names("test_a_device_that_forgets_or_is_removed_keeps_nothing_of_the_channel_it_read")
FORGET_IN_A_READ = names("test_a_read_ahead_that_a_forget_comes_into_keeps_nothing")
AFTER_START = at_start("test_after_start_a_read_under_the_lock_checks_nothing_again")
TOKEN = auth("test_a_token_of_another_length_or_that_differs_in_its_last_byte_is_refused")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("TL1 letting go of what is kept lets go of nothing", NAMES,
     '''pub(crate) fn forget_kept() {
    *KEPT.lock().unwrap_or_else(|e| e.into_inner()) = None;
}''',
     '''pub(crate) fn forget_kept() {}''',
     [FORGETS]),
    ("TL2 a device that leaves its channels keeps what it read of them", ADDING,
     '''    // Nor does it keep in memory what it read of the personal channel.
    crate::names::forget_kept();
''',
     '''''',
     [FORGETS]),
    ("TL3 a device that stops keeps what it read of its channel", PERSON,
     '''    // A device that has stopped keeps nothing in memory of what it read
    // of its personal channel.
    crate::names::forget_kept();
''',
     '''''',
     [FORGETS]),
    ("TL4 a read ahead keeps what it found of a channel the device has left", NAMES,
     '''    if stands_in != Some(*channel) {
        return Ok(());
    }''',
     '''    let _ = stands_in;''',
     [FORGET_IN_A_READ]),
    ("TL5 the read ahead at start reads nothing", NAMES,
     '''        if let Err(e) = read_ahead(&state.db) {''',
     '''        if let Err(e) = Ok::<(), PersonError>(()).map(|()| drop(state)) {''',
     [AFTER_START]),
    ("TL6 the token is compared only as far as the shorter of the two", AUTH,
     '''    bool::from(given.as_bytes().ct_eq(token.as_bytes()))''',
     '''    let n = given.len().min(token.len());
    bool::from(given.as_bytes()[..n].ct_eq(&token.as_bytes()[..n]))''',
     [TOKEN]),
    ("TL7 the last byte of the token is not compared", AUTH,
     '''    bool::from(given.as_bytes().ct_eq(token.as_bytes()))''',
     '''    let (g, t) = (given.as_bytes(), token.as_bytes());
    bool::from(g[..g.len().saturating_sub(1)].ct_eq(&t[..t.len().saturating_sub(1)]))''',
     [TOKEN]),
    ("TL8 a request is let through whatever its token", AUTH,
     '''    if !is_the_token(token, &state.bearer_token) {''',
     '''    if token.is_empty() && !is_the_token(token, &state.bearer_token) {''',
     [TOKEN]),
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
