#!/usr/bin/env python3
"""Mutation checks for a relay given no key that is never taken for
another relay (decision 2026-10-17 §1; decision 2026-10-19 §1 and §13):
only the configuration makes two names one relay, and a relay given no
key at another relay's address stays a relay of its own, reached by no
connection there, passed over by the dial loop and never listed as
connected. A part for each rule of the slice: put each fault in, and
confirm the test named for it fails on an assertion. Run from the root
of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
P2P = 'crates/cordelia-node/src/p2p.rs'
BOOTSTRAP = 'crates/cordelia-network/src/bootstrap.rs'
ORIG = {f: open(f).read() for f in (P2P, BOOTSTRAP)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NODE_BIN = ("cordelia-node", ["--bin", "cordelia"])
DEVICES_E2E = ("cordelia-node", ["--test", "devices_e2e"])
def p2p(test): return (NODE_BIN, "p2p::tests::" + test)
def devices(test): return (DEVICES_E2E, test)

OWN = "a_relay_given_no_key_at_another_relays_address_is_a_relay_of_its_own"
OUT = "a_relay_given_no_key_at_another_relays_address_is_passed_over_and_comes_to_be_out_of_reach"
LISTED = "two_relays_at_one_address_are_each_listed_and_a_wrong_key_is_their_own"
ONE = "one_relay_under_two_names_is_one_relay"
DEFAULT = "a_default_relay_named_without_a_key_takes_the_compiled_key"
NEVER_ONE = "a_same_relay_name_is_never_one"
E2E_OWN = "a_relay_given_no_key_at_another_relays_address_is_counted_as_its_own"

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("KR1 a relay given no key at another's address is not told apart", P2P,
     '''            one[i] = OneRelay::KeylessAt(j);''',
     '''            let _ = j;''',
     [p2p(OWN), p2p(ONE)]),
    ("KR2 the connection that answers makes two names one relay, as before", P2P,
     '''                && key == set_up[j].key
                && (key.is_some() || named_alike(i, j))''',
     '''                && ((key.is_some() && key == set_up[j].key)
                    || (peers[i].is_some() && peers[i] == peers[j])
                    || key.is_some_and(|key| peers[j] == Some(NodeId(key))))''',
     [p2p(OWN), devices(E2E_OWN)]),
    ("KR3 the connection at its address is given to it", P2P,
     '''        .map(|(peer, one)| peer.filter(|_| !matches!(one, OneRelay::KeylessAt(_))))''',
     '''        .map(|(peer, _)| peer)''',
     [p2p(OWN)]),
    ("KR4 the dial loop takes it for connected", P2P,
     '''    !at_anothers && connected(relay)''',
     '''    let _ = at_anothers;
    connected(relay)''',
     [p2p(OUT)]),
    ("KR5 the status lists it as connected", P2P,
     '''            let connected = !wrong_key_at && keyless_at.is_none() && connected(relay);''',
     '''            let connected = !wrong_key_at && connected(relay);''',
     [p2p(LISTED)]),
    ("KR6 the status says it is dialled while it is passed over", P2P,
     '''                tried: match wrong_key_at || passed_over {''',
     '''                tried: match wrong_key_at {''',
     [p2p(LISTED)]),
    ("KR7 the status says no reason for it", P2P,
     '''                    Some(other) if passed_over => Some(no_key_at(other)),''',
     '''                    Some(other) if passed_over && other.is_empty() => Some(no_key_at(other)),''',
     [p2p(LISTED)]),
    ("KR8 two names given the same key are no longer one relay", P2P,
     '''                && (key.is_some() || named_alike(i, j))''',
     '''                && key.is_none()
                && named_alike(i, j)''',
     [p2p(ONE), p2p(DEFAULT), p2p(NEVER_ONE)]),
    ("KR9 one name given twice with no key is two relays", P2P,
     '''(key.is_some() || named_alike(i, j))''',
     '''key.is_some()''',
     [p2p(ONE)]),
    ("KR10 a default relay named without a key takes no compiled key", BOOTSTRAP,
     '''                None => default_relay_key(host),''',
     '''                None => None,''',
     [p2p(DEFAULT)]),
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
