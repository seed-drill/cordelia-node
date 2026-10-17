#!/usr/bin/env python3
"""Mutation checks for the test harness of a shared channel: a stand-in
relay and `files_containing` in the harness every real-process test
shares, and a device set up with its relay's key, which replaces the
keyless entry and never names the address twice (decision 2026-10-10
section 13, slice 2 of section 17). A part for each rule of the slice:
put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
COMMON = 'crates/cordelia-node/tests/common/mod.rs'
ORIG = {f: open(f).read() for f in (COMMON,)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
DEVICES = ("cordelia-node", ["--test", "devices_e2e"])
THREATS = ("cordelia-node", ["--test", "threat_model"])
def devices(test): return (DEVICES, test)
def threats(test): return (THREATS, test)

REPLACES = devices("adding_a_relay_that_a_node_names_replaces_its_entry_in_its_place")
KEYED = devices("a_device_set_up_with_its_relays_key_names_its_relay_once_and_reaches_it")
TWICE = devices("the_harness_refuses_to_add_a_relay_that_a_configuration_names_twice")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("H1 a relay the configuration names is added a second time", COMMON,
     '''            Some(at) => config.replace_range(at, &entry),''',
     '''            Some(_) => config.push_str(&format!("\\n{entry}")),''',
     [REPLACES, KEYED]),
    ("H2 the replaced entry moves to the end, out of its place", COMMON,
     '''            Some(at) => config.replace_range(at, &entry),''',
     '''            Some(at) => {
                config.replace_range(at, "");
                config.push_str(&format!("\\n{entry}"));
            }''',
     [REPLACES]),
    ("H3 the old key's line is left behind", COMMON,
     '''    let key_line = if rest.starts_with("key = \\"") {''',
     '''    let key_line = if rest.starts_with("never") {''',
     [REPLACES]),
    ("H4 an address named twice already is not refused", COMMON,
     '''        found.next().is_none(),''',
     '''        true,''',
     [TWICE]),
    ("H5 the keyed device is given no key", COMMON,
     '''    device.add_relay(&format!("127.0.0.1:{}", relay.p2p), Some(&key_of(relay)));''',
     '''    device.add_relay(&format!("127.0.0.1:{}", relay.p2p), None);''',
     [KEYED]),
    ("H6 files_containing finds nothing", COMMON,
     '''                found.push(path);''',
     '''                let _ = path;''',
     [threats("t01_a_relay_holds_nothing_it_can_read")]),
    ("H7 the stand-in's has_room ignores what it is told", COMMON,
     '''        self.script.lock().unwrap().has_room = has_room;''',
     '''        self.script.lock().unwrap().has_room = true;''',
     [threats("t16_a_relays_refusal_is_not_taken_for_delivery")]),
    ("H8 the stand-in takes an entry whatever its room", COMMON,
     '''            let room = script.has_room && script.no_room_in != Some(entry.channel);''',
     '''            let room = script.no_room_in != Some(entry.channel);''',
     [threats("t16_a_relays_refusal_is_not_taken_for_delivery")]),
    ("H9 the stand-in records no stream it is opened", COMMON,
     '''        streams.lock().unwrap().push(protocol);''',
     '''        let _ = (&streams, protocol);''',
     [threats("t19_a_device_asks_no_peer_for_addresses_to_dial")]),
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
