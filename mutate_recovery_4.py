#!/usr/bin/env python3
"""Mutation checks for slice 4 of the recovery and carrying record: a read
through the carry door takes a place to start from at each relay, and
gives back the place it reached there (decision 2026-10-17 §3.2): in
`DeviceEntries::read_left`, the door's `DoorAsk::Read`, `read_with_proofs`
and `POST /api/v1/carry/read`. A part for each rule of the slice: put each
fault in, and confirm the test named for it fails on an assertion. Run
from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
ENTRIES = 'crates/cordelia-node/src/device_entries.rs'
CARRYING = 'crates/cordelia-api/src/carrying.rs'
STATE = 'crates/cordelia-api/src/state.rs'
ORIG = {f: open(f).read() for f in (ENTRIES, CARRYING, STATE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NODE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
API = ("cordelia-api", ["--lib"])
def e2e(test): return (NODE_E2E, test)
def api(test): return (API, "carrying::tests::" + test)

GOES_ON = e2e("a_read_of_a_left_channel_goes_on_from_a_place")
FROM_THE_START = e2e("the_door_for_a_carry_proves_and_pulls_and_does_nothing_else")
SAYS = api("test_a_read_with_proofs_says_the_place_it_reached_at_each_relay")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("RP1 read_left reads from the start whatever place it is given", ENTRIES,
     '''let mut place = (from.mark, from.next);''',
     '''let mut place = (NO_MARK, 0u64);''',
     [GOES_ON]),
    ("RP2 read_left starts from the place's count under no mark", ENTRIES,
     '''let mut place = (from.mark, from.next);''',
     '''let mut place = (NO_MARK, from.next);''',
     [GOES_ON]),
    ("RP3 read_left starts from the place's mark at the start", ENTRIES,
     '''let mut place = (from.mark, from.next);''',
     '''let mut place = (from.mark, 0u64);''',
     [GOES_ON]),
    ("RP4 a read given no place begins elsewhere than the start", STATE,
     '''        mark: cordelia_storage::relay::NO_MARK,
        next: 0,
    };''',
     '''        mark: cordelia_storage::relay::NO_MARK,
        next: 1,
    };''',
     [FROM_THE_START]),
    ("RP5 the door reads every relay from the start", ENTRIES,
     '''let place = from.get(&name).copied().unwrap_or(LeftPlace::START);''',
     '''let place = LeftPlace::START;''',
     [GOES_ON]),
    ("RP6 a read whose time has gone says the start as its place", ENTRIES,
     '''                    whole: false,
                    reached: reached(place),
                };
            }
            if !self.room_to_take(link) {''',
     '''                    whole: false,
                    reached: LeftPlace::START,
                };
            }
            if !self.room_to_take(link) {''',
     [GOES_ON]),
    ("RP7 a page of nothing of the channel says the place after it", ENTRIES,
     '''                            whole: false,
                            reached: reached(place),
                        };
                    }
                    // A page that holds nothing''',
     '''                            whole: false,
                            reached: reached((mark, next)),
                        };
                    }
                    // A page that holds nothing''',
     [GOES_ON]),
    ("RP8 a read to the end says the place asked, not the relay's", ENTRIES,
     '''reached: reached((mark, next)),''',
     '''reached: reached(place),''',
     [GOES_ON]),
    ("RP9 a read stopped by no answer says the start as its place", ENTRIES,
     '''                        whole: false,
                        reached: reached(place),
                    };
                }
            }''',
     '''                        whole: false,
                        reached: LeftPlace::START,
                    };
                }
            }''',
     [GOES_ON]),
    ("RP10 read_with_proofs reads from the start whatever it is given", CARRYING,
     '''let at = read_at_relays_from(state, channel, by, &from, until).await;''',
     '''let at = read_at_relays_from(state, channel, by, &HashMap::new(), until).await;''',
     [SAYS]),
    ("RP11 the asking of the door carries no place", CARRYING,
     '''        from: from.clone(),
        until,''',
     '''        from: HashMap::new(),
        until,''',
     [SAYS]),
    ("RP12 a connection made again reads from the start", CARRYING,
     '''asks_to_read(state, channel, by.clone(), Some(remade), from, until).await''',
     '''asks_to_read(state, channel, by.clone(), Some(remade), &HashMap::new(), until).await''',
     [SAYS]),
    ("RP13 the answer says no place reached", CARRYING,
     '''    let reached = places_reached(&at);''',
     '''    let reached: Vec<serde_json::Value> = Vec::new();''',
     [SAYS]),
    ("RP14 the place said is the start, not the place reached", CARRYING,
     '''"place": reached.next,''',
     '''"place": 0,''',
     [SAYS]),
    ("RP15 the mark said is no mark", CARRYING,
     '''"mark": hex::encode(reached.mark),''',
     '''"mark": hex::encode(LeftPlace::START.mark),''',
     [SAYS]),
    ("RP16 a relay where nothing was read is said to have a place", CARRYING,
     '''                "place": reached.next,
            })),
            _ => None,''',
     '''                "place": reached.next,
            })),
            _ => Some(json!({ "relay": at.relay, "mark": "", "place": 0 })),''',
     [SAYS]),
    ("RP17 the route drops the places it is handed", CARRYING,
     '''        from.insert(place.relay.clone(), at);''',
     '''        let _ = (&place.relay, at);''',
     [SAYS]),
    ("RP18 the route takes the place under no mark", CARRYING,
     '''        let at = LeftPlace {
            mark,
            next: place.place,
        };''',
     '''        let at = LeftPlace {
            mark: LeftPlace::START.mark,
            next: place.place,
        };''',
     [SAYS]),
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
