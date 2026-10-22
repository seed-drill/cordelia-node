#!/usr/bin/env python3
"""Mutation checks for what a relay holds across a wait and the bounds of a
page's header: each field of an ItemHeader read within its size (a header with a
text over its size refused, and its page gone through), a fetch
of the older kind that drops its page before it fetches the page's entries
and lets each channel go once gone through, and a stream of entries that
holds only the written answer through its write (parameter-rationale.md
section 1). A part for each rule of the slice: put each fault in, and
confirm the test named for it fails on an assertion. Run from the root of
a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
MESSAGES = 'crates/cordelia-network/src/messages.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
RELAY = 'crates/cordelia-node/src/relay_entries.rs'
ORIG = {f: open(f).read() for f in (MESSAGES, P2P, RELAY)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NETWORK = ("cordelia-network", ["--lib"])
COST = ("cordelia-network", ["--test", "decode_cost"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
def network(test): return (NETWORK, "messages::tests::" + test)
def cost(test): return (COST, test)
def p2p(test): return (NODE, "p2p::tests::" + test)
def relay(test): return (NODE, "relay_entries::tests::" + test)

HEADER = network("a_header_with_a_field_past_its_bound_is_refused_where_it_is_read")
PAGE_COST = cost("a_page_of_headers_holds_no_more_than_its_bounds")
FETCH = p2p("test_a_page_is_not_held_while_its_entries_are_fetched")
CHANNELS = p2p("test_each_channel_is_let_go_once_it_has_been_gone_through")
SERVE = relay("a_request_is_not_held_while_its_answer_is_written")
T03 = (("cordelia-node", ["--test", "threat_model"]),
       "t03_a_relay_gets_past_what_it_will_not_store")

ANY_BYTES = 'serde_bytes::deserialize(deserializer)'

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("H1 an entry's ID is read at any length", MESSAGES,
     '''text_of_at_most(deserializer, MAX_ITEM_ID_LEN, "an entry's ID")''',
     '''text_of_at_most(deserializer, usize::MAX, "an entry's ID")''',
     [HEADER]),
    ("H2 a channel's ID is read at any length", MESSAGES,
     '''text_of_at_most(deserializer, MAX_CHANNEL_ID_LEN, "a channel's ID")''',
     '''text_of_at_most(deserializer, usize::MAX, "a channel's ID")''',
     [HEADER]),
    ("H3 an entry's type is read at any length", MESSAGES,
     '''text_of_at_most(deserializer, MAX_ITEM_TYPE_LEN, "an entry's type")''',
     '''text_of_at_most(deserializer, usize::MAX, "an entry's type")''',
     [HEADER]),
    ("H4 an entry's time is read at any length", MESSAGES,
     '''text_of_at_most(deserializer, MAX_TIMESTAMP_LEN, "an entry's time")''',
     '''text_of_at_most(deserializer, usize::MAX, "an entry's time")''',
     [HEADER]),
    ("H5 a parent's ID is read at any length", MESSAGES,
     '''text_of_at_most(d, MAX_ITEM_ID_LEN, "a parent's ID")''',
     '''text_of_at_most(d, usize::MAX, "a parent's ID")''',
     [HEADER]),
    ("H6 a content hash is read at any length", MESSAGES,
     '''bytes_of(deserializer, ITEM_HASH_BYTES, "a content hash")''',
     ANY_BYTES,
     [HEADER]),
    ("H7 an author is read at any length", MESSAGES,
     '''bytes_of(deserializer, ITEM_AUTHOR_BYTES, "an author's key")''',
     ANY_BYTES,
     [HEADER]),
    ("H8 a signature is read at any length", MESSAGES,
     '''bytes_of(deserializer, ITEM_SIGNATURE_BYTES, "a signature")''',
     ANY_BYTES,
     [HEADER, PAGE_COST]),
    ("H9 a slot is read at any length", MESSAGES,
     '''bytes_of(d, ITEM_SLOT_BYTES, "a slot").map(Some)''',
     '''serde_bytes::deserialize::<Vec<u8>, _>(d).map(Some)''',
     [HEADER]),
    ("H10 a text over its size is read", MESSAGES,
     '''            if text.len() > self.most {''',
     '''            if text.len() > self.most && false {''',
     [HEADER]),
    ("H12 the mark of a text over its size fits", MESSAGES,
     '''    "#".repeat(most + 1)''',
     '''    "#".repeat(most)''',
     [HEADER, PAGE_COST]),
    ("H13 a text over its size refuses its page", MESSAGES,
     '''                return Ok(over_its_size(self.most));''',
     '''                return Err(E::invalid_length(text.len(), &self));''',
     [HEADER, PAGE_COST, T03]),
    ("H11 bytes shorter than their size are read", MESSAGES,
     '''            if bytes.len() != self.size {''',
     '''            if bytes.len() > self.size {''',
     [HEADER]),
    ("F1 a fetch keeps its page while it fetches the entries", P2P,
     '''            drop(resp);
''',
     '''            // the page is kept
''',
     [FETCH]),
    ("F2 a fetch keeps every channel's ID to its end", P2P,
     '''    'channels: for ch_id in channels {
        let ch_id: &str = &ch_id;''',
     '''    'channels: for ch_id in &channels {
        let ch_id: &str = ch_id;''',
     [CHANNELS]),
    ("S1 serve keeps the request through its write", RELAY,
     '''        drop(request);
''',
     '''        // the request is kept
''',
     [SERVE]),
    ("S2 serve keeps the frame through its write", RELAY,
     '''        drop(frame);
''',
     '''        // the frame is kept
''',
     [SERVE]),
    ("S3 serve keeps the answer as a message through its write", RELAY,
     '''        drop(answer);
''',
     '''        // the answer is kept
''',
     [SERVE]),
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
