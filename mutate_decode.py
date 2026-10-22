#!/usr/bin/env python3
"""Mutation checks for reading each wire message by the stream it arrives
on, straight into its own type with every list bounded, and dropping a
request before anything is awaited (network-protocol.md §3.2,
parameter-rationale.md §1). A part for each rule of the slice: put each
fault in, and confirm the test named for it fails on an assertion. Run
from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
MESSAGES = 'crates/cordelia-network/src/messages.rs'
CODEC = 'crates/cordelia-network/src/codec.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
ORIG = {f: open(f).read() for f in (MESSAGES, CODEC, P2P)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NET_LIB = ("cordelia-network", ["--lib"])
NET_COST = ("cordelia-network", ["--test", "decode_cost"])
NODE_BIN = ("cordelia-node", ["--bin", "cordelia"])
def messages(test): return (NET_LIB, "messages::tests::" + test)
def cost(test): return (NET_COST, test)
def p2p(test): return (NODE_BIN, "p2p::tests::" + test)

BOUNDED = messages("each_list_of_the_older_streams_is_bounded_where_it_is_read")
FORM = messages("a_message_not_in_its_form_is_refused")
ON_ITS_STREAM = messages("every_message_is_read_on_its_stream_and_on_no_other")
BOTH_WAYS = messages("every_message_reads_the_same_both_ways_with_alpha_14")
WRITTEN = messages("every_message_is_written_as_alpha_14_writes_it")
COST = cost("decoding_a_frame_costs_at_most_three_times_its_bytes")
REFUSED_COST = cost("a_frame_that_is_refused_is_refused_before_it_is_held")
NOT_HELD = p2p("test_a_fetch_request_is_not_held_while_the_node_waits")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # Decoding by the stream: no frame is held as values of no type.
    ("D1 the frame is read as values of no type before its message", CODEC,
     '''    let mut rest = data;''',
     '''    let _values: ciborium::Value =
        ciborium::from_reader(data).map_err(|e| CodecError::CborDecode(e.to_string()))?;
    let mut rest = data;''',
     [COST, REFUSED_COST]),
    ("D2 a message of another stream is read", MESSAGES,
     '''        if !named.travels_on(self.0) {''',
     '''        if false && !named.travels_on(self.0) {''',
     [ON_ITS_STREAM]),
    # Exactly its form.
    ("F1 a first key other than the name is taken for it", MESSAGES,
     '''        if key == MESSAGE_NAME_KEY {''',
     '''        if key == MESSAGE_NAME_KEY || !key.is_empty() {''',
     [FORM]),
    ("F2 what follows the message in its frame is not refused", CODEC,
     '''    if !rest.is_empty() {''',
     '''    if !rest.is_empty() && rest.is_empty() {''',
     [FORM]),
    # Every list bounded where it is read.
    ("B1 a handshake's roles are not bounded", MESSAGES,
     '''    /// At most MAX_HANDSHAKE_ROLES.
    #[serde(deserialize_with = "at_most_roles")]
    pub roles: Vec<String>,
    /// P2P listening port''',
     '''    /// At most MAX_HANDSHAKE_ROLES.
    pub roles: Vec<String>,
    /// P2P listening port''',
     [BOUNDED]),
    ("B2 the roles of a handshake's answer are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_roles")]
    pub roles: Vec<String>,
    pub reject_reason''',
     '''    pub roles: Vec<String>,
    pub reject_reason''',
     [BOUNDED]),
    ("B3 the peers shared are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_peers")]
''', '',
     [BOUNDED]),
    ("B4 the addresses of a peer shared are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_addrs")]
''', '',
     [BOUNDED]),
    ("B5 the channel descriptors listed are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_descriptors")]
''', '',
     [BOUNDED]),
    ("B6 the channel IDs listed are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_channel_ids")]
''', '',
     [BOUNDED]),
    ("B7 the headers of a page are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_headers")]
''', '',
     [BOUNDED]),
    ("B8 the IDs of a fetch are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_fetched_ids")]
''', '',
     [BOUNDED]),
    ("B9 the items handed for a fetch are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_fetched_items")]
''', '',
     [BOUNDED]),
    ("B10 the items of a push are not bounded", MESSAGES,
     '''    #[serde(deserialize_with = "at_most_pushed_items")]
''', '',
     [BOUNDED]),
    ("B11 the items a push refused are not bounded", MESSAGES,
     '''        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "at_most_refusals"
''',
     '''        skip_serializing_if = "Vec::is_empty"
''',
     [BOUNDED]),
    ("B12 a bound is one more than its constant", MESSAGES,
     '''    at_most(deserializer, MAX_FETCH_ITEMS as u32, "item IDs")''',
     '''    at_most(deserializer, MAX_FETCH_ITEMS as u32 + 1, "item IDs")''',
     [BOUNDED]),
    # A request dropped before anything is awaited.
    ("S1 a fetch request is held through the write and the next read", P2P,
     '''                drop(freq);
''', '',
     [NOT_HELD]),
    # Nothing changed on the wire.
    ("W1 a message is written with its name under another key", MESSAGES,
     '''#[derive(Debug, Clone, Serialize)]
#[serde(tag = "msg_type")]
pub enum WireMessage {''',
     '''#[derive(Debug, Clone, Serialize)]
#[serde(tag = "msg_typ")]
pub enum WireMessage {''',
     [WRITTEN, BOTH_WAYS]),
    ("W2 a message's name is read under another key", MESSAGES,
     '''pub const MESSAGE_NAME_KEY: &str = "msg_type";''',
     '''pub const MESSAGE_NAME_KEY: &str = "type";''',
     [ON_ITS_STREAM, BOTH_WAYS]),
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
