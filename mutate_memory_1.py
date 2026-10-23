#!/usr/bin/env python3
"""Mutation checks for change F slice 1, the small message and the permits
(decision 2026-10-22 "what a relay holds across its connections", section
9), with the parts the review added: rule 2 on the streams of entries, the
other inbound streams capped at a small message, first-come-first-served,
and the live inbound loop. A part for each rule and each review finding:
put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits.

Rule 10's test by memory (test 8) is not among these: the loopback GRO
pinning the review measured did not reproduce to the record's "twice" bar
in this environment, so that test is not merged here. Rule 10's setsockopt
is still told, by #195's own socket-option test (part P9)."""
import re, subprocess, sys

PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
RELAY = 'crates/cordelia-node/src/relay_entries.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
CODEC = 'crates/cordelia-network/src/codec.rs'
TRANSPORT = 'crates/cordelia-network/src/transport.rs'
ORIG = {f: open(f).read() for f in (P2P, RELAY, DEVICE, CODEC, TRANSPORT)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
NET = ("cordelia-network", ["--lib"])
def bin(test): return (BIN, test)
def e2e(test): return (E2E, test)
def net(test): return (NET, test)

SYNC_ANSWER_ORIG = '''    let written = cordelia_network::codec::encode_message(&answer);
    drop(answer);
    if let Ok(written) = written {
        let _ = cordelia_network::codec::write_raw_frame(send, &written).await;
    }'''
SYNC_ANSWER_MUT = '''    let _ = cordelia_network::codec::write_frame(send, &answer).await;'''

# Each part: (a short id and the fault, the file, the exact text to take
# out, the exact text to put in its place, the tests that must then fail).
# The text to take out must occur exactly once in the file.
MUTATIONS = [
    ("P1 a large frame is read with no permit taken first", P2P,
     'if len > cordelia_core::protocol::SMALL_MESSAGE_BYTES && !listed {',
     'if false {',
     [bin("p2p::tests::a_large_frame_from_an_unlisted_peer_is_not_read_without_a_permit")]),
    ("P2 no per-subnet gate on a permit", P2P,
     '&& !self.held.contains(subnet)\n            && !self',
     '&& !self',
     [bin("p2p::tests::a_large_permit_is_one_for_each_subnet")]),
    ("P3 a stream takes nothing from the budget", P2P,
     'p.free -= 1;',
     'p.free -= 0;',
     [bin("p2p::tests::large_permits_are_bounded_and_given_back")]),
    ("P4 no exemption for a relay listed by key", P2P,
     'if len > cordelia_core::protocol::SMALL_MESSAGE_BYTES && !listed {',
     'if len > cordelia_core::protocol::SMALL_MESSAGE_BYTES {',
     [bin("p2p::tests::a_listed_relays_large_frame_is_read_with_every_permit_held")]),
    ("P5 a permit is not given back on drop", P2P,
     'p.free += 1;',
     'p.free += 0;',
     [bin("p2p::tests::large_permits_are_bounded_and_given_back")]),
    ("P6 the refusal uses another code than 0x05", P2P,
     'let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_LARGE_MESSAGE_LATER);',
     'let code = quinn::VarInt::from_u32(cordelia_core::protocol::ERR_RATE_LIMIT);',
     [bin("p2p::tests::a_large_frame_with_no_permit_is_refused_later_and_counts_no_breach")]),
    ("P7 room_to_push stops past a small page", DEVICE,
     '(room >= entry_cost(MAX_ITEM_BYTES)).then(|| SMALL_PAGE_BYTES.min(room as usize))',
     '(room >= entry_cost(MAX_ITEM_BYTES)).then(|| (896 * 1024).min(room as usize))',
     [e2e("a_device_of_this_version_pushes_no_message_over_a_small_message")]),
    ("P8 the answer is held through its write", P2P,
     SYNC_ANSWER_ORIG, SYNC_ANSWER_MUT,
     [bin("p2p::tests::an_older_kind_sync_answer_is_not_held_through_its_write")]),
    ("P9 the setsockopt leaves GRO on", TRANSPORT,
     'let off: libc::c_int = 0;',
     'let off: libc::c_int = 1;',
     [net("transport::tests::a_nodes_socket_takes_no_batches_of_datagrams")]),
    # Review finding 1: rule 2 on the streams of entries.
    ("F1a serve reads a large frame with no permit", RELAY,
     '            serving.permits,\n            who.address,',
     '            None,\n            who.address,',
     [bin("relay_entries::tests::a_large_frame_on_an_entry_stream_is_read_only_under_a_permit")]),
    ("F1b serve lets its permit go before the write", RELAY,
     'let (frame, _permit) = match crate::p2p::read_under_permit(',
     'let (frame, _) = match crate::p2p::read_under_permit(',
     [bin("relay_entries::tests::a_stream_holds_its_permit_through_the_write")]),
    # Review finding 2: the other inbound streams, capped at a small message.
    ("F2a the older-kind answer-nothing reads any length", P2P,
     'read_small_frame(\n            recv,\n            cordelia_network::messages::Protocol::ItemSync,',
     'read_frame(\n            recv,\n            cordelia_network::messages::Protocol::ItemSync,',
     [bin("p2p::tests::the_small_streams_do_not_read_a_frame_over_a_small_message")]),
    ("F2b peer-share reads any length", P2P,
     'read_small_frame(\n        recv,\n        cordelia_network::messages::Protocol::PeerSharing,',
     'read_frame(\n        recv,\n        cordelia_network::messages::Protocol::PeerSharing,',
     [bin("p2p::tests::the_small_streams_do_not_read_a_frame_over_a_small_message")]),
    ("F2c channel-announce reads any length", P2P,
     'read_small_frame(\n            recv,\n            cordelia_network::messages::Protocol::ChannelAnnounce,',
     'read_frame(\n            recv,\n            cordelia_network::messages::Protocol::ChannelAnnounce,',
     [bin("p2p::tests::the_small_streams_do_not_read_a_frame_over_a_small_message")]),
    ("F2d read_small_frame does not cap the length", CODEC,
     '    if len > protocol::SMALL_MESSAGE_BYTES {\n        return Err(CodecError::MessageTooLarge { size: len });\n    }\n',
     '',
     [net("codec::tests::a_small_frame_read_refuses_a_frame_over_a_small_message")]),
    # Review finding 3: first come, first served.
    ("F3 a later asker may jump an earlier waiter", P2P,
     '\n            && !self\n                .waiting\n                .iter()\n                .any(|(t, s)| *t < ticket && !self.held.contains(s))',
     '',
     [bin("p2p::tests::a_holder_that_retakes_does_not_starve_a_waiter")]),
    # Review finding 4: the live inbound loop.
    ("F4a the loop reads without permits", P2P,
     '                    !unlimited,\n                    address,\n                    Some(&large_permits),\n                    listed_by_key,',
     '                    !unlimited,\n                    address,\n                    None,\n                    listed_by_key,',
     [bin("p2p::tests::the_inbound_loop_takes_permits_and_exempts_only_listed_relays")]),
    ("F4b the exemption is widened to a relay by address", P2P,
     '                    !unlimited,\n                    address,\n                    Some(&large_permits),\n                    listed_by_key,',
     '                    !unlimited,\n                    address,\n                    Some(&large_permits),\n                    listed_by_key || own_relay,',
     [bin("p2p::tests::the_inbound_loop_takes_permits_and_exempts_only_listed_relays")]),
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
