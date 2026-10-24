#!/usr/bin/env python3
"""Mutation checks for slice 4 of change F, windows and streams: QUIC's
windows and stream count set from a small message, each stream's window
an eighth of the connection's, the push retries
bounded, and today's windows and streams kept between relays listed by
key, with what crosses the windows of every peer bounded by the end that
has them where the two ends of a listed relay's connection disagree
(decision 2026-10-22, memory across connections, rules 8, 9, 11 and 12,
section 9 item 4), with test 8's check of rule 10 by memory. A part
for each rule of the slice: put each fault in, and confirm the test named
for it fails on an assertion. Run from the root of a checkout that
nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
TRANSPORT = 'crates/cordelia-network/src/transport.rs'
CONNECTION = 'crates/cordelia-network/src/connection.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
RELAY_ENTRIES = 'crates/cordelia-node/src/relay_entries.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, TRANSPORT, CONNECTION, P2P, RELAY_ENTRIES)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
NET = ("cordelia-network", ["--lib"])
BATCHING = ("cordelia-network", ["--test", "receive_batching"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
def core(test): return (CORE, "protocol::tests::" + test)
def net(test): return (NET, "transport::tests::" + test)
def batching(test): return (BATCHING, test)
def node(test): return (NODE, "p2p::tests::" + test)
def entries(test): return (NODE, "relay_entries::tests::" + test)

LISTED = node("a_relay_listed_by_key_keeps_todays_windows_and_streams")
RETRIES = node("a_failed_repush_is_tried_again_a_few_streams_at_a_time")
SET_FROM_SMALL = net("the_windows_and_streams_are_set_from_a_small_message")
LISTED_CONFIGS = net("a_relay_listed_by_key_has_the_windows_and_streams_of_before")
SMALL_ASKED = entries("a_relay_on_every_peers_windows_asks_a_listed_relay_for_small_pages")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("W1 a stream's receive window is a small message, as the connection's half", PROTOCOL,
     ['''pub const QUIC_STREAM_RECEIVE_WINDOW: u32 =
    (QUIC_RECEIVE_WINDOW - QUIC_RECEIVE_WINDOW / 8) / QUIC_MAX_BIDI_STREAMS;''',
      '''        <= QUIC_RECEIVE_WINDOW as u64 - QUIC_RECEIVE_WINDOW as u64 / 8
'''],
     ['''pub const QUIC_STREAM_RECEIVE_WINDOW: u32 = SMALL_MESSAGE_BYTES;''',
      '''        <= u64::MAX\n'''],
     [core("the_receive_windows_hold_every_stream_within_two_small_messages"), SET_FROM_SMALL,
      node("a_fetch_and_large_pushes_on_one_connection_do_not_wait_on_each_other")]),
    ("W5 a stream's receive window is an eighth of the connection's, none left for its own", PROTOCOL,
     ['''pub const QUIC_STREAM_RECEIVE_WINDOW: u32 =
    (QUIC_RECEIVE_WINDOW - QUIC_RECEIVE_WINDOW / 8) / QUIC_MAX_BIDI_STREAMS;''',
      '''        <= QUIC_RECEIVE_WINDOW as u64 - QUIC_RECEIVE_WINDOW as u64 / 8
'''],
     ['''pub const QUIC_STREAM_RECEIVE_WINDOW: u32 = QUIC_RECEIVE_WINDOW / QUIC_MAX_BIDI_STREAMS;''',
      '''        <= QUIC_RECEIVE_WINDOW as u64\n'''],
     [core("the_receive_windows_hold_every_stream_within_two_small_messages"), SET_FROM_SMALL,
      node("a_fetch_and_large_pushes_on_one_connection_do_not_wait_on_each_other")]),
    ("W2 a connection's receive window is two messages", PROTOCOL,
     '''pub const QUIC_RECEIVE_WINDOW: u32 = 2 * SMALL_MESSAGE_BYTES;''',
     '''pub const QUIC_RECEIVE_WINDOW: u32 = 2 * MAX_MESSAGE_BYTES;''',
     [core("the_receive_windows_hold_every_stream_within_two_small_messages"), SET_FROM_SMALL]),
    ("W3 the send window is two messages", PROTOCOL,
     '''pub const QUIC_SEND_WINDOW: u64 = 2 * SMALL_MESSAGE_BYTES as u64;''',
     '''pub const QUIC_SEND_WINDOW: u64 = 2 * MAX_MESSAGE_BYTES as u64;''',
     [core("test_quic_send_window_parameter_rationale_1"), SET_FROM_SMALL]),
    ("W4 a peer may have 64 streams open", PROTOCOL,
     '''pub const MAX_CONCURRENT_STREAMS: usize = 8;''',
     '''pub const MAX_CONCURRENT_STREAMS: usize = 64;''',
     [core("test_quic_max_bidi_streams_network_protocol_2_1"), SET_FROM_SMALL]),
    ("L1 a listed relay's stream window is a small message", PROTOCOL,
     '''pub const QUIC_LISTED_STREAM_RECEIVE_WINDOW: u32 = MAX_MESSAGE_BYTES;''',
     '''pub const QUIC_LISTED_STREAM_RECEIVE_WINDOW: u32 = SMALL_MESSAGE_BYTES;''',
     [core("a_relay_listed_by_key_keeps_the_windows_and_streams_of_before"),
      LISTED_CONFIGS]),
    ("L2 a listed relay's connection window is two small messages", PROTOCOL,
     '''pub const QUIC_LISTED_RECEIVE_WINDOW: u32 = 2 * MAX_MESSAGE_BYTES;''',
     '''pub const QUIC_LISTED_RECEIVE_WINDOW: u32 = 2 * SMALL_MESSAGE_BYTES;''',
     [core("a_relay_listed_by_key_keeps_the_windows_and_streams_of_before"),
      LISTED_CONFIGS]),
    ("L3 the send window to a listed relay is two small messages", PROTOCOL,
     '''pub const QUIC_LISTED_SEND_WINDOW: u64 = 2 * MAX_MESSAGE_BYTES as u64;''',
     '''pub const QUIC_LISTED_SEND_WINDOW: u64 = 2 * SMALL_MESSAGE_BYTES as u64;''',
     [core("a_relay_listed_by_key_keeps_the_windows_and_streams_of_before"),
      LISTED_CONFIGS]),
    ("L4 a listed relay may have 8 streams open", PROTOCOL,
     '''pub const QUIC_LISTED_MAX_BIDI_STREAMS: u32 = 64;''',
     '''pub const QUIC_LISTED_MAX_BIDI_STREAMS: u32 = 8;''',
     [core("a_relay_listed_by_key_keeps_the_windows_and_streams_of_before"),
      LISTED_CONFIGS]),
    ("R1 the push retries run eight to a peer at once", PROTOCOL,
     '''pub const PUSH_RETRY_STREAMS_AT_ONCE: usize = QUIC_MAX_BIDI_STREAMS as usize / 2;''',
     '''pub const PUSH_RETRY_STREAMS_AT_ONCE: usize = QUIC_MAX_BIDI_STREAMS as usize;''',
     [core("at_most_four_push_retries_run_to_a_peer_at_once")]),
    ("R2 the push retries are not bounded", P2P,
     '''                if *at_once >= cordelia_core::protocol::PUSH_RETRY_STREAMS_AT_ONCE {''',
     '''                if *at_once >= usize::MAX {''',
     [RETRIES]),
    ("R3 a retry held back spends a try", P2P,
     '''                if *at_once >= cordelia_core::protocol::PUSH_RETRY_STREAMS_AT_ONCE {
                    remaining.push(entry);''',
     '''                if *at_once >= cordelia_core::protocol::PUSH_RETRY_STREAMS_AT_ONCE {
                    let mut entry = entry;
                    entry.attempt += 1;
                    remaining.push(entry);''',
     [RETRIES]),
    ("D1 a relay configured by key is dialled with every peer's settings", CONNECTION,
     '''        Some(listed) => ctx
            .endpoint
            .connect_with(listed.client.clone(), addr, "cordelia"),''',
     '''        Some(_) => ctx.endpoint.connect(addr, "cordelia"),''',
     [LISTED]),
    ("D2 the dial does not ask for a relay's settings by its key", P2P,
     '''    if relay.key.is_some() {''',
     '''    if relay.key.is_none() {''',
     [LISTED]),
    ("A1 a listed relay's address is accepted with every peer's settings", CONNECTION,
     '''        Some(listed) => incoming
            .accept_with(listed.server.clone())''',
     '''        Some(_) => incoming
            .accept()''',
     [LISTED]),
    ("A2 every address is taken for a listed relay's", P2P,
     '''        .filter(|relay| canonical(relay.addr) == canonical(from))''',
     '''        .filter(|relay| canonical(relay.addr).ip() == canonical(from).ip())''',
     [LISTED]),
    ("A3 no address is taken for a listed relay's", P2P,
     '''    if keys.is_empty() {
        cordelia_network::connection::inbound_accept(ctx, incoming).await''',
     '''    if true {
        cordelia_network::connection::inbound_accept(ctx, incoming).await''',
     [LISTED]),
    ("C1 a connection from a listed relay's address with another key is kept", CONNECTION,
     '''    if let Some(keys) = keys
        && !keys.contains(&peer_node_id)
    {''',
     '''    if let Some(keys) = keys
        && keys.is_empty()
        && !keys.contains(&peer_node_id)
    {''',
     [LISTED]),
    ("G1 the node's socket takes batches of datagrams", TRANSPORT,
     '''    receive_batching_off(&same_socket)?;''',
     '''    let _ = &same_socket;''',
     [batching("a_peer_cannot_make_a_node_hold_its_batches_of_datagrams"),
      net("a_nodes_socket_takes_no_batches_of_datagrams")]),
    ("S1 a relay on every peer's windows asks a listed relay for full pages", RELAY_ENTRIES,
     '''        let limit = if link.small_windows() {''',
     '''        let limit = if false {''',
     [SMALL_ASKED]),
    ("S3 a relay's links say the opposite of its own end's settings", RELAY_ENTRIES,
     '''            let small_windows = !conn_mgr.carries_listed_settings(&relay);''',
     '''            let small_windows = conn_mgr.carries_listed_settings(&relay);''',
     [node("behind_a_nat_each_relay_asks_for_pages_by_its_own_ends_settings")]),
    ("S4 a listed relay is served small pages", RELAY_ENTRIES,
     '''                    pull.limit,
                    ENTRY_PAGE_MAX_BYTES,
                );''',
     '''                    pull.limit,
                    SMALL_PAGE_BYTES,
                );''',
     [SMALL_ASKED]),
    ("S5 the entries a page on every peer's windows asks for are two", PROTOCOL,
     ['''pub const SMALL_WINDOWS_PULL_ENTRIES: u32 = (SMALL_PAGE_BYTES / MAX_ENTRY_WIRE_BYTES) as u32;''',
      '''const _: () =
    assert!(SMALL_WINDOWS_PULL_ENTRIES as usize * MAX_ENTRY_WIRE_BYTES <= SMALL_PAGE_BYTES);'''],
     ['''pub const SMALL_WINDOWS_PULL_ENTRIES: u32 = 2;''',
      '''const _: () = assert!(SMALL_WINDOWS_PULL_ENTRIES as usize * MAX_ENTRY_WIRE_BYTES <= usize::MAX);'''],
     [core("a_relay_on_every_peers_windows_asks_for_one_entry_a_page"), SMALL_ASKED]),
    ("P1 entries are passed on to a listed relay a full page to a message", RELAY_ENTRIES,
     '''                            || bytes + entry.bytes.len() > SMALL_PAGE_BYTES''',
     '''                            || bytes + entry.bytes.len() > ENTRY_PAGE_MAX_BYTES''',
     [entries("an_entry_that_is_taken_is_passed_on_to_the_listed_relays_but_not_back")]),
    ("S2 every accepted connection says it has the listed settings", CONNECTION,
     '''        listed_settings: keys.is_some() && ctx.listed.is_some(),''',
     '''        listed_settings: true,''',
     [LISTED]),
    ("K1 an IPv4 address mapped into IPv6 is not taken for itself", P2P,
     '''    let canonical = |addr: std::net::SocketAddr| {
        std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port())
    };''',
     '''    let canonical = |addr: std::net::SocketAddr| addr;''',
     [node("a_listed_relays_address_is_found_when_shown_mapped_into_ipv6")]),
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
