#!/usr/bin/env python3
"""Mutation checks for a relay given no key that is never taken for
another relay (decision 2026-10-17 §1; decision 2026-10-19 §1, §5 S9 and
§13): only the configuration makes two names one relay; a relay given no
key at a keyed relay's place, by the address its name resolves to or by
the key that answers on its connection, stays a relay of its own,
reached by no connection there, passed over by the dial loop, never
listed as connected, and named with what to do; two names given no key
at one address are two relays on one connection, which counts once. A part for each rule of the slice: put each fault in, and
confirm the test named for it fails on an assertion. Run from the root
of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
P2P = 'crates/cordelia-node/src/p2p.rs'
BOOTSTRAP = 'crates/cordelia-network/src/bootstrap.rs'
ENTRIES = 'crates/cordelia-node/src/device_entries.rs'
WAIT = 'crates/cordelia-node/src/person_cmd/wait.rs'
COMMANDS = 'crates/cordelia-api/src/commands.rs'
ORIG = {f: open(f).read() for f in (P2P, BOOTSTRAP, ENTRIES, WAIT, COMMANDS)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NODE_BIN = ("cordelia-node", ["--bin", "cordelia"])
DEVICES_E2E = ("cordelia-node", ["--test", "devices_e2e"])
API = ("cordelia-api", ["--lib"])
NETWORK = ("cordelia-network", ["--lib"])
def p2p(test): return (NODE_BIN, "p2p::tests::" + test)
def wait(test): return (NODE_BIN, "person_cmd::wait::tests::" + test)
def api(test): return (API, "commands::tests::" + test)
def network(test): return (NETWORK, "bootstrap::tests::" + test)
def devices(test): return (DEVICES_E2E, test)

OWN = "a_relay_given_no_key_at_another_relays_address_is_a_relay_of_its_own"
OUT = "a_relay_given_no_key_at_a_keyed_relays_place_is_passed_over_and_comes_to_be_out_of_reach"
TWO_KEYLESS = "two_names_given_no_key_at_one_address_are_two_relays_on_one_connection"
COUNTS_ONCE = "one_connection_that_serves_two_relays_never_counts_as_two"
REACHED = "a_relay_found_at_a_keyed_relays_place_is_reached_no_more_at_once"
S9 = "s9_says_what_to_do_of_a_relay_given_no_key_at_a_keyed_relays_place"
LOOK = "test_the_look_says_how_the_node_tries_each_relay"
WARNED = "a_relay_given_no_key_at_a_keyed_relays_address_is_warned_of"
KEY_AT = "the_dial_loop_reads_the_key_that_answers_at_an_address"
ANSWERED = "a_dial_answered_at_a_keyed_relays_place_ends_the_relay_given_no_key_once"
FOUND = "the_addresses_found_warn_of_relays_at_one_address_with_what_to_do"
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
     '''    !at_a_keyed && (at.connected)(relay)''',
     '''    let _ = at_a_keyed;
    (at.connected)(relay)''',
     [p2p(OUT)]),
    ("KR5 the status lists it as connected", P2P,
     '''            let connected = !wrong_key_at && keyless_at.is_none() && connected(relay);''',
     '''            let connected = !wrong_key_at && connected(relay);''',
     [p2p(LISTED)]),
    ("KR6 the status says it is dialled, not never reached", P2P,
     '''                    (false, true) => cordelia_api::state::Tried::NoKey,''',
     '''                    (false, true) => cordelia_api::state::Tried::Dialled,''',
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
    ("KR11 the key that answers on its connection is not looked at, in the count", P2P,
     '''                peers[i] == Some(NodeId(key)) || (addrs[i].is_some() && addrs[j] == addrs[i])''',
     '''                let _ = key;
                addrs[i].is_some() && addrs[j] == addrs[i]''',
     [p2p(OWN)]),
    ("KR12 the key that answers on its connection is not looked at, in the dial loop", P2P,
     '''            answered == Some(key)
                || resolved.iter()''',
     '''            (answered == Some(key) && false)
                || resolved.iter()''',
     [p2p(OUT)]),
    ("KR13 one connection that serves two relays counts as two", ENTRIES,
     '''    set_up.filter(|keys| Some(keys.len()) == configured && distinct(keys))''',
     '''    let _ = distinct;
    set_up.filter(|keys| Some(keys.len()) == configured)''',
     [p2p(COUNTS_ONCE)]),
    ("KR14 two names given no key at one address are each at the other's place, in the count", P2P,
     '''        let keyed = (0..set_up.len()).find(|&j| {
            set_up[j].key.is_some_and(|key| {''',
     '''        let keyed = (0..set_up.len()).find(|&j| {
            (j != i && addrs[i].is_some() && addrs[j] == addrs[i] && !named_alike(i, j))
                || set_up[j].key.is_some_and(|key| {''',
     [p2p(TWO_KEYLESS), p2p(COUNTS_ONCE)]),
    ("KR15 two names given no key at one address are each at the other's place, in the dial loop", P2P,
     '''    let at_a_keyed = relay.key.is_none()
        && keyed_relay_at(at.set_up, at.relays, relay.addr, (at.key_at)(relay.addr)).is_some();''',
     '''    let at_a_keyed = relay.key.is_none()
        && (keyed_relay_at(at.set_up, at.relays, relay.addr, (at.key_at)(relay.addr)).is_some()
            || at.relays.iter().any(|o| o.addr == relay.addr && o.host != relay.host));''',
     [p2p(TWO_KEYLESS)]),
    ("KR16 the dial loop's turn takes any connection at its address for its own", P2P,
     '''    if connected_as_itself(at, relay) {
        let id = tried_relay(relay);''',
     '''    if (at.connected)(relay) {
        let id = tried_relay(relay);''',
     [p2p(OUT)]),
    ("KR17 the dial loop paces by any connection, its own or not", P2P,
     '''    at.relays.iter().any(|relay| connected_as_itself(at, relay))''',
     '''    at.relays.iter().any(|relay| (at.connected)(relay))''',
     [p2p(OUT)]),
    ("KR18 a dial answered at a keyed relay's place counts it as answered", P2P,
     '''                Some(other) => passed.push((relay.clone(), set_up[other].host.clone())),''',
     '''                Some(_) => answers.push(relay.clone()),''',
     [p2p(LISTED)]),
    ("KR19 a relay found at a keyed relay's place stays reached while it is passed over", P2P,
     '''    let id = tried_relay(relay);
    if let Some(reach) = reach {
        reach.connection(&reach_id(&id), None);
    }
    if passed_over(relays, relay, connected, reach) {
        return false;
    }
    if tick.busy {''',
     '''    if passed_over(relays, relay, connected, reach) {
        return false;
    }
    let id = tried_relay(relay);
    if let Some(reach) = reach {
        reach.connection(&reach_id(&id), None);
    }
    if tick.busy {''',
     [p2p(REACHED)]),
    ("KR20 the status says nothing of what to do", P2P,
     '''        "given no key, at the address of {other}: give it that relay's key, or remove it from \\
         your configuration"''',
     '''        "given no key, at the address of {other}"''',
     [p2p(LISTED)]),
    ("KR21 the wait after a change says nothing of it", WAIT,
     '''    let no_key = dialled_so(Dial::NoKey);''',
     '''    let no_key: Vec<&RelayAt> = Vec::new();''',
     [wait(S9)]),
    ("KR22 the look does not say that it is never reached", COMMANDS,
     '''                Some(listed) if listed.tried == Tried::NoKey => "no_key",
''',
     '''''',
     [api(LOOK)]),
    ("KR23 the log warns of no relay given no key at a keyed relay's address", BOOTSTRAP,
     '''                .find(|r| r.key.is_some() && r.addr == relay.addr)?;''',
     '''                .find(|r| r.key.is_some() && r.addr == relay.addr && false)?;''',
     [network(WARNED)]),
    ("KR24 the dial loop reads no key at an address", P2P,
     '''    let key_at = |addr| key_at(conn_mgr, addr);''',
     '''    let key_at = |_addr| None;''',
     [p2p(KEY_AT)]),
    ("KR25 the pace of a dial's answer takes any connection for a relay's own", P2P,
     '''        .map(|relays| with_tick(set_up, &relays, conn_mgr, any_connected_as_itself))''',
     '''        .map(|relays| relays.iter().any(|r| relay_connected(conn_mgr, r)))''',
     [p2p(KEY_AT)]),
    ("KR26 a dial answered at a keyed relay's place does not end for the relay given no key", P2P,
     '''    for (relay, other) in &passed {''',
     '''    for (relay, other) in passed.iter().filter(|_| false) {''',
     [p2p(ANSWERED)]),
    ("KR27 a dial's answer judges a relay given no key by the address alone", P2P,
     '''            None => match keyed_relay_at(set_up, relays, addr, Some(*answered)) {''',
     '''            None => match keyed_relay_at(set_up, relays, addr, None) {''',
     [p2p(ANSWERED)]),
    ("KR28 a relay given no key passed at a dial's answer is also taken to have moved", P2P,
     '''        .chain(passed.iter().map(|(relay, _)| relay))''',
     '''        .chain(passed.iter().map(|(relay, _)| relay).filter(|_| false))''',
     [p2p(ANSWERED)]),
    ("KR29 two names given no key at one address are warned of nothing", P2P,
     '''            (true, true) => said.push(format!(''',
     '''            (true, true) if false => said.push(format!(''',
     [p2p(FOUND)]),
    ("KR30 the addresses found warn of nothing", P2P,
     '''    Some(address_warnings(resolved))''',
     '''    let _ = address_warnings;
    Some(Vec::new())''',
     [p2p(FOUND)]),
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
