#!/usr/bin/env python3
"""Mutation checks for a device's relays and its connections: every
relay a node is set up with is kept, churn closes no personal node's
relay, the requests of the minute of a day's proofs are counted against
the device's own pace, a connection whose proofs are held by a left
generation is made again, and a role this version does not know is
refused at load (decision 2026-10-17 §1 to §5). A part for each rule of
the slice: put each fault in, and confirm the test named for it fails on
an assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
BOOTSTRAP = 'crates/cordelia-network/src/bootstrap.rs'
GOVERNOR = 'crates/cordelia-network/src/governor.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
CONFIG = 'crates/cordelia-core/src/config.rs'
ORIG = {f: open(f).read() for f in (BOOTSTRAP, GOVERNOR, P2P, DEVICE, PROTOCOL, CONFIG)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NETWORK = ("cordelia-network", ["--lib"])
CORE = ("cordelia-core", ["--lib"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
DEVICE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
DEVICES_E2E = ("cordelia-node", ["--test", "devices_e2e"])
def bootstrap(test): return (NETWORK, "bootstrap::tests::" + test)
def governor(test): return (NETWORK, "governor::tests::" + test)
def p2p(test): return (NODE, "p2p::tests::" + test)
def core(test): return (CORE, "protocol::tests::" + test)
def config(test): return (CORE, "config::tests::" + test)
def device_e2e(test): return (DEVICE_E2E, test)
def devices_e2e(test): return (DEVICES_E2E, test)

KEPT = bootstrap("two_relays_that_resolve_to_one_address_are_both_kept")
LISTED = p2p("two_relays_at_one_address_are_each_listed_and_a_wrong_key_is_their_own")
AT_ONE_ADDRESS = devices_e2e("two_relays_at_one_address_are_each_kept_and_the_wrong_key_is_its_own")
CHURN = governor("test_a_personal_node_keeps_its_relays_through_churn")
CHURN_E2E = devices_e2e("a_device_keeps_every_relay_it_is_set_up_with_through_churn")
REQUESTS = core("test_requests_on_the_streams_of_entries_decision_2026_10_04_16")
MADE_AGAIN = device_e2e("a_connection_whose_places_are_held_by_a_left_generation_is_made_again")
ROLE = config("test_a_role_that_this_version_does_not_know_is_refused")
REPOSITORY = config("test_the_configurations_in_this_repository_load")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # §1 Two relays at one address.
    ("R1 resolving now drops a relay at another's address", BOOTSTRAP,
     '''if let Some(addr) = pick(&addrs) {
                    debug!(host = %relay.host, %addr, "resolved relay");''',
     '''if let Some(addr) = pick(&addrs).filter(|a| !resolved.iter().any(|r| r.addr == *a)) {
                    debug!(host = %relay.host, %addr, "resolved relay");''',
     [KEPT]),
    ("R2 resolving off the loop drops a relay at another's address", BOOTSTRAP,
     '''if let Some(addr) = pick(&addrs) {
                    resolved.push(RelayAddr {''',
     '''if let Some(addr) = pick(&addrs).filter(|a| !resolved.iter().any(|r| r.addr == *a)) {
                    resolved.push(RelayAddr {''',
     [KEPT]),
    ("R3 an answer is judged for the first relay at the address alone", P2P,
     '''        .filter(|relay| relay.addr == addr)
        .cloned()
        .partition(''',
     '''        .filter(|relay| relay.addr == addr)
        .take(1)
        .cloned()
        .partition(''',
     [LISTED, AT_ONE_ADDRESS]),
    ("R4 too wide: a relay given no key is refused at a shared address", P2P,
     '''.partition(|relay| relay.key.is_none_or(|key| key == *answered))''',
     '''.partition(|relay| relay.key == Some(*answered))''',
     [LISTED]),
    ("R5 the wrong relay is dialled again while another is connected there", P2P,
     '''if relays.iter().any(|other| other.addr == relay.addr && relay_connected(&conn_mgr, other)) {''',
     '''if relays.iter().any(|other| other.addr == relay.addr && relay_connected(&conn_mgr, other) && false) {''',
     [AT_ONE_ADDRESS]),
    # §2 Churn on a personal node.
    ("C1 churn closes a personal node's relays", GOVERNOR,
     '''let churned = |p: &PeerInfo| !(self.keeps_its_relays && p.is_relay);''',
     '''let churned = |p: &PeerInfo| !(self.keeps_its_relays && p.is_relay && false);''',
     [CHURN]),
    ("C2 too wide: churn closes no relay's warm relays either", GOVERNOR,
     '''let churned = |p: &PeerInfo| !(self.keeps_its_relays && p.is_relay);''',
     '''let churned = |p: &PeerInfo| !p.is_relay;''',
     [CHURN]),
    ("C3 a personal node's governor does not keep its relays", P2P,
     '''        governor = governor.keeping_its_relays();''',
     '''        let _ = &governor;''',
     [CHURN_E2E]),
    # §3 The requests of the minute of a day's proofs.
    ("Q1 the device paces itself at the relay's limit", PROTOCOL,
     '''pub const OWN_ENTRY_REQUESTS_PER_MINUTE: u32 = ENTRY_REQUESTS_PER_PEER_PER_MINUTE / 4 * 3;''',
     '''pub const OWN_ENTRY_REQUESTS_PER_MINUTE: u32 = ENTRY_REQUESTS_PER_PEER_PER_MINUTE;''',
     [REQUESTS]),
    ("Q2 the device's pace leaves no room in the next minute", PROTOCOL,
     '''pub const OWN_ENTRY_REQUESTS_PER_MINUTE: u32 = ENTRY_REQUESTS_PER_PEER_PER_MINUTE / 4 * 3;''',
     '''pub const OWN_ENTRY_REQUESTS_PER_MINUTE: u32 = ENTRY_REQUESTS_PER_PEER_PER_MINUTE / 5 * 3;''',
     [REQUESTS]),
    # §4 The channels proved on a connection.
    ("P1 a full connection is never made again", DEVICE,
     '''        if whole {
            self.make_again_where_full(link, &own);
        }''',
     '''        let _ = Self::make_again_where_full;''',
     [MADE_AGAIN]),
    ("P2 the device forgets a left generation's proofs, which the relay keeps", DEVICE,
     '''            of.made_again = left > 0;
            left
        };''',
     '''            of.proved.retain(|channel, _| proves(channel));
            let _ = left;
            0
        };''',
     [MADE_AGAIN]),
    ("P3 too wide: a connection is made again with room left", DEVICE,
     '''!of.made_again && of.proved.len() + not_proved.count() > self.most_proved''',
     '''!of.made_again && not_proved.count() > 0''',
     [MADE_AGAIN]),
    ("P4 the device asks again at every pass", DEVICE,
     '''            of.made_again = left > 0;''',
     '''            let _ = of.made_again;''',
     [MADE_AGAIN]),
    # §5 A node's role.
    ("F1 the role is not checked at load", CONFIG,
     '''        config.network.check()?;
''',
     '''''',
     [ROLE]),
    ("F2 too wide: only a personal node loads", CONFIG,
     '''pub const ROLES: &[&str] = &["personal", "relay", "bootnode"];''',
     '''pub const ROLES: &[&str] = &["personal"];''',
     [ROLE, REPOSITORY]),
    ("F3 a role in another case or with spaces loads", CONFIG,
     '''if ROLES.contains(&self.role.as_str()) {''',
     '''if ROLES.iter().any(|role| role.eq_ignore_ascii_case(self.role.trim())) {''',
     [ROLE]),
    ("F4 a role of an earlier design loads", CONFIG,
     '''if ROLES.contains(&self.role.as_str()) {''',
     '''if ROLES.contains(&self.role.as_str()) || self.role == "keeper" {''',
     [ROLE]),
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
