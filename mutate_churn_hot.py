#!/usr/bin/env python3
"""Mutation checks for hot churn promoting a warm peer in the place of the
one it demotes (network-protocol.md 5.4 step 6, with the guards of step 4;
decision 2026-10-17 sections 2 and 6). A part for each rule of the slice:
put each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
GOVERNOR = 'crates/cordelia-network/src/governor.rs'
ORIG = {f: open(f).read() for f in (GOVERNOR,)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NETWORK = ("cordelia-network", ["--lib"])
def gov(test): return (NETWORK, "governor::tests::" + test)

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("CH1 hot churn promotes no warm peer", GOVERNOR,
     '''        self.transition_peer(promoted, PeerState::Hot, actions, "warm", "hot");''',
     '''        let _ = promoted;''',
     [gov("test_churn_hot_promotes_a_warm_peer_in_the_place_of_the_one_it_demotes")]),
    ("CH2 hot churn promotes a peer warm for less than its tenure", GOVERNOR,
     '''            .filter(|p| self.may_be_made_hot(p) && Self::has_warm_tenure(p))''',
     '''            .filter(|p| self.may_be_made_hot(p))''',
     [gov("test_churn_hot_promotes_no_peer_warm_for_less_than_its_tenure")]),
    ("CH3 a peer demoted lately may be made hot", GOVERNOR,
     '''                .is_none_or(|d| d.elapsed() > self.timeouts.dead_timeout)''',
     '''                .is_none_or(|_| true)''',
     [gov("test_churn_hot_promotes_no_peer_demoted_lately")]),
    ("CH4 a bootnode may be made hot", GOVERNOR,
     '''        peer.state == PeerState::Warm
            && !peer.is_bootnode
''',
     '''        peer.state == PeerState::Warm
''',
     [gov("test_churn_hot_promotes_no_bootnode")]),
    ("CH5 a warm swarm member may be made hot", GOVERNOR,
     '''            && !peer.is_swarm
            && peer
''',
     '''            && peer
''',
     [gov("test_churn_hot_promotes_no_swarm_member")]),
    ("CH6 hot churn demotes though no warm peer may take its place", GOVERNOR,
     ['''        if warm_peers.is_empty() {
            return;
        }

''',
      '''        let promoted = &warm_peers[self.random_index(warm_peers.len())];'''],
     ['''''',
      '''        if warm_peers.is_empty() {
            return;
        }
        let promoted = &warm_peers[self.random_index(warm_peers.len())];'''],
     [gov("test_churn_hot_demotes_none_where_no_warm_peer_may_take_its_place")]),
    ("CH7 hot churn may demote a trusted peer", GOVERNOR,
     '''            .filter(|p| p.state == PeerState::Hot && !self.is_trusted(p))
            .filter(|p| !(relay_spared && p.is_relay))''',
     '''            .filter(|p| p.state == PeerState::Hot)
            .filter(|p| !(relay_spared && p.is_relay))''',
     [gov("test_churn_hot_demotes_no_trusted_peer")]),
    ("CH8 hot churn promotes no trusted warm peer", GOVERNOR,
     '''            .filter(|p| self.may_be_made_hot(p) && Self::has_warm_tenure(p))''',
     '''            .filter(|p| self.may_be_made_hot(p) && Self::has_warm_tenure(p) && !self.is_trusted(p))''',
     [gov("test_churn_hot_may_promote_a_trusted_peer")]),
    ("CH9 hot churn promotes the first warm peer, not a random one", GOVERNOR,
     '''        let promoted = &warm_peers[self.random_index(warm_peers.len())];''',
     '''        let promoted = &warm_peers[0];''',
     [gov("test_churn_hot_promotes_a_random_warm_peer")]),
    # The picks below go back to the time modulo the count, as they were,
    # with the time from the governor's clock, which the tests make one
    # that counts in microseconds.
    ("CH10 the hot peer churn demotes is the time modulo the count", GOVERNOR,
     '''        let victim = &hot_peers[self.random_index(hot_peers.len())];''',
     '''        let victim = &hot_peers[(self.clock_nanos)() as usize % hot_peers.len()];''',
     [gov("test_churn_hot_demotes_a_random_hot_peer_on_a_microsecond_clock")]),
    ("CH11 step 4's shuffle is seeded by the time as it was", GOVERNOR,
     '''            let j = self.random_index(i + 1);''',
     '''            let j = (((self.clock_nanos)() as usize).wrapping_mul(i + 1).wrapping_add(7)) % (i + 1);''',
     [gov("test_step_4_promotes_a_random_warm_peer_on_a_microsecond_clock")]),
    ("CH12 the churn's jitter is the time modulo the jitter", GOVERNOR,
     '''            self.random_index(self.targets.churn_jitter_secs as usize + 1) as u64''',
     '''            (self.clock_nanos)() as u64 % self.targets.churn_jitter_secs''',
     [gov("test_churn_jitter_is_random_on_a_microsecond_clock")]),
    ("CH13 the churn's jitter is drawn again at every tick", GOVERNOR,
     '''            Some(jitter) => jitter,''',
     '''            Some(_) => self.draw_churn_jitter(),''',
     [gov("test_churn_jitter_is_random_on_a_microsecond_clock")]),
    ("CH14 hot churn may demote a relay while no more than hot_min_relays are hot", GOVERNOR,
     '''            .filter(|p| !(relay_spared && p.is_relay))
''',
     '''''',
     [gov("test_churn_hot_leaves_hot_relays_and_the_hot_count_as_they_were")]),
    ("CH15 step 4a promotes warm relays in the map's order", GOVERNOR,
     '''        for id in self.shuffled(warm_relays).into_iter().take(needed) {''',
     '''        for id in warm_relays.into_iter().take(needed) {''',
     [gov("test_step_4a_promotes_a_random_warm_relay_on_a_microsecond_clock")]),
    ("CH16 warm churn closes warm peers in the map's order", GOVERNOR,
     '''        let warm_ids: Vec<NodeId> = self
            .shuffled(warm_ids)
            .into_iter()''',
     '''        let warm_ids: Vec<NodeId> = warm_ids
            .into_iter()''',
     [gov("test_churn_warm_closes_a_random_warm_peer_on_a_microsecond_clock")]),
    ("CH17 warm churn dials cold peers in the map's order", GOVERNOR,
     '''        let cold_ids: Vec<NodeId> = self
            .shuffled(cold_ids)
            .into_iter()''',
     '''        let cold_ids: Vec<NodeId> = cold_ids
            .into_iter()''',
     [gov("test_churn_warm_dials_a_random_cold_peer_on_a_microsecond_clock")]),
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
