#!/usr/bin/env python3
"""Mutation checks for the counters of the scale test: the node's lock,
timed by kind, with the waits for the rates and the room apart; what a
relay is asked, by stream kind, with its answers and bytes; its
connections and those it turned away; its governor's churns, closures and
peers; what a device asked and held back; and the route that reads them
with no lock (decision 2026-10-22 §1.1, §1.2, §7.3). A part for each rule
of the slice: put each fault in, and confirm the test named for it fails
on an assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
LOAD = 'crates/cordelia-core/src/load.rs'
LOCK = 'crates/cordelia-core/src/lock.rs'
GOVERNOR = 'crates/cordelia-network/src/governor.rs'
CONNECTION = 'crates/cordelia-network/src/connection.rs'
RATE_LIMIT = 'crates/cordelia-network/src/rate_limit.rs'
MESSAGES = 'crates/cordelia-network/src/messages.rs'
RELAY = 'crates/cordelia-node/src/relay_entries.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
LEAVE = 'crates/cordelia-node/src/device_entries/leave.rs'
HANDLERS = 'crates/cordelia-api/src/handlers.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, LOAD, LOCK, GOVERNOR, CONNECTION, RATE_LIMIT,
                                    MESSAGES, RELAY, P2P, DEVICE, LEAVE, HANDLERS)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
NETWORK = ("cordelia-network", ["--lib"])
NODE_BIN = ("cordelia-node", ["--bin", "cordelia"])
NODE_LIB = ("cordelia-node", ["--lib"])
NODE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
API = ("cordelia-api", ["--lib"])
def core(test): return (CORE, test)
def network(test): return (NETWORK, test)
def relay(test): return (NODE_BIN, "relay_entries::tests::" + test)
def leave(test): return (NODE_LIB, "device_entries::leave::tests::" + test)
def e2e(test): return (NODE_E2E, test)
def api(test): return (API, "local::tests::" + test)

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The lock, timed by kind (§1.1, rule 4) ──
    ("L1 a hold is recorded as no kind but Other", LOCK,
     '''        self.times.hold[self.kind as usize].record(self.since.elapsed());''',
     '''        self.times.hold[Kind::Other as usize].record(self.since.elapsed());''',
     [core("lock::tests::a_take_is_recorded_as_the_kind_said_for_it_and_as_no_other")]),
    ("L2 a take that waits records no wait", LOCK,
     '''                let taken = self.inner.lock();
                let since = Instant::now();
                self.times.wait[kind as usize].record(since - asked);''',
     '''                let taken = self.inner.lock();
                let since = Instant::now();
                self.times.wait[kind as usize].record(Duration::ZERO + (since - since));
                let _ = asked;''',
     [core("lock::tests::a_hold_is_as_long_as_its_guard_lives_and_a_wait_as_long_as_another_holds_it")]),
    ("L3 a future's kind is not undone after its poll", LOCK,
     '''        let _kind = taking(self.kind);
        self.future.as_mut().poll(cx)''',
     '''        std::mem::forget(taking(self.kind));
        self.future.as_mut().poll(cx)''',
     [core("lock::tests::a_futures_takes_are_of_its_kind_and_not_of_what_runs_between_its_polls")]),
    ("L4 a wait for a mutex taken under the lock is not recorded", LOCK,
     '''        self.times.nested[which as usize].record(asked.elapsed());''',
     '''        let _ = (which, asked);''',
     [core("lock::tests::a_wait_for_a_mutex_taken_under_the_lock_is_recorded_apart")]),
    ("L5 a try that finds the lock held records a take", LOCK,
     '''            Err(TryLockError::WouldBlock) => return Err(TryLockError::WouldBlock),''',
     '''            Err(TryLockError::WouldBlock) => {
                self.times.wait[kind as usize].record(since - asked);
                return Err(TryLockError::WouldBlock);
            }''',
     [core("lock::tests::a_try_that_finds_the_lock_held_records_nothing")]),
    # ── What timing costs (§1.1, rule 5) ──
    ("T1 a record reads the clock 64 times more", LOAD,
     '''        let nanos = u64::try_from(length.as_nanos()).unwrap_or(u64::MAX);''',
     '''        for _ in 0..64 {
            std::hint::black_box(std::time::Instant::now());
        }
        let nanos = u64::try_from(length.as_nanos()).unwrap_or(u64::MAX);''',
     [core("lock::tests::timing_a_take_costs_under_one_hundredth_of_the_median_hold")]),
    ("T2 the bar on timing is a tenth of the median, not a hundredth", PROTOCOL,
     '''pub const LOCK_TIMING_COST_MAX_NANOS: u64 = LOCK_HOLD_MEDIAN_NANOS / 100;''',
     '''pub const LOCK_TIMING_COST_MAX_NANOS: u64 = LOCK_HOLD_MEDIAN_NANOS / 10;''',
     [core("protocol::tests::test_the_counters_of_the_scale_test_decision_2026_10_22_1_2")]),
    # ── The histograms (§1.2) ──
    ("H1 a length falls one bucket high", LOAD,
     '''        _ => (u64::BITS - (micros - 1).leading_zeros()) as usize,''',
     '''        _ => (u64::BITS - micros.leading_zeros()) as usize,''',
     [core("load::tests::a_length_falls_in_the_least_bucket_of_powers_of_two_that_holds_it")]),
    ("H2 a length of exactly 5 ms counts as over 5 ms", LOAD,
     '''            if micros > ms * 1000 {''',
     '''            if micros >= ms * 1000 {''',
     [core("load::tests::a_histogram_counts_sums_and_keeps_the_longest_and_those_over_each_length")]),
    ("H3 the buckets are said each alone, not summed", LOAD,
     '''        summed += n;''',
     '''        summed = *n;''',
     [core("load::tests::a_histogram_is_said_with_its_buckets_summed")]),
    # ── What a relay is asked, by stream kind (§1.2) ──
    ("S1 a request's kind in answer() is Other", RELAY,
     '''                .counted_as(Some(request))
                .map_or(Kind::Other, Stream::kind),''',
     '''                .counted_as(Some(request))
                .map_or(Kind::Other, |_| Kind::Other),''',
     [relay("each_take_of_the_lock_in_a_request_is_of_its_kind")]),
    ("S2 a sweep of old deletes is not said as a sweep", RELAY,
     '''    fn sweep_deletes_at(&self, db: &TimedLock<Connection>, now: i64) {
        let _sweep = taking(Kind::Sweep);''',
     '''    fn sweep_deletes_at(&self, db: &TimedLock<Connection>, now: i64) {''',
     [relay("each_take_of_the_lock_in_a_request_is_of_its_kind")]),
    ("S3 a relay's pull from a listed relay is not said as between relays", RELAY,
     '''        take_as(Kind::Relays, self.pulling_from(link, relay, db)).await''',
     '''        self.pulling_from(link, relay, db).await''',
     [relay("a_relays_pull_from_a_listed_relay_takes_the_lock_as_the_stream_between_relays")]),
    ("S4 the room is taken under the lock untimed in a push", RELAY,
     '''            let mut room = db.nested(Nested::Room, &self.room);
            let written = Self::written_as_one(&db, &mut room, entries, now);''',
     '''            let mut room = lock(&self.room);
            let written = Self::written_as_one(&db, &mut room, entries, now);''',
     [relay("a_wait_for_the_rates_or_the_room_under_the_lock_is_timed_apart")]),
    ("S5 the rates are taken under the lock untimed in a pull", RELAY,
     '''            && !db
                .nested(Nested::Rates, rates)
                .handed(who.peer, who.address, page.cost)''',
     '''            && !lock(rates).handed(who.peer, who.address, page.cost)''',
     [relay("a_wait_for_the_rates_or_the_room_under_the_lock_is_timed_apart")]),
    ("S6 a request's bytes in are counted without the frame's length", RELAY,
     '''        self.counts.read(stream, FRAME_LENGTH_BYTES + frame.len());''',
     '''        self.counts.read(stream, frame.len());''',
     [relay("each_request_served_is_counted_by_its_kind_with_its_bytes_and_what_became_of_it")]),
    ("S7 a pull refused for now is counted as not served", RELAY,
     '''            Answer::NotNow => Answered::NotNow,''',
     '''            Answer::NotNow => Answered::NotServed,''',
     [relay("each_request_served_is_counted_by_its_kind_with_its_bytes_and_what_became_of_it")]),
    ("S8 the bytes of an answer written are not counted", RELAY,
     '''            self.counts
                .wrote(stream, FRAME_LENGTH_BYTES + written.len());''',
     '''            let _ = (stream, written.len());''',
     [relay("each_request_served_is_counted_by_its_kind_with_its_bytes_and_what_became_of_it")]),
    ("S9 an entry refused for new channels is counted as for room", RELAY,
     '''            EntryRefused::OverLimit => Some(Refusal::NewChannels),''',
     '''            EntryRefused::OverLimit => Some(Refusal::Room),''',
     [relay("the_entries_refused_for_room_and_for_new_channels_are_told_from_an_answer")]),
    ("S10 a frame that is no message is not counted", RELAY,
     '''                self.count(protocol, None, &frame, Answered::Stray);''',
     '''                let _ = Answered::Stray;''',
     [relay("each_request_served_is_counted_by_its_kind_with_its_bytes_and_what_became_of_it")]),
    ("S11 a short show is counted as a whole one", MESSAGES,
     '''                Some(WireMessage::EntryShowShort(_)) => Some(Stream::ShowShort),''',
     '''                Some(WireMessage::EntryShowShort(_)) => Some(Stream::ShowWhole),''',
     [network("messages::tests::each_request_on_a_stream_of_entries_is_counted_as_its_kind")]),
    # ── Connections (§1.2) ──
    ("C1 a connection at its subnet's bound is counted for the address", RATE_LIMIT,
     '''        if subnet_count >= MAX_CONNECTIONS_PER_SUBNET {
            return Some(TurnedAway::Subnet);''',
     '''        if subnet_count >= MAX_CONNECTIONS_PER_SUBNET {
            return Some(TurnedAway::Address);''',
     [network("rate_limit::tests::a_connection_is_turned_away_for_the_bound_the_address_or_the_subnet")]),
    ("C2 a connection turned away before its handshake is not counted", P2P,
     '''                            // Counted by why (decision 2026-10-22 §1.2).
                            state.load.connections.turned_away(why);''',
     '''                            let _ = why;''',
     [e2e("a_relay_counts_who_it_turns_away_and_each_churn_where_warm_churn_closes_nothing")]),
    ("C3 the gauge is not set again as a connection goes", CONNECTION,
     '''        self.counts.closed(&node_id.0);
        self.counts.set_open(self.connections.len());''',
     '''        self.counts.closed(&node_id.0);''',
     [network("connection::tests::the_connections_open_and_gone_are_counted_as_each_is_made_and_goes")]),
    ("C4 a connection that goes is not counted", CONNECTION,
     '''        self.counts.closed(&node_id.0);
        self.counts.set_open(self.connections.len());''',
     '''        let _ = node_id;
        self.counts.set_open(self.connections.len());''',
     [network("connection::tests::the_connections_open_and_gone_are_counted_as_each_is_made_and_goes")]),
    # ── The governor (§1.2) ──
    ("G1 a churn is counted in warm churn, after its early return", GOVERNOR,
     ['''        self.counted.churned();
        self.churn_warm(actions);''',
      '''        tracing::info!(warm, cold, churn_count, "gov: periodic churn cycle");'''],
     ['''        self.churn_warm(actions);''',
      '''        tracing::info!(warm, cold, churn_count, "gov: periodic churn cycle");
        self.counted.churned();'''],
     [network("governor::tests::a_churn_is_counted_where_warm_churn_closes_nothing")]),
    ("G2 a relay closed by warm churn is counted as a device", GOVERNOR,
     '''                    true => Peer::Relay,''',
     '''                    true => Peer::Device,''',
     [network("governor::tests::warm_churn_counts_what_it_closes_of_devices_and_of_relays")]),
    ("G3 the governor's peers are not counted at its tick", GOVERNOR,
     '''        self.counted.set_peers(hot, warm, cold);''',
     '''        let _ = (hot, warm, cold);''',
     [network("governor::tests::the_governors_peers_are_counted_at_its_tick")]),
    # ── What a device asks (§1.2) ──
    ("D1 a request held back by the device's pace is not counted", LEAVE,
     '''        if !may {
            self.counts.held_back(&relay.0);
        }''',
     '''        let _ = relay;''',
     [leave("a_request_held_back_by_the_devices_own_pace_is_counted_for_its_relay")]),
    ("D2 a request refused for rate is not counted", LEAVE,
     '''        self.counts.refused_for_rate(&relay);''',
     '''        let _ = &relay;''',
     [leave("a_request_refused_for_rate_is_counted_for_its_relay")]),
    ("D3 a request is counted without its frame's length", LEAVE,
     '''        sent(FRAME_LENGTH_BYTES + frame.len());''',
     '''        sent(frame.len());''',
     [e2e("what_a_device_counts_it_asked_is_what_its_relay_counts_it_read")]),
    ("D4 a relay's turn in a pass is not said as a pass", DEVICE,
     '''            turns.spawn(take_as(TakeKind::Pass, async move {
                engine.turn(&link, kind, shown).await
            }));''',
     '''            turns.spawn(async move { engine.turn(&link, kind, shown).await });''',
     [e2e("what_a_device_counts_it_asked_is_what_its_relay_counts_it_read")]),
    # ── The route (§1.1, rule 3) ──
    ("R1 the route takes the store's lock", HANDLERS,
     '''    auth::check_token(&req, &state)?;
    let body = cordelia_core::load::render(&state.load, state.db.times(), state.uptime_secs());''',
     '''    auth::check_token(&req, &state)?;
    let _db = state.db.lock();
    let body = cordelia_core::load::render(&state.load, state.db.times(), state.uptime_secs());''',
     [api("the_route_of_the_counters_takes_no_lock")]),
    ("R2 the route asks whether the node is held up, under its lock", HANDLERS,
     '''    auth::check_token(&req, &state)?;
    let body = cordelia_core::load::render(&state.load, state.db.times(), state.uptime_secs());''',
     '''    auth::check_bearer(&req, &state)?;
    let body = cordelia_core::load::render(&state.load, state.db.times(), state.uptime_secs());''',
     [api("the_route_of_the_counters_takes_no_lock")]),
    ("R3 the route asks for no token", HANDLERS,
     '''    auth::check_token(&req, &state)?;
    let body = cordelia_core::load::render(&state.load, state.db.times(), state.uptime_secs());''',
     '''    let _ = &req;
    let body = cordelia_core::load::render(&state.load, state.db.times(), state.uptime_secs());''',
     [api("the_route_of_the_counters_says_each_as_it_moved_to_whoever_has_the_token")]),
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
