#!/usr/bin/env python3
"""Mutation checks for the messages channel's plumbing: the channel is
derived on a device with sync on, is last in a pass, is taken through the
one door, records its first fetch, has no place past the limit on proofs
by the room a connection has and sends none of it then, is not read
through the door for a carry, goes from the store at a statement and at leaving, and is left out of
every fact that feeds a status's level or a command's warning (decision
2026-10-09 §2.1, §2.3, §8, §9.1). A part for each rule of the slice: put
each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
AT_RELAYS = 'crates/cordelia-api/src/at_relays.rs'
TAKE = 'crates/cordelia-api/src/take.rs'
LEAVING = 'crates/cordelia-api/src/leaving.rs'
PERSON = 'crates/cordelia-api/src/person.rs'
ADDING = 'crates/cordelia-api/src/adding.rs'
STATE = 'crates/cordelia-api/src/state.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
LEAVE = 'crates/cordelia-node/src/device_entries/leave.rs'
ORIG = {f: open(f).read() for f in (AT_RELAYS, TAKE, LEAVING, PERSON, ADDING, STATE, DEVICE, LEAVE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def at_relays(test): return (API, "at_relays::tests::" + test)
def take(test): return (API, "take::tests::" + test)
def leaving(test): return (API, "leaving::tests::" + test)
def person(test): return (API, "person::tests::" + test)
def e2e(test): return (E2E, test)

LAST = at_relays("test_the_messages_channel_is_last_in_the_pass")
DOOR = take("test_the_door_takes_the_messages_channel_as_a_channel_of_the_persons_own")
WAITS = leaving("test_the_messages_channel_is_not_counted_as_waiting_or_refused")
FORGETS = leaving("test_a_device_that_forgets_keeps_its_names_and_nothing_else_of_its_person")
APPLIES = person("test_applying_a_statement_drops_the_messages_channel_that_is_left_and_carries_none")
TWO = e2e("two_devices_of_one_person_each_hold_the_messages_channel_after_a_pass")
REACHES = e2e("an_entry_in_the_messages_channel_reaches_the_other_device_through_a_relay")
SYNC_OFF = e2e("with_sync_off_the_messages_channel_is_neither_pushed_nor_pulled")
FIRST_FETCH = e2e("a_pass_that_reads_the_messages_channel_to_its_end_records_its_first_fetch")
PAST_LIMIT = e2e("past_the_limit_on_proofs_a_device_has_no_messages_and_says_so")
FILLED = e2e("a_filled_messages_channel_makes_no_pass_short")
NO_ROOM = e2e("a_refusal_for_room_of_the_messages_channel_is_said_of_no_relay")
STATEMENT = e2e("a_pass_that_stops_at_the_messages_channel_after_a_statement_is_short")
PLACE_TAKEN = e2e("a_place_taken_by_a_channel_held_no_more_leaves_the_messages_channel_none")
CARRY = e2e("the_messages_channel_is_not_read_through_the_door_for_a_carry")
AFRESH = e2e("the_word_that_the_messages_channel_has_no_place_is_said_afresh")
ANOTHER = e2e("a_message_answered_another_is_not_said_in_another_form")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("C1 the messages channel is not in a pass at all", AT_RELAYS,
     '''        own.push(messages);''',
     '''        let _ = messages;''',
     [LAST, TWO]),
    ("C2 the messages channel comes before the names", AT_RELAYS,
     '''        own.push(messages);''',
     '''        own.insert(1, messages);''',
     [LAST]),
    ("C3 the messages channel is in a pass with sync off", AT_RELAYS,
     '''    if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_some() {
        own.push(messages);''',
     '''    if true {
        own.push(messages);''',
     [LAST, SYNC_OFF]),
    ("C4 with sync off an entry of its own makes the messages channel a pair channel", AT_RELAYS,
     '''        .filter(|id| *id != messages.id && !own.iter().any(|channel| channel.id == *id))''',
     '''        .filter(|id| !own.iter().any(|channel| channel.id == *id))''',
     [LAST, SYNC_OFF]),
    ("C5 the messages channel is derived under the personal channel's label", AT_RELAYS,
     '''    let messages = derive::messages_secret(&standing.secret)?;
    let messages = Own {''',
     '''    let messages = derive::personal_secret(&standing.secret)?;
    let messages = Own {''',
     [LAST]),
    ("P1 no place is said only past one more than the limit", DEVICE,
     '''        proved.is_none_or(|proved| proved.contains_key(channel) || proved.len() < self.most_proved)''',
     '''        proved.is_none_or(|proved| proved.contains_key(channel) || proved.len() <= self.most_proved)''',
     [PAST_LIMIT, PLACE_TAKEN]),
    ("P2 no place is said at the limit itself", DEVICE,
     '''        proved.is_none_or(|proved| proved.contains_key(channel) || proved.len() < self.most_proved)''',
     '''        proved.is_none_or(|proved| proved.contains_key(channel) || proved.len() + 1 < self.most_proved)''',
     [PAST_LIMIT, PLACE_TAKEN]),
    ("P3 a channel proved on the connection already has no place there", DEVICE,
     '''        proved.is_none_or(|proved| proved.contains_key(channel) || proved.len() < self.most_proved)''',
     '''        proved.is_none_or(|proved| proved.len() < self.most_proved)''',
     [PAST_LIMIT]),
    ("P4 a device with no messages channel is said to have no place", DEVICE,
     '''        let no_place = messages
            .is_some_and(|messages| links.iter().any(|link| !self.has_room(link, &messages)));''',
     '''        let no_place = messages
            .is_none_or(|messages| links.iter().any(|link| !self.has_room(link, &messages)));''',
     [AFRESH]),
    ("Q1 no place is said by counting the device's channels, not by the connection's room", DEVICE,
     '''        let no_place = messages
            .is_some_and(|messages| links.iter().any(|link| !self.has_room(link, &messages)));''',
     '''        let own = at_relays::channels(&lock(&self.state.db), &self.state.identity);
        let own = own.unwrap_or_default();
        let _ = links;
        let no_place = messages.is_some()
            && own.iter().filter(|own| own.is_pulled()).count() > self.most_proved;''',
     [PLACE_TAKEN]),
    ("M1 the pass that sends pushes the messages channel past the limit on proofs", DEVICE,
     '''            if messages && !self.has_room(link, &channel.id) {''',
     '''            if whole && messages && !self.has_room(link, &channel.id) {''',
     [PAST_LIMIT]),
    ("G1 a pass that stops at the messages channel after a statement is not short", DEVICE,
     '''        whole
            && matches!(at_relays::kept_id(&lock(&self.state.db)), Ok(Some(kept)) if kept == at.under)''',
     '''        whole''',
     [STATEMENT]),
    ("G2 a pass that stops at the messages channel under the entry it began under is short", DEVICE,
     '''Ok(Some(kept)) if kept == at.under)''',
     '''Ok(Some(kept)) if kept != at.under)''',
     [STATEMENT, FILLED]),
    ("K1 the door for a carry reads the messages channel with sync off", LEAVE,
     '''        if own.iter().any(|own| own.id == *channel) || messages == Some(*channel) {''',
     '''        let _ = messages;
        if own.iter().any(|own| own.id == *channel) {''',
     [CARRY]),
    ("X1 with no relay connected the word that there is no place stays", DEVICE,
     '''        self.state.own_channels.say_no_place(no_place);''',
     '''        if !links.is_empty() {
            self.state.own_channels.say_no_place(no_place);
        }''',
     [AFRESH]),
    ("X2 a device with no messages channel leaves the word that there is no place as it was", DEVICE,
     '''        let no_place = messages
            .is_some_and(''',
     '''        let Some(messages) = messages else { return };
        let no_place = Some(messages)
            .is_some_and(''',
     [AFRESH]),
    ("D1 the door does not take the messages channel", TAKE,
     '''    if !is_personal && !is_messages && held_rows::name_of_channel(conn, &entry.channel)?.is_none() {''',
     '''    if !is_personal && held_rows::name_of_channel(conn, &entry.channel)?.is_none() {''',
     [DOOR, REACHES]),
    ("D2 the door takes the messages channel on a device that has stopped", TAKE,
     '''    if held.state != State::Applied {''',
     '''    if held.state != State::Applied && !is_messages {''',
     [DOOR]),
    ("D3 the door takes the messages channel from a signer that does not count", TAKE,
     '''    if !counting.counts(&entry.author) {''',
     '''    if !counting.counts(&entry.author) && !is_messages {''',
     [DOOR, REACHES]),
    ("D4 the door takes the messages channel in a band above the statement's", TAKE,
     '''    if band(entry.rev) > statement.number {''',
     '''    if band(entry.rev) > statement.number && !is_messages {''',
     [DOOR]),
    ("D5 a messages channel that was left is not refused as an old channel", TAKE,
     '''        for secret in [personal, messages] {
            if derive::channel_id(&secret)? == entry.channel {''',
     '''        for secret in [personal, personal] {
            let _ = messages;
            if derive::channel_id(&secret)? == entry.channel {''',
     [DOOR]),
    ("W1 what waits in the messages channel is counted as waiting", LEAVING,
     '''        if channel.kind == Kind::Messages {
            continue;
        }''',
     '''''',
     [WAITS, NO_ROOM]),
    ("S1 the messages channel that is left stays in the store at a statement", PERSON,
     '''        entries::remove_channel(conn, &messages)?;
        kept_rows::forget_channel(conn, &messages)?;''',
     '''        kept_rows::forget_channel(conn, &messages)?;''',
     [APPLIES]),
    ("S2 what was kept of each relay for the messages channel that is left stays", PERSON,
     '''        entries::remove_channel(conn, &messages)?;
        kept_rows::forget_channel(conn, &messages)?;''',
     '''        entries::remove_channel(conn, &messages)?;''',
     [APPLIES]),
    ("S3 a device that forgets keeps its messages channel", ADDING,
     '''        for secret in [personal, messages] {''',
     '''        for secret in [personal] {
            let _ = messages;''',
     [FORGETS]),
    ("F1 a whole read of the messages channel is not recorded as its first fetch", DEVICE,
     '''                if read_to_its_end && matches!(channel.kind, Kind::Name(_) | Kind::Messages) {''',
     '''                if read_to_its_end && matches!(channel.kind, Kind::Name(_)) {''',
     [FIRST_FETCH, TWO]),
    ("F2 a part read of the messages channel is recorded as its first fetch", DEVICE,
     '''                if read_to_its_end && matches!(channel.kind, Kind::Name(_) | Kind::Messages) {''',
     '''                if (read_to_its_end || messages) && matches!(channel.kind, Kind::Name(_) | Kind::Messages) {''',
     [FIRST_FETCH]),
    ("R1 a proof of the messages channel that was not sent makes the pass short", DEVICE,
     '''                        read_all &= messages;''',
     '''                        read_all = false;''',
     [FILLED]),
    ("R2 a pull of the messages channel that did not reach its end makes the pass short", DEVICE,
     '''                read_all &= read_to_its_end || messages;''',
     '''                read_all &= read_to_its_end;''',
     [FILLED]),
    ("R3 a relay that stops answering at the messages channel makes the pass short", DEVICE,
     '''            let stopped = messages && read_all;''',
     '''            let stopped = false && messages && read_all;''',
     [FILLED, STATEMENT]),
    ("R4 a pull of a name that did not reach its end leaves the pass whole", DEVICE,
     '''                read_all &= read_to_its_end || messages;''',
     '''                read_all &= read_to_its_end || true;''',
     [FILLED]),
    ("N1 no place is never said", DEVICE,
     '''        self.state.own_channels.say_no_place(no_place);''',
     '''        self.state.own_channels.say_no_place(false && no_place);''',
     [PAST_LIMIT]),
    ("N2 no place is said by the relays' limit and not the device's", DEVICE,
     '''        proved.is_none_or(|proved| proved.contains_key(channel) || proved.len() < self.most_proved)''',
     '''        proved.is_none_or(|proved| proved.contains_key(channel) || proved.len() < MAX_CHANNELS_PROVED_ON_A_CONNECTION)''',
     [PAST_LIMIT]),
    ("N3 what the node said of no place is not kept", STATE,
     '''        self.no_place.load(Ordering::SeqCst)''',
     '''        let _ = self.no_place.load(Ordering::SeqCst);
        false''',
     [PAST_LIMIT]),
    ("A1 an entry of the messages channel at a relay in another form is said", DEVICE,
     '''            if done.another > 0 && channel.kind != Kind::Messages {''',
     '''            if done.another > 0 {''',
     [ANOTHER]),
    ("A2 nothing of a name in another form is said", DEVICE,
     '''            if done.another > 0 && channel.kind != Kind::Messages {''',
     '''            if done.another > 0 && false {''',
     [ANOTHER]),
    ("O1 a relay with no room for the messages channel sets a hold", DEVICE,
     '''                if channel.kind != Kind::Messages {
                    self.no_room(link, done.refused == Some(Pushed::OverAllowance), false);
                }''',
     '''                self.no_room(link, done.refused == Some(Pushed::OverAllowance), false);''',
     [NO_ROOM]),
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
