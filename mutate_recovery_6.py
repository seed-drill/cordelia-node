#!/usr/bin/env python3
"""Mutation checks for a pull of a device's own channel with places of
its own, slice 6 of decision 2026-10-17 (section 4.2, items 1 to 3): a
page taken through take_page and the one door without writing the
stored place or what was sent, the read's places and notes kept in
memory under its ID, read on round by round, within the pass's budget at
each relay, and outside the database's lock. A part for each rule of the
slice: put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
AT_RELAYS = 'crates/cordelia-api/src/at_relays.rs'
OWN_READ = 'crates/cordelia-api/src/own_read.rs'
NODE_READ = 'crates/cordelia-node/src/device_entries/own_read.rs'
ORIG = {f: open(f).read() for f in (AT_RELAYS, OWN_READ, NODE_READ)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def at_relays(test): return (API, "at_relays::tests::" + test)
def own_read(test): return (API, "own_read::tests::" + test)
def e2e(test): return (E2E, test)

LEAVES = at_relays("test_a_page_under_places_of_a_reads_own_leaves_the_stored_place_and_what_was_sent")
READ_AGAIN = at_relays("test_a_page_under_places_of_a_reads_own_that_makes_a_key_count_has_everything_read_again")
KEPT_PULL = at_relays("test_a_pull_goes_on_from_the_place_kept_and_from_the_start_under_another_mark")
STARTS = own_read("test_a_read_starts_from_the_start_and_goes_on_from_the_place_each_page_reaches")
TO_ITS_END = own_read("test_a_relay_is_read_to_its_end_by_a_page_of_nothing_or_one_that_leaves_the_place")
HOLDS_NONE = own_read("test_a_relay_that_holds_none_and_one_that_handed_part_and_then_holds_none")
NOT_THE_PAGE = own_read("test_a_page_that_is_not_the_channels_leaves_the_relay_read_in_part")
NOTED = own_read("test_what_each_relay_handed_is_noted_in_each_slot")
NOT_REACHED = own_read("test_a_relay_not_reached_in_a_round_is_not_read_on")
KEPT_UNDER_ID = own_read("test_a_read_is_kept_under_its_id_and_a_new_read_of_its_channel_takes_its_place")
E2E_STARTS = e2e("a_read_with_places_of_its_own_starts_from_the_start_and_leaves_the_stored_place_and_what_was_sent")
E2E_LOCK = e2e("a_read_with_places_of_its_own_does_not_hold_the_lock_while_it_reads")
E2E_READS_ON = e2e("a_read_with_places_of_its_own_reads_on_under_its_id_from_the_place_it_reached")
E2E_TAKES = e2e("a_read_with_places_of_its_own_takes_within_what_the_pass_takes_from_a_relay")
E2E_ASKS = e2e("a_read_with_places_of_its_own_asks_within_what_the_device_asks_of_a_relay")

OWN_BRANCH = '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            if read_again {'''

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("TP1 a page of a read's own writes the stored place", AT_RELAYS,
     OWN_BRANCH,
     '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            if page.mark != NO_MARK {
                kept_rows::keep_place(conn, page.relay, &page.channel.id, &page.mark, page.next)?;
            }
            if read_again {''',
     [LEAVES]),
    ("TP2 a page of a read's own marks what it brought as sent", AT_RELAYS,
     OWN_BRANCH,
     '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            let last = kept_rows::last_taken(conn, &page.channel.id)?;
            kept_rows::sent(conn, page.relay, &page.channel.id, last)?;
            if read_again {''',
     [LEAVES]),
    ("TP3 a page of a read's own under no holding starts the relay again", AT_RELAYS,
     OWN_BRANCH,
     '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            if page.mark == NO_MARK && page.entries.is_empty() {
                kept_rows::start_again(conn, page.relay, &page.channel.id)?;
            }
            if read_again {''',
     [LEAVES]),
    ("TP4 a page of a read's own that makes a key count forgets no place", AT_RELAYS,
     '''            if read_again {
                kept_rows::forget_places(conn)?;
            }
            Ok(PageTaken::Taken { each, read_again })
        });''',
     '''            Ok(PageTaken::Taken { each, read_again })
        });''',
     [READ_AGAIN]),
    ("TP5 a pass's page is taken as a read's own", AT_RELAYS,
     '''    if places == Places::Own {''',
     '''    if places == Places::Own || places == Places::Kept {''',
     [KEPT_PULL]),
    ("TP6 a read's own page is taken as a pass's", AT_RELAYS,
     '''    if places == Places::Own {''',
     '''    if places != Places::Own && places == Places::Own {''',
     [LEAVES]),
    ("OR1 a read starts at a place that is not the start", OWN_READ,
     '''            place: (NO_MARK, 0),''',
     '''            place: (NO_MARK, 1),''',
     [STARTS, KEPT_UNDER_ID]),
    ("OR2 a page that is not the channel's is read on", OWN_READ,
     '''                self.read = ReadAt::InPart;
                return false;''',
     '''                self.read = ReadAt::Reading;
                return false;''',
     [NOT_THE_PAGE]),
    ("OR3 holding none and read in part are swapped", OWN_READ,
     '''                true => ReadAt::HoldsNone,
                false => ReadAt::InPart,''',
     '''                true => ReadAt::InPart,
                false => ReadAt::HoldsNone,''',
     [HOLDS_NONE]),
    ("OR4 the mark of no holding is not read as holding none", OWN_READ,
     '''        if mark == NO_MARK && entries.is_empty() {''',
     '''        if mark == NO_MARK && entries.is_empty() && false {''',
     [HOLDS_NONE]),
    ("OR5 a page that leaves the place is not the end", OWN_READ,
     '''        if entries.is_empty() || (mark, next) == self.place {''',
     '''        if entries.is_empty() {''',
     [TO_ITS_END]),
    ("OR6 a page of nothing that moves the place is not the end", OWN_READ,
     '''        if entries.is_empty() || (mark, next) == self.place {''',
     '''        if (mark, next) == self.place {''',
     [TO_ITS_END]),
    ("OR7 the place does not move with the page", OWN_READ,
     '''        self.place = (mark, next);''',
     '''        let _ = (mark, next);''',
     [STARTS]),
    ("OR8 an entry handed again is noted twice", OWN_READ,
     '''            if !slot.iter().any(|held| held.id() == entry.id()) {''',
     '''            if !slot.iter().any(|held| held.id() == entry.id()) || true {''',
     [NOTED]),
    ("OR9 what was handed is not noted", OWN_READ,
     '''                slot.push(entry.clone());''',
     '''                let _ = entry;''',
     [NOTED, STARTS]),
    ("OR10 a relay not reached is read in part with nothing handed", OWN_READ,
     '''            true => ReadAt::NotReached,
            false => ReadAt::InPart,''',
     '''            true => ReadAt::InPart,
            false => ReadAt::NotReached,''',
     [NOT_REACHED]),
    ("OR11 a relay read in part and stopped is read on", OWN_READ,
     '''        self == Self::Reading''',
     '''        self != Self::ToItsEnd''',
     [NOT_THE_PAGE, KEPT_UNDER_ID]),
    ("OR12 what was handed is not counted", OWN_READ,
     '''                self.bytes += counted;
                (entries, mark, next)''',
     '''                (entries, mark, next)''',
     [STARTS]),
    ("OR13 a new read of a channel keeps the one before", OWN_READ,
     '''        reads.retain(|_, kept| kept.channel != *channel);''',
     '''        reads.retain(|_, _| true);''',
     [KEPT_UNDER_ID]),
    ("OR14 a round is taken while another runs", OWN_READ,
     '''.filter(|kept| !kept.reading)?;''',
     '''.filter(|_| true)?;''',
     [KEPT_UNDER_ID]),
    ("OR15 a round takes every relay, not those read in part", OWN_READ,
     '''            .filter(|at| at.read.reads_on())''',
     '''            .filter(|_| true)''',
     [KEPT_UNDER_ID]),
    ("OR16 a round that ends leaves the read running", OWN_READ,
     '''        kept.reading = false;''',
     '''        let _ = &kept.reading;''',
     [KEPT_UNDER_ID]),
    ("OR17 every read is named by the same ID", OWN_READ,
     '''        id.copy_from_slice(&random[..16]);''',
     '''        let _ = random;''',
     [KEPT_UNDER_ID]),
    ("NR1 the node takes a read's page as a pass's", NODE_READ,
     '''take_page(db, identity, &page, Places::Own, now)''',
     '''take_page(db, identity, &page, Places::Kept, now)''',
     [E2E_STARTS]),
    ("NR2 the node reads from the place that the pass keeps", NODE_READ,
     '''            let (mark, after) = at.place;''',
     '''            let (mark, after) = at_relays::place(&lock(&self.state.db), &relay, &channel.id)
                .unwrap_or(at.place);''',
     [E2E_STARTS]),
    ("NR3 the read's proof answered no starts the relay again", NODE_READ,
     '''self.prove(&asks, channel, false)''',
     '''self.prove(&asks, channel, true)''',
     [E2E_STARTS]),
    ("NR4 the read takes beyond the minute's room", NODE_READ,
     '''            if !self.room_to_take(link) {''',
     '''            if !self.room_to_take(link) && false {''',
     [E2E_TAKES]),
    ("NR5 what the read takes is not counted with the pass", NODE_READ,
     '''                        self.took(link, handed);''',
     '''                        let _ = handed;''',
     [E2E_TAKES]),
    ("NR6 asked enough ends the relay's read instead of waiting", NODE_READ,
     '''                Err(Refused::AskedEnough) => {''',
     '''                Err(Refused::NotARequest) => {''',
     [E2E_ASKS]),
    ("NR7 the read holds the database's lock", NODE_READ,
     '''        let relay = link.relay().0;
        loop {''',
     '''        let relay = link.relay().0;
        std::mem::forget(lock(&self.state.db));
        loop {''',
     [E2E_LOCK]),
    ("NR8 a channel that a pass does not pull begins a read", NODE_READ,
     '''            if !own.iter().any(|own| own.id == *channel && own.is_pulled()) {''',
     '''            if !own.iter().any(|own| own.id == *channel && own.is_pulled()) && false {''',
     [E2E_READS_ON]),
    ("NR9 a read that the node does not know is answered as known", NODE_READ,
     '''        let Some((channel, under, at)) = reads.to_read(read) else {
            return false;''',
     '''        let Some((channel, under, at)) = reads.to_read(read) else {
            return true;''',
     [E2E_READS_ON]),
    ("NR10 a relay not connected stays read on", NODE_READ,
     '''                    one.not_reached();''',
     '''                    let _ = &mut one;''',
     [E2E_READS_ON]),
    ("NR11 a node that is held up begins a read", NODE_READ,
     '''        if self.state.held.why().is_some() {
            return None;
        }''',
     '''''',
     [E2E_READS_ON]),
    ("NR12 a node that is held up reads a round", NODE_READ,
     '''(self.state.held.why().is_none())''',
     '''(true)''',
     [E2E_READS_ON]),
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
