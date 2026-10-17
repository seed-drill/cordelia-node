#!/usr/bin/env python3
"""Mutation checks for the order in which a reader keeps the records that
do not count (decision 2026-10-17 section 2.2, with 2.1 and 2.7; section
10, slice 2): `keep_to_the_bound` in crates/cordelia-api/src/person.rs and
`KEPT_OUT_PER_ADDER` in protocol.rs. A part for each rule of the slice: put
each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
PERSON = 'crates/cordelia-api/src/person.rs'
ADDITION = 'crates/cordelia-crypto/src/addition.rs'
TAKE = 'crates/cordelia-api/src/take.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, PERSON, ADDITION, TAKE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
API = ("cordelia-api", ["--lib"])
CRYPTO = ("cordelia-crypto", ["--lib"])
def crypto(test): return (CRYPTO, "addition::tests::" + test)
def core(test): return (CORE, "protocol::tests::" + test)
def person(test): return (API, "person::tests::" + test)
def take(test): return (API, "take::tests::" + test)

KEPT_OUT = core("test_each_adder_keeps_its_first_three_kept_out_decision_2026_10_17_2_2")
BOUND = person("test_the_records_kept_as_not_counted_have_a_bound")
FROM_THE_END = person("test_the_records_that_do_not_count_go_from_the_end_of_the_order_of_keeping")
FLOOD = person("test_a_flood_of_records_keeps_each_adders_first_three_kept_out")
FLOOR = person("test_at_every_bound_each_adder_that_may_add_keeps_its_first_three_kept_out")
ONE_PLACE = person("test_an_adder_has_one_place_for_each_key")
IN_A_TURN = person("test_within_a_turn_the_devices_of_the_statement_come_first_in_its_order")
MAY_NOT_ADD = person("test_records_whose_adder_may_not_add_yet_are_dealt_to_their_adders_in_turn")
NOT_THE_ORDER_SEEN = person("test_the_records_kept_do_not_turn_on_the_order_they_were_seen")
LETS_ADD = person("test_the_record_that_lets_a_key_add_does_not_turn_on_the_order_seen")
WHO_COUNTS = person("test_who_counts_does_not_turn_on_which_records_beyond_the_bound_were_kept")
THE_REST_IN_ONE_TIME = person("test_of_the_rest_two_that_say_one_time_go_by_key_and_then_adder")
COMES_TO_ADD = person("test_a_key_whose_adder_comes_to_add_after_a_flood_keeps_its_first_three")
NOT_WORKED_OUT = person("test_within_the_bound_the_order_of_keeping_is_not_worked_out")
NOT_CHECKED_AGAIN = person("test_a_row_is_ordered_by_its_time_without_its_record_checked_again")
TIME_OF = crypto("the_time_of_a_signed_record_is_read_without_checking_the_record")
GIVEN_AGAIN = take("test_a_record_that_went_at_the_bound_counts_when_its_entry_is_given_again")
TAKE_FLOOD = take("test_a_flood_of_records_drops_none_that_lets_a_key_add")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # KEPT_OUT_PER_ADDER (decision 2026-10-17 §2.7).
    ("K1 what a reader keeps is less what 128 records take, not 63", PROTOCOL,
     '''    let kept = (MAX_NOT_COUNTED_RECORDS - (MAX_COUNTED_DEVICES - 1)) / MAX_COUNTED_DEVICES;''',
     '''    let kept = (MAX_NOT_COUNTED_RECORDS - 2 * MAX_COUNTED_DEVICES) / MAX_COUNTED_DEVICES;''',
     [KEPT_OUT, FLOOR]),
    ("K2 one less than the lesser of the two quotients", PROTOCOL,
     '''    if kept < shown { kept } else { shown }''',
     '''    if kept < shown { kept - 1 } else { shown - 1 }''',
     [KEPT_OUT, FLOOR]),

    # The bound, and where it is kept (decision 2026-10-04 §6).
    ("B1 one record more than the bound is kept", PERSON,
     '''    for record in order.iter().skip(MAX_NOT_COUNTED_RECORDS) {''',
     '''    for record in order.iter().skip(MAX_NOT_COUNTED_RECORDS + 1) {''',
     [BOUND, FLOOD, TAKE_FLOOD]),
    ("B2 nothing beyond the bound is dropped", PERSON,
     '''        held_rows::drop_not_counted(conn, record.seen)?;''',
     '''        let _ = record;''',
     [BOUND, FLOOD]),
    ("B3 a record that is seen is not kept to the bound", PERSON,
     '''        judge_again(conn, statement)?;
        keep_to_the_bound(conn, statement)?;''',
     '''        judge_again(conn, statement)?;''',
     [BOUND]),
    ("B4 a record kept as not counted is not judged again (§2.7)", PERSON,
     '''        judge_again(conn, statement)?;
        keep_to_the_bound(conn, statement)?;''',
     '''        keep_to_the_bound(conn, statement)?;''',
     [WHO_COUNTS]),

    # The order of seeing is not the order of keeping (§1, property 2).
    ("O1 the oldest seen goes first, as before", PERSON,
     '''    let order = in_the_order_of_keeping(statement, &counting, &kept);''',
     '''    let _ = in_the_order_of_keeping(statement, &counting, &kept);
    let (mut order, mut may_go): (Vec<&KeptAddition>, Vec<&KeptAddition>) =
        (Vec::new(), Vec::new());
    for record in kept.iter().filter(|record| !record.counted) {
        if counting.lets_add(&record.key, &record.adder)
            && !order.iter().any(|one| one.key == record.key)
        {
            order.push(record);
        } else {
            may_go.push(record);
        }
    }
    order.extend(may_go.into_iter().rev());''',
     [FLOOD, NOT_THE_ORDER_SEEN, LETS_ADD, MAY_NOT_ADD]),

    # The order is worked out only beyond the bound, and reads a row's
    # time without checking its record again.
    ("E1 the order is worked out within the bound too", PERSON,
     '''    if kept.iter().filter(|row| !row.counted).count() <= MAX_NOT_COUNTED_RECORDS {
        return Ok(());
    }''',
     '''''',
     [NOT_WORKED_OUT]),
    ("E2 the order is not worked out at one record past the bound", PERSON,
     '''    if kept.iter().filter(|row| !row.counted).count() <= MAX_NOT_COUNTED_RECORDS {''',
     '''    if kept.iter().filter(|row| !row.counted).count() <= MAX_NOT_COUNTED_RECORDS + 1 {''',
     [BOUND, NOT_WORKED_OUT]),
    ("E3 the order is worked out at the bound itself", PERSON,
     '''    if kept.iter().filter(|row| !row.counted).count() <= MAX_NOT_COUNTED_RECORDS {''',
     '''    if kept.iter().filter(|row| !row.counted).count() < MAX_NOT_COUNTED_RECORDS {''',
     [NOT_WORKED_OUT]),
    ("E4 a row's record is checked again to read its time", PERSON,
     '''        let at = SignedAddition::time_of(&row.record).unwrap_or(u64::MAX);''',
     '''        let at = SignedAddition::from_bytes(&row.record)
            .map_or(u64::MAX, |record| record.addition.at);''',
     [NOT_CHECKED_AGAIN]),
    ("E5 the time is read without passing over the label", ADDITION,
     '''        reader.take(length)?;
        reader.u64()''',
     '''        let _ = length;
        reader.u64()''',
     [TIME_OF]),
    ("E6 the time is read from bytes that end before it", ADDITION,
     '''        reader.take(length)?;
        reader.u64()''',
     '''        reader.take(length)?;
        Some(reader.u64().unwrap_or(0))''',
     [TIME_OF]),
    ("E7 an entry given again is never read again, though its record went", TAKE,
     '''    if again && (is_kept(conn, &record)? || !is_the_entry_held(conn, entry)?) {''',
     '''    if again {''',
     [GIVEN_AGAIN]),

    # A record's time.
    ("T1 a row whose bytes are no record says the earliest time", PERSON,
     '''        let at = SignedAddition::time_of(&row.record).unwrap_or(u64::MAX);''',
     '''        let at = SignedAddition::time_of(&row.record).unwrap_or(0);''',
     [BOUND]),
    ("T2 among records of one key, the first seen and not the oldest by its time", PERSON,
     '''        (self.at, &self.row.record)''',
     '''        (self.row.seen as u64, &self.row.record)''',
     [LETS_ADD]),
    ("T3 among records of one key that say one time, no order by bytes", PERSON,
     '''        (self.at, &self.row.record)''',
     '''        (self.at, &[][..])''',
     [LETS_ADD]),

    # The first group: the records that let a key add.
    ("G1 no record is kept as one that lets a key add", PERSON,
     '''        if counting.lets_add(&row.key, &row.adder) {''',
     '''        if false && counting.lets_add(&row.key, &row.adder) {''',
     [FROM_THE_END, TAKE_FLOOD]),
    ("G2 every record that lets a key add is in the first group, not one for each key", PERSON,
     '''    let first = one_for_each_key(let_add, &mut rest);''',
     '''    let first = let_add;''',
     [LETS_ADD]),

    # The second and third groups, and the rest.
    ("G3 a record whose key the 64 kept out is among the rest", PERSON,
     '''                Some(NotCounted::NoRoom) => kept_out.push(record),''',
     '''                Some(NotCounted::NoRoom) => rest.push(record),''',
     [FROM_THE_END]),
    ("G4 a record whose adder may not add yet is among the rest", PERSON,
     '''                    may_not_add.push(record)''',
     '''                    rest.push(record)''',
     [FROM_THE_END]),
    ("G5 a record whose adder does not count is among those that may not add", PERSON,
     '''                Some(NotCounted::MayNotAdd) if counting.counts(&row.adder) => {''',
     '''                Some(NotCounted::MayNotAdd) => {''',
     [FROM_THE_END]),
    ("G6 the records whose adder may not add are kept before those the 64 kept out", PERSON,
     '''        .chain(kept_out)
        .chain(may_not_add)''',
     '''        .chain(may_not_add)
        .chain(kept_out)''',
     [FROM_THE_END, COMES_TO_ADD]),
    ("G7 the rest are kept before the records whose adder may not add", PERSON,
     '''        .chain(may_not_add)
        .chain(rest.into_iter().map(|record| record.row))''',
     '''        .chain(rest.into_iter().map(|record| record.row))
        .chain(may_not_add)''',
     [FROM_THE_END]),
    ("G8 the rest by key before their time", PERSON,
     '''            (record.at, row.key, row.adder, &row.record)''',
     '''            (row.key, record.at, row.adder, &row.record)''',
     [FROM_THE_END]),
    ("G9 the rest that say one time in no order of key, adder or bytes", PERSON,
     '''            (record.at, row.key, row.adder, &row.record)''',
     '''            (record.at, [0u8; 32], [0u8; 32], &row.record[..0])''',
     [THE_REST_IN_ONE_TIME]),

    # Dealing in turns.
    ("D1 the records whose key the 64 kept out are not dealt, but kept as seen", PERSON,
     '''    let kept_out = dealt(statement, kept_out, &mut rest);''',
     '''    let kept_out: Vec<&KeptAddition> = kept_out.iter().map(|record| record.row).collect();''',
     [FLOOD, FLOOR]),
    ("D2 the records whose adder may not add are not dealt, but kept as seen", PERSON,
     '''    let may_not_add = dealt(statement, may_not_add, &mut rest);''',
     '''    let may_not_add: Vec<&KeptAddition> = may_not_add.iter().map(|record| record.row).collect();''',
     [MAY_NOT_ADD]),
    ("D3 records are dealt, not keys: an adder has a place for each record", PERSON,
     '''        let mut places = one_for_each_key(records, rest);''',
     '''        let mut places = records;''',
     [ONE_PLACE]),
    ("D4 an adder's keys by key and not by the time each says", PERSON,
     '''        places.sort_by_key(|place| (place.at, place.row.key));''',
     '''        places.sort_by_key(|place| (place.row.key, place.at));''',
     [FLOOR]),
    ("D5 within a turn the devices of the statement do not come first", PERSON,
     '''        adders.push((listed.unwrap_or(usize::MAX), adder, places));''',
     '''        adders.push((usize::MAX, adder, places));''',
     [IN_A_TURN]),
    ("D6 within a turn the devices of the statement are not in its order", PERSON,
     '''    adders.sort_by_key(|(listed, adder, _)| (*listed, *adder));''',
     '''    adders.sort_by_key(|(listed, adder, _)| (usize::MAX - *listed, *adder));''',
     [IN_A_TURN]),
    ("D7 an adder's keys all before the next adder's, and not in turns", PERSON,
     '''    for turn in 0..turns {
        for (.., places) in &adders {
            if let Some(place) = places.get(turn) {
                order.push(place.row);
            }
        }
    }''',
     '''    let _ = turns;
    for (.., places) in &adders {
        order.extend(places.iter().map(|place| place.row));
    }''',
     [FLOOD, FLOOR]),
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
