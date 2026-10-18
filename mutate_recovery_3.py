#!/usr/bin/env python3
"""Mutation checks for the rows of a recovery (decision 2026-10-17
sections 2.2 to 2.5; section 10, slice 3): `read_generation` and
`asked_for_room` in crates/cordelia-api/src/recover.rs, and `row_says`,
`for_room_says` and `no_row_says` in crates/cordelia-node/src/recover_cmd.rs.
The rows of records that do not count in the order of keeping, each key at
its best place; each adder's label beside it, in the order of the adders'
rows; an adder that may be in someone else's hands among several counted
and not shown; the line of a key that the 64 kept out and that signed a
record; and the sentence of the floor of three. A part for each rule of the
slice: put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
RECOVER = 'crates/cordelia-api/src/recover.rs'
CMD = 'crates/cordelia-node/src/recover_cmd.rs'
ORIG = {f: open(f).read() for f in (RECOVER, CMD)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "recover_e2e"])
def recover(test): return (API, "recover::tests::" + test)
def cmd(test): return (BIN, "recover_cmd::tests::" + test)
def e2e(test): return (E2E, test)

FIRST_THREE = recover("test_a_recovery_shows_each_adders_first_three_kept_out_rows")
LABELS = recover("test_a_row_kept_out_by_the_64_shows_every_label_its_adders_gave")
NO_ROW = recover("test_a_key_added_by_a_key_the_64_kept_out_has_no_row")
ITS_ADDER = recover("test_a_device_kept_out_by_the_64_is_asked_about_where_its_adder_may_add")
FILLING = recover("test_a_device_added_since_is_asked_about_where_only_the_bound_of_64_kept_it_out")
TWO_LABELS = cmd("test_what_is_said_of_a_key_added_under_two_labels")
NOT_SHOWN = cmd("test_a_row_kept_out_by_the_64_says_that_what_it_added_is_not_shown")
BOUND_64 = cmd("test_what_is_said_of_a_key_that_only_the_bound_of_64_kept_out")
NO_ROW_SAYS = cmd("test_what_is_said_of_the_keys_whose_record_was_read_and_that_have_no_row")
PHONE = e2e("a_device_that_signs_hundreds_of_records_leaves_a_phone_its_row")
AT_A_ROW = cmd("test_what_is_said_at_a_row_turns_on_the_answers_so_far")
SHOWN_LABEL = cmd("test_a_key_kept_out_by_the_64_is_named_by_the_label_its_row_showed")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # The order of the rows of records that do not count (§2.2).
    ("O1 the rows of records that do not count in order of key", RECOVER,
     '''    for record in person::in_the_order_of_keeping(statement, &counting, &kept) {''',
     '''    let _ = person::in_the_order_of_keeping(statement, &counting, &kept);
    let mut by_key: Vec<&KeptAddition> = kept.iter().filter(|one| !one.counted).collect();
    by_key.sort_by_key(|one| one.key);
    for record in by_key {''',
     [FIRST_THREE, PHONE]),
    ("O2 the rows of records that do not count from the end of the order of keeping", RECOVER,
     '''    for record in person::in_the_order_of_keeping(statement, &counting, &kept) {''',
     '''    for record in person::in_the_order_of_keeping(statement, &counting, &kept)
        .into_iter()
        .rev()
    {''',
     [FIRST_THREE, PHONE]),
    ("O3 a key's row at the last place its records give it, not the best", RECOVER,
     '''        let has_a_row = |key: &[u8; 32]| rows.iter().chain(&not_counted).any(|row| row.key == *key);''',
     '''        if rows.iter().all(|row| row.key != record.key) {
            not_counted.retain(|kept| kept.key != record.key);
        }
        let has_a_row = |key: &[u8; 32]| rows.iter().chain(&not_counted).any(|row| row.key == *key);''',
     [LABELS]),
    ("O4 a key that counts has a second row, of a record that does not count", RECOVER,
     '''        if !has_a_row(&record.key) {''',
     '''        if !not_counted.iter().any(|row| row.key == record.key) && !statement.lists(&record.key) {''',
     [FILLING]),

    # Each adder's label beside it, in the order of the adders' rows (§2.4).
    ("L1 a record that does not count for another reason is among the adders of a key the 64 kept out", RECOVER,
     '''        if counting.why_not(&record.key, &record.adder) == Some(NotCounted::NoRoom) {''',
     '''        if counting.why_not(&record.key, &record.adder).is_some() {''',
     [ITS_ADDER]),
    ("L2 one adder's label stands for the key", RECOVER,
     '''            if !by.iter().any(|(adder, ..)| *adder == record.adder) {''',
     '''            if by.is_empty() {''',
     [LABELS, FILLING]),
    ("L3 an adder that signed two records for the key is shown twice", RECOVER,
     '''            if !by.iter().any(|(adder, ..)| *adder == record.adder) {''',
     '''            if true {''',
     [LABELS]),
    ("L4 an adder's later record, and not the one that takes its place, gives its label", RECOVER,
     '''            if !by.iter().any(|(adder, ..)| *adder == record.adder) {
                let at = row.added_by.map_or(0, |(_, at)| at);''',
     '''            by.retain(|(adder, ..)| *adder != record.adder);
            {
                let at = row.added_by.map_or(0, |(_, at)| at);''',
     [LABELS]),
    ("L5 the adders in order of key, not of their rows", RECOVER,
     '''        by.sort_by_key(|(adder, ..)| (place(adder).unwrap_or(usize::MAX), *adder));''',
     '''        by.sort_by_key(|(adder, ..)| *adder);''',
     [LABELS]),
    ("L6 the row by the last of its adders, not the first", RECOVER,
     '''        let (adder, at, label) = &by[0];''',
     '''        let (adder, at, label) = &by[by.len() - 1];''',
     [LABELS, FILLING]),
    ("L7 the row by its best record, and not by the first of its adders", RECOVER,
     '''        (row.added_by, row.label) = (Some((*adder, *at)), label.clone());''',
     '''        let _ = (adder, at, label);''',
     [LABELS]),
    ("L8 asked under the last adder that is not in someone else's hands, not the first", RECOVER,
     '''    let under = row.no_room.iter().find(not_in_other_hands);''',
     '''    let under = row.no_room.iter().rev().find(not_in_other_hands);''',
     [LABELS]),

    # The record of a key that the 64 kept out (§2.3).
    ("S1 any added/ entry that opens counts as a record, as before", RECOVER,
     '''        let Value::Other(bytes) = &inside.value else {''',
     '''        if inside.name.starts_with(PERSONAL_ADDED_PREFIX) {
            return true;
        }
        let Value::Other(bytes) = &inside.value else {''',
     [NO_ROW]),
    ("S2 a record under any name counts, not only under an added/ name", RECOVER,
     '''        inside.name.starts_with(PERSONAL_ADDED_PREFIX)
            && record.addition.adder == entry.author''',
     '''        !inside.name.is_empty()
            && record.addition.adder == entry.author''',
     [NO_ROW]),
    ("S5 a record that another key signed counts for the key that put it there", RECOVER,
     '''            && record.addition.adder == entry.author
''',
     '''''',
     [NO_ROW]),
    ("S6 a record whose signature does not hold counts", RECOVER,
     '''            && record.verify().is_ok()''',
     '''            && record.verify().is_ok() || record.addition.adder == entry.author''',
     [NO_ROW]),
    ("S3 every row of a key the 64 kept out says that it signed a record", RECOVER,
     '''        row.signed_a_record = signed_records.contains(&row.key);''',
     '''        row.signed_a_record = !signed_records.is_empty();''',
     [NO_ROW]),
    ("S4 no row says that it signed a record", RECOVER,
     '''        row.signed_a_record = signed_records.contains(&row.key);''',
     '''        row.signed_a_record = false && signed_records.contains(&row.key);''',
     [NO_ROW]),

    # What a person reads (§2.5).
    ("C1 the line of several adders for a key that one adder added", CMD,
     '''        Some(_) if row.no_room.len() > 1 || hidden > 0 => {''',
     '''        Some(_) if !row.no_room.is_empty() || hidden > 0 => {''',
     [BOUND_64]),
    ("C2 the line of one adder for a key that two added", CMD,
     '''        Some(_) if row.no_room.len() > 1 || hidden > 0 => {''',
     '''        Some(_) if row.no_room.len() > 2 || hidden > 0 => {''',
     [TWO_LABELS, BOUND_64]),
    ("C3 an adder that may be in someone else's hands is shown", RECOVER,
     '''        place.is_some_and(|place| in_other_hands(rows, answers, place))
    };
    let (hidden, shown)''',
     '''        place.is_some_and(|place| in_other_hands(rows, answers, place) && false)
    };
    let (hidden, shown)''',
     [TWO_LABELS, AT_A_ROW, SHOWN_LABEL]),
    ("C13 an adder is hidden only by its own answer, not by its adder's (the chain)", RECOVER,
     '''        place.is_some_and(|place| in_other_hands(rows, answers, place))
    };
    let (hidden, shown)''',
     '''        place.is_some_and(|place| answers.get(place) == Some(&Answer::OtherHands))
    };
    let (hidden, shown)''',
     [TWO_LABELS]),
    ("C14 one adder alone that may be in someone else's hands is shown with its label", CMD,
     '''        Some(_) if row.no_room.len() > 1 || hidden > 0 => {''',
     '''        Some(_) if row.no_room.len() > 1 => {''',
     [TWO_LABELS]),
    ("C4 the label that the row holds stands first, not the first adder's shown", RECOVER,
     '''    shown.first().map_or("", |(_, _, label)| label.as_str())''',
     '''    let _ = shown;
    &row.label''',
     [TWO_LABELS, SHOWN_LABEL]),
    ("C15 where every adder is hidden, the first adder's label stands", RECOVER,
     '''    shown.first().map_or("", |(_, _, label)| label.as_str())''',
     '''    shown.first().map_or(row.no_room[0].2.as_str(), |(_, _, label)| label.as_str())''',
     [TWO_LABELS, SHOWN_LABEL]),
    ("C16 the row shows the label that its record holds, not the label shown", CMD,
     '''    let label = recover::label_shown(rows, answers, row);
    let (shown, hidden)''',
     '''    let label = row.label.as_str();
    let (shown, hidden)''',
     [TWO_LABELS]),
    ("C17 before the yes, a key is named by the label its record holds", CMD,
     '''            .map(|row| named(recover::label_shown(rows, answers, row), &row.key))''',
     '''            .map(|row| named(&row.label, &row.key))''',
     [SHOWN_LABEL]),
    ("C18 the node is handed the label that a key's record holds", CMD,
     '''        let label = recover::label_shown(rows, answers, row);
        json!''',
     '''        let label = &row.label;
        json!''',
     [SHOWN_LABEL]),
    ("C19 a row is said with no answers, whatever was answered before it", CMD,
     '''    let says = row_says(rows, answers, at, number);
    if rows[at].key == *own {''',
     '''    let says = row_says(rows, &[], at, number);
    if rows[at].key == *own {''',
     [AT_A_ROW]),
    ("C20 a row asked about for the 64 alone is said with no answers", CMD,
     '''        return AtARow::Asks(for_room_says(rows, answers, at, number, left));''',
     '''        return AtARow::Asks(for_room_says(rows, &[], at, number, left));''',
     [AT_A_ROW]),
    ("C5 no label beside its adder", CMD,
     '''                    format!("from {adder} at {} as {label:?}", time_of(*at))''',
     '''                    format!("from {adder} at {}", time_of(*at) + &label[..0])''',
     [TWO_LABELS, BOUND_64]),
    ("C6 the adders in someone else's hands are not counted", CMD,
     '''                    format!(", and {n} more added it, which may be in someone else's hands")''',
     '''                    format!("{}", &n.to_string()[..0])''',
     [TWO_LABELS]),
    ("C7 where every adder may be in someone else's hands, nothing is said of them", CMD,
     '''                    " by {} that may be in someone else's hands",''',
     '''                    "{}",''',
     [TWO_LABELS]),
    ("C8 that the labels differ is not said", CMD,
     '''            if labels.len() > 1 {''',
     '''            if labels.len() > 2 {''',
     [TWO_LABELS, BOUND_64]),
    ("C9 that the labels differ is said where they are the same", CMD,
     '''            if labels.len() > 1 {''',
     '''            if !labels.is_empty() {''',
     [TWO_LABELS]),
    ("C10 the line of what it added is said where it signed no record", CMD,
     '''    if row.signed_a_record {''',
     '''    if !row.signed_a_record {''',
     [NOT_SHOWN, TWO_LABELS]),
    ("C11 the sentence of the floor of three is not said", CMD,
     '''Each device that may add keeps a \\
         row for at least the first {KEPT_OUT_PER_ADDER} devices that it added since change \\
         {number} and that {MAX_COUNTED_DEVICES} devices counted already kept out: a device that \\
         added more than that may have left one of them here. ''',
     '''''',
     [NO_ROW_SAYS, PHONE]),
    ("C12 the floor said is not KEPT_OUT_PER_ADDER", CMD,
     '''         row for at least the first {KEPT_OUT_PER_ADDER} devices that it added since change \\''',
     '''         row for at least the first {MAX_COUNTED_DEVICES} devices that it added since change \\''',
     [NO_ROW_SAYS]),
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
