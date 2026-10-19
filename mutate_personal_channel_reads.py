#!/usr/bin/env python3
"""Mutation checks for what a device keeps of its personal channel between
reads, so that a cycle of sync, a status and a message do not check and
open every word again under the store's lock (decision 2026-10-04 §2.2,
§2.3, §7.3, §16): a kept entry is used only where it is stored as it was,
to the byte; whose words are read, and their band, are asked at every
read; what is no longer stored is kept no more; the cycle reads ahead
with the lock let go, and reads both lists in one pass. A part for each
rule: put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
NAMES = 'crates/cordelia-api/src/names.rs'
CLAUDE = 'crates/cordelia-sync/src/claude.rs'
ORIG = {f: open(f).read() for f in (NAMES, CLAUDE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
SYNC = ("cordelia-sync", ["--lib"])
SYNC_IT = ("cordelia-sync", ["--test", "claude"])
# The timed tests are ignored in `cargo test` and run optimised: the
# arguments after `--` reach the test binary, and the name is matched as
# a part of the test's (the `--exact` after it is one more name, of no
# test).
TIMED = ("cordelia-sync", ["--release", "--lib", "--", "--ignored"])
def names(test): return (API, "names::tests::" + test)
def sender(test): return (API, "sender::tests::" + test)
def sync(test): return (SYNC, "claude::tests::" + test)
def sync_it(test): return (SYNC_IT, test)
def timed(test): return (TIMED, "claude::tests::personal_reads::" + test)

KEPT_IS_READ = names("test_what_is_kept_of_the_personal_channel_is_what_a_read_of_it_finds")
BAND = names("test_what_is_kept_says_nothing_of_the_band_of_a_word")
BAND_BEFORE = names("test_a_word_in_a_band_above_the_statements_is_read_nowhere")
AHEAD = names("test_a_read_ahead_leaves_nothing_to_read_under_the_lock")
RECIPIENT = sender("test_the_recipient_is_a_name_the_personal_channel_lists_now")
CYCLE = timed("a_cycle_reads_a_large_personal_channel_and_holds_the_store_briefly")
STATUS = timed("the_status_answers_within_its_second_while_cycles_read_a_large_personal_channel")
SETTINGS = sync("nothing_is_concluded_from_settings_that_have_changed")
OTHERS = sync_it("what_other_devices_sync_is_what_they_sync_now")

KEPT_SAME = '''            Some((kept, found)) if kept == *entry => Some(found),'''

def all_but(field, value):
    return ('''            Some((kept, found)) if Entry { %s: %s, ..kept.clone() } == *entry => Some(found),'''
            % (field, value))

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("PR1 a kept entry is used by its slot and author alone, however it is stored now", NAMES,
     KEPT_SAME,
     '''            Some((_, found)) => Some(found),''',
     [KEPT_IS_READ, RECIPIENT]),
    ("PR2 a kept entry is used whatever its content is now", NAMES,
     KEPT_SAME, all_but("content", "entry.content.clone()"),
     [KEPT_IS_READ]),
    ("PR3 a kept entry is used whatever its revision is now", NAMES,
     KEPT_SAME, all_but("rev", "entry.rev"),
     [KEPT_IS_READ]),
    ("PR4 a kept entry is used whether or not it is a delete now", NAMES,
     KEPT_SAME, all_but("delete", "entry.delete"),
     [KEPT_IS_READ]),
    ("PR5 a kept entry is used whatever its author's signature is now", NAMES,
     KEPT_SAME, all_but("author_signature", "entry.author_signature"),
     [KEPT_IS_READ]),
    ("PR6 a kept entry is used whatever its channel's signature is now", NAMES,
     KEPT_SAME, all_but("channel_signature", "entry.channel_signature"),
     [KEPT_IS_READ]),
    ("PR7 nothing is kept between reads: every entry is checked and opened each time", NAMES,
     '''    let mut kept = Kept::take(slot, &channel);''',
     '''    let mut kept = Kept::of(&channel);''',
     [KEPT_IS_READ, AHEAD, CYCLE]),
    ("PR8 what is no longer stored stays kept", NAMES,
     '''    kept.found = found_now;''',
     '''    kept.found.extend(found_now);''',
     [KEPT_IS_READ]),
    ("PR9 the signer of a kept entry is not asked again: who counted when it was first read stands", NAMES,
     ['''        let found = match kept.of_entry(&held.entry) {''',
      '''            Ok(Some(inside)) if !delete && of(&author) && in_a_band_of(rev, number) => {'''],
     ['''        let was_kept = kept.holds(&held.entry);
        let found = match kept.of_entry(&held.entry) {''',
      '''            Ok(Some(inside)) if !delete && (was_kept || of(&author)) && in_a_band_of(rev, number) => {'''],
     [KEPT_IS_READ]),
    ("PR10 the band of a kept entry is not asked again", NAMES,
     ['''        let found = match kept.of_entry(&held.entry) {''',
      '''            Ok(Some(inside)) if !delete && of(&author) && in_a_band_of(rev, number) => {'''],
     ['''        let was_kept = kept.holds(&held.entry);
        let found = match kept.of_entry(&held.entry) {''',
      '''            Ok(Some(inside)) if !delete && of(&author) && (was_kept || in_a_band_of(rev, number)) => {'''],
     [BAND]),
    ("PR11 the band of a word is not asked at all", NAMES,
     '''            Ok(Some(inside)) if !delete && of(&author) && in_a_band_of(rev, number) => {''',
     '''            Ok(Some(inside)) if !delete && of(&author) => {''',
     [BAND, BAND_BEFORE]),
    ("PR12 a read ahead keeps nothing of what it found", NAMES,
     '''    kept.found.extend(read);''',
     '''    let _ = read;''',
     [AHEAD, CYCLE]),
    ("PR13 a read ahead takes nothing for kept: it checks and opens every entry each time", NAMES,
     '''            .is_some_and(|(kept, _)| kept == entry)''',
     '''            .is_some_and(|_| false)''',
     [AHEAD, CYCLE]),
    ("PR14 a read ahead holds the store's lock while it checks and opens", NAMES,
     ['''    let (personal, stored) = {''',
      '''        (personal, entries::channel_stored(&conn, &channel)?)'''],
     ['''    let (personal, stored, _held) = {''',
      '''        (personal, entries::channel_stored(&conn, &channel)?, conn)'''],
     [CYCLE, STATUS]),
    ("PR15 the cycle reads nothing ahead: its first read checks and opens under the lock", CLAUDE,
     '''    said_names::read_ahead(&state.db).map_err(of_person)?;
''',
     '''''',
     [CYCLE, STATUS]),
    ("PR16 the one pass says that this device syncs what another device's word lists", NAMES,
     '''        .filter(|(_, key)| *key == own)''',
     '''        .filter(|(_, key)| *key == own || counts(key))''',
     [KEPT_IS_READ]),
    ("PR17 the one pass lists the words of a key that does not count", NAMES,
     '''    let listed = by_name(read.into_iter().filter(|(_, key)| counts(key)));''',
     '''    let listed = by_name(read.into_iter());''',
     [KEPT_IS_READ]),
    ("PR18 the cycle takes back no word: what it says it syncs is not read", CLAUDE,
     '''    let (said, listed) = said_names::said_and_listed(&db, &state.identity).map_err(of_person)?;''',
     '''    let (_, listed) = said_names::said_and_listed(&db, &state.identity).map_err(of_person)?;
    let said: BTreeSet<String> = BTreeSet::new();''',
     [SETTINGS, OTHERS]),
    ("PR19 the cycle offers nothing: what the channel lists is not read", CLAUDE,
     '''    let (said, listed) = said_names::said_and_listed(&db, &state.identity).map_err(of_person)?;''',
     '''    let (said, _) = said_names::said_and_listed(&db, &state.identity).map_err(of_person)?;
    let listed: Vec<said_names::Listed> = Vec::new();''',
     [OTHERS, CYCLE]),
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
