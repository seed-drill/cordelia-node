#!/usr/bin/env python3
"""Mutation checks for the warning before the personal channel fills a
relay's room (decision 2026-10-19, names at the limit, §2 rules 1 to 6,
and the constants of §6), with the parts of rule 1 that the review's
low findings 1 and 2 added (L1, L2a, L2b). A part for each rule of the slice: put each
fault in, and confirm the test named for it fails on an assertion. Run
from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
ENTRIES = 'crates/cordelia-storage/src/entries.rs'
NAMES = 'crates/cordelia-api/src/names.rs'
PERSON = 'crates/cordelia-api/src/person.rs'
STATE = 'crates/cordelia-api/src/state.rs'
LOOK = 'crates/cordelia-api/src/look.rs'
COMMANDS = 'crates/cordelia-api/src/commands.rs'
CLAUDE = 'crates/cordelia-sync/src/claude.rs'
INDICATOR = 'crates/cordelia-node/src/indicator.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
PERSON_CMD = 'crates/cordelia-node/src/person_cmd.rs'
DEVICE_ENTRIES = 'crates/cordelia-node/src/device_entries.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, ENTRIES, NAMES, PERSON, STATE, LOOK, COMMANDS,
                                    CLAUDE, INDICATOR, MAIN, PERSON_CMD, DEVICE_ENTRIES)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
STORAGE = ("cordelia-storage", ["--lib"])
API = ("cordelia-api", ["--lib"])
API_ROUTES = ("cordelia-api", ["--test", "commands_api"])
SYNC = ("cordelia-sync", ["--lib"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def core(test): return (CORE, "protocol::tests::" + test)
def relay(test): return (STORAGE, "relay::tests::" + test)
def names(test): return (API, "names::tests::" + test)
def look(test): return (API, "look::tests::" + test)
def routes(test): return (API_ROUTES, test)
def claude(test): return (SYNC, "claude::tests::" + test)
def indicator(test): return (NODE, "indicator::tests::" + test)
def main(test): return (NODE, "tests::" + test)
def person_cmd(test): return (NODE, "person_cmd::tests::" + test)
def e2e(test): return (E2E, test)

TOTAL = names("the_channels_total_counts_every_author_and_every_delete")
CARRIES = claude("a_cycles_report_carries_the_channels_total")
PAST = indicator("the_status_is_amber_past_the_line")
FIRST = indicator("the_warning_is_shown_before_every_other_amber_memory_line")
FORMS = indicator("the_warning_says_what_fills_the_channel")
READS = main("the_status_reads_the_personal_channel_from_the_report")
SIZES = person_cmd("devices_shows_what_each_device_keeps_past_the_line")
ROUTE = routes("test_a_look_carries_what_the_personal_channel_holds_from_the_report")
REFUSAL = look("a_refusal_for_room_says_which_channel")
REFUSAL_E2E = e2e("a_relays_refusal_for_room_is_said_as_what_it_is")
HEADROOM = relay("the_headroom_holds_what_can_arrive")
LINE = core("test_the_line_of_the_personal_channel_decision_2026_10_19_6")

WARNING = '''        if let Some(channel) = f.channel.as_ref().filter(|c| c.past_the_line()) {
            amber("channel_nearly_full", channel.warning());
        }
'''

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # Rule 1: the sum in the one read, before the filter.
    ("R1a the sum goes after the filter of who counts and which band", NAMES,
     '''        fill.add(author, entry_cost(held.entry.content.len()), word);''',
     '''        if of(&author) && in_a_band_of(rev, number) {
            fill.add(author, entry_cost(held.entry.content.len()), word);
        }''',
     [TOTAL]),
    ("R1b every delete is counted as no word", NAMES,
     '''            (_, true) => kept.slots.delete_is_a_word(&held.entry.slot, &author),''',
     '''            (_, true) => false,''',
     [TOTAL]),
    ("R1c a text under name/ that is no name is counted as a word", NAMES,
     '''                .is_some_and(is_a_name),''',
     '''                .is_some(),''',
     [TOTAL]),
    ("R1d the read takes no channel's filter", ENTRIES,
     '''             WHERE channel_id = ?1
             ORDER BY seq ASC''',
     '''             WHERE ?1 IS NOT NULL
             ORDER BY seq ASC''',
     [TOTAL]),
    ("R1e a delete in an applied/ or left/ slot is no word whoever signed it", NAMES,
     '''            Some(SlotIs::OwnOf(_)) => return true,''',
     '''            Some(SlotIs::OwnOf(_)) => return false,''',
     [TOTAL]),
    ("R1f a delete in an added/ slot is a word", NAMES,
     '''            Some(SlotIs::Added) => return false,''',
     '''            Some(SlotIs::Added) => return true,''',
     [TOTAL]),
    ("L1 an author the device does not know: its own slots are not looked up", NAMES,
     '''        if self.keys.binary_search(author).is_ok() {''',
     '''        if true || self.keys.binary_search(author).is_ok() {''',
     [names("a_delete_in_its_own_authors_slot_is_no_word_whoever_the_author")]),
    ("L2a the slots are not worked out again when the known keys change", NAMES,
     '''    if kept.slots.of.is_empty() || kept.slots.keys != known {''',
     '''    if kept.slots.of.is_empty() {''',
     [names("the_slots_are_worked_out_again_when_a_key_comes_to_count")]),
    ("L2b a key recorded and not counted is not among the known", PERSON,
     '''            .chain(&self.recorded)
            .filter(|key| self.counts(key) || self.recorded.contains(key))''',
     '''            .filter(|key| self.counts(key))''',
     [names("a_delete_under_added_and_a_recorded_key_that_does_not_count_is_no_word")]),
    # Rule 2: the report keeps it, and a short cycle carries it forward.
    ("R2a the cycle's report keeps no total", CLAUDE,
     '''                    Ok(read) => report.personal_channel = read,''',
     '''                    Ok(_) => {}''',
     [CARRIES]),
    ("R2b a short cycle carries nothing forward", CLAUDE,
     '''                report.personal_channel = self.personal_channel.clone();''',
     '''                report.personal_channel = None;''',
     [CARRIES]),
    ("R2c after a start nothing is carried from the stored report", CLAUDE,
     '''                    self.personal_channel = stored_personal_channel(state);''',
     '''                    self.personal_channel = None;''',
     [CARRIES]),
    # Rule 3: the amber line, first, and who shows it.
    ("R3a amber at the line, not past it", INDICATOR,
     '''        self.total > cordelia_core::protocol::PERSONAL_CHANNEL_WARN_BYTES''',
     '''        self.total >= cordelia_core::protocol::PERSONAL_CHANNEL_WARN_BYTES''',
     [PAST]),
    ("R3b the warning is placed after the other amber lines", INDICATOR,
     [WARNING,
      '''    if d.no_room_secs.iter().any(|ago| *ago <= NO_ROOM_STANDS_SECS) {'''],
     ['',
      WARNING.replace('        ', '    ') + '''    if d.no_room_secs.iter().any(|ago| *ago <= NO_ROOM_STANDS_SECS) {'''],
     [FIRST]),
    ("R3c the warning shows with sync off or nothing mapped", INDICATOR,
     [WARNING,
      '''    let d = &f.devices;
    if of_folders {'''],
     ['',
      '''    let d = &f.devices;
''' + WARNING.replace('        ', '    ') + '''    if of_folders {'''],
     [PAST]),
    ("R3d the status takes no device for this one", MAIN,
     '''                this_device: Some(key) == this_device,''',
     '''                this_device: false,''',
     [READS]),
    # Rule 4: the four forms.
    ("R4a exactly half of what is not words names a device", INDICATOR,
     '''            signer.not_words.saturating_mul(2) > not_words''',
     '''            signer.not_words.saturating_mul(2) >= not_words''',
     [FORMS]),
    ("R4b exactly a quarter of the total names a device", INDICATOR,
     '''                && signer.not_words.saturating_mul(4) > self.total''',
     '''                && signer.not_words.saturating_mul(4) >= self.total''',
     [FORMS]),
    ("R4c this device has no form of its own", INDICATOR,
     '''        if self.by.iter().filter(|s| s.this_device).any(|s| filled(&s)) {''',
     '''        if self.by.iter().filter(|s| s.this_device).any(|_| false) {''',
     [FORMS]),
    ("R4d words at exactly half the total do not give the names form", INDICATOR,
     '''        if self.words.saturating_mul(2) >= self.total {''',
     '''        if self.words.saturating_mul(2) > self.total {''',
     [FORMS]),
    # Rule 5: the sizes in `cordelia devices`, past the line only.
    ("R5a the sizes show at the line", PERSON_CMD,
     '''    (filled["total"].as_u64()? > PERSONAL_CHANNEL_WARN_BYTES).then_some(filled)''',
     '''    (filled["total"].as_u64()? >= PERSONAL_CHANNEL_WARN_BYTES).then_some(filled)''',
     [SIZES]),
    ("R5b no size beside each device", PERSON_CMD,
     '''        Some(filled) => format!("; keeps {} MiB there", mib(signed_by(filled, device))),''',
     '''        Some(_) => String::new(),''',
     [SIZES]),
    ("R5c the look carries nothing of the report", COMMANDS,
     '''    answer["personal_channel"] = filled;''',
     '''    let _ = filled;''',
     [ROUTE]),
    # Rule 6: the refusal for room, kept by channel and worded for each.
    ("R6a the personal channel's refusal said as before", LOOK,
     '''            sent("the relay is full, or what your devices keep there is.".into())''',
     '''            what_of("a new channel")''',
     [REFUSAL, REFUSAL_E2E]),
    ("R6b a name's refusal said as before", LOOK,
     '''            "the relay is full, or your memory of {} there is as large as a relay keeps.",''',
     '''            "it is full ({}).",''',
     [REFUSAL, REFUSAL_E2E]),
    ("R6c a pair channel's refusal said as before", LOOK,
     '''            sent("the relay is full, so no device can be added through it now.".into())''',
     '''            what_of("a new channel")''',
     [REFUSAL]),
    ("R6d a refusal for the allowance is not said as before", LOOK,
     '''        _ if refused.over_allowance => what_of("a new channel"),
''',
     '',
     [REFUSAL]),
    ("R6e the personal channel's refusal is not kept over another in one pass", STATE,
     '''        if personal_this_pass && refused.of != RefusedOf::Personal {''',
     '''        if false && personal_this_pass && refused.of != RefusedOf::Personal {''',
     [REFUSAL]),
    ("R6f a device keeps the personal channel's refusal as a pair channel's", DEVICE_ENTRIES,
     '''        Kind::Personal => Some(RefusedOf::Personal),''',
     '''        Kind::Personal => Some(RefusedOf::Pair),''',
     [REFUSAL_E2E]),
    ("R6g a pass begins no new pass for what is kept", DEVICE_ENTRIES,
     '''            .passes += 1;''',
     '''            .passes += 0;''',
     [REFUSAL_E2E]),
    # §6: the constants, to the relay's own count.
    ("C1 the headroom is 5 MiB", PROTOCOL,
     '''pub const PERSONAL_CHANNEL_HEADROOM_BYTES: u64 = 4 * 1024 * 1024;''',
     '''pub const PERSONAL_CHANNEL_HEADROOM_BYTES: u64 = 5 * 1024 * 1024;''',
     [LINE, HEADROOM]),
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
