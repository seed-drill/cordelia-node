#!/usr/bin/env python3
"""Mutation checks for slice 2 of a relay out of reach: the carried word,
`reached/<key>` in the personal channel, where it is written, rewritten
and deleted, its fields and their bounds, how it is read, and what other
devices and the device itself say of it (decision 2026-10-19 §4, rules 4
to 7; §5, D1, S4 and S5; §7; §10). A part for each rule of the slice: put
each fault in, and confirm the test named for it fails on an assertion.
Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
WORD = 'crates/cordelia-crypto/src/reached.rs'
PERSON = 'crates/cordelia-api/src/person.rs'
AT_RELAYS = 'crates/cordelia-api/src/at_relays.rs'
LOOK = 'crates/cordelia-api/src/look.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
CMD = 'crates/cordelia-node/src/person_cmd.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, WORD, PERSON, AT_RELAYS, LOOK, DEVICE, CMD)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
CRYPTO = ("cordelia-crypto", ["--lib"])
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def core(test): return (CORE, "protocol::tests::" + test)
def word(test): return (CRYPTO, "reached::tests::" + test)
def person(test): return (API, "person::tests::" + test)
def at_relays(test): return (API, "at_relays::tests::" + test)
def look(test): return (API, "look::tests::" + test)
def take(test): return (API, "take::tests::" + test)
def cmd(test): return (BIN, "person_cmd::tests::" + test)
def e2e(test): return (E2E, test)

WRITTEN = at_relays("the_carried_word_is_written_only_where_sent_would_be_but_for_relays_out_of_reach")
REWRITTEN = at_relays("it_is_rewritten_when_a_field_changes_and_deleted_when_sent_is_written")
EIGHT = at_relays("it_names_eight_keys_and_counts_the_rest")
TOOK_ALL = at_relays("the_carried_word_counts_a_relay_out_of_reach_that_took_everything")
TO_COME = at_relays("word_to_come_is_what_the_next_pass_would_write")
READ = look("the_carried_word_is_read_only_from_its_own_key_under_the_applied_number")
NAMED = look("a_relay_is_named_three_ways")
LINES = cmd("each_line_of_the_carried_word_word_for_word")
OVERLAP = cmd("held_and_not_yet_never_overlap")
STANDING = at_relays("a_standing_word_is_rewritten_or_deleted_when_its_fields_no_longer_hold")
PASS = e2e("a_pass_writes_the_carried_word_where_the_other_relay_is_out_of_reach")
FORM = word("the_value_is_four_fields_byte_for_byte")
REFUSED = word("a_word_out_of_its_form_is_no_word")
CONSTANTS = core("test_the_carried_word_decision_2026_10_19_10")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── §10, the constants ──────────────────────────────────────────
    ("C1 the prefix is another", PROTOCOL,
     '''pub const PERSONAL_REACHED_PREFIX: &str = "reached/";''',
     '''pub const PERSONAL_REACHED_PREFIX: &str = "reach/";''',
     [CONSTANTS]),
    ("C2 the word names nine keys", PROTOCOL,
     '''pub const REACHED_WORD_MAX_RELAYS: usize = 8;''',
     '''pub const REACHED_WORD_MAX_RELAYS: usize = 9;''',
     [CONSTANTS, REFUSED, EIGHT]),
    ("C3 a count may say 257", PROTOCOL,
     '''pub const REACHED_WORD_MAX_COUNT: u64 = 256;''',
     '''pub const REACHED_WORD_MAX_COUNT: u64 = 257;''',
     [CONSTANTS, REFUSED, READ, EIGHT]),

    # ── Rule 4: the word's form ─────────────────────────────────────
    ("V1 a word of no key is a word", WORD,
     '''        if !(1..=REACHED_WORD_MAX_RELAYS).contains(&self.keys.len()) {''',
     '''        if self.keys.len() > REACHED_WORD_MAX_RELAYS {''',
     [REFUSED, READ]),
    ("V2 a word of nine keys is a word", WORD,
     '''        if !(1..=REACHED_WORD_MAX_RELAYS).contains(&self.keys.len()) {''',
     '''        if self.keys.is_empty() {''',
     [REFUSED, READ]),
    ("V3 a key may be named twice", WORD,
     '''            if self.keys[..at].contains(key) {''',
     '''            if self.keys[..at].contains(key) && at > 8 {''',
     [REFUSED, READ]),
    ("V4 more is counted with fewer than eight keys", WORD,
     '''        if self.more != 0 && self.keys.len() < REACHED_WORD_MAX_RELAYS {''',
     '''        if self.more != 0 && self.keys.len() < 1 {''',
     [REFUSED, READ]),
    ("V5 a count may be over its bound", WORD,
     '''            if count > REACHED_WORD_MAX_COUNT {''',
     '''            if count > 2 * REACHED_WORD_MAX_COUNT {''',
     [REFUSED, READ]),
    ("V6 a count at its bound is refused", WORD,
     '''            if count > REACHED_WORD_MAX_COUNT {''',
     '''            if count >= REACHED_WORD_MAX_COUNT {''',
     [FORM, READ]),
    ("V7 bytes after the four fields are read", WORD,
     '''        if !reader.is_empty() {
            return Err(NotAWord::Long);
        }''',
     '''''',
     [REFUSED]),
    ("V8 the two counts change places in the value", WORD,
     '''        out.extend_from_slice(&(self.more as u16).to_be_bytes());
        out.extend_from_slice(&(self.not_yet as u16).to_be_bytes());''',
     '''        out.extend_from_slice(&(self.not_yet as u16).to_be_bytes());
        out.extend_from_slice(&(self.more as u16).to_be_bytes());''',
     [FORM, REWRITTEN]),
    ("V9 a text is read as a word", WORD,
     '''        let Value::Other(bytes) = value else {
            return Err(NotAWord::Kind);
        };''',
     '''        let bytes = value.bytes();''',
     [REFUSED]),

    # ── Rule 4: the name, and not carried ───────────────────────────
    ("P1 the carried word is carried to the next statement", PERSON,
     '''        && !version.name.starts_with(PERSONAL_REACHED_PREFIX)
}''',
     '''}''',
     [person("the_carried_word_and_its_delete_are_not_carried")]),
    ("P2 the carried word is written in the slot of the word under applied/", PERSON,
     '''        "{PERSONAL_REACHED_PREFIX}{}",''',
     '''        "{PERSONAL_APPLIED_PREFIX}{}",''',
     [REWRITTEN, WRITTEN]),

    # ── Rule 4, condition 1: what `sent` asks but connections ───────
    ("W1 a recovery's look that is pending writes the word", AT_RELAYS,
     '''    if meta::get(conn, meta::PERSON_LOOK_PENDING)?.is_some() {
        return Ok(None);
    }''',
     '''''',
     [WRITTEN, TO_COME]),
    ("W2 a device that has stopped writes the word", AT_RELAYS,
     '''fn alone(conn: &Connection, identity: &NodeIdentity) -> Result<Option<Alone>, PersonError> {
    if stands(conn)? != Stands::Applied {
        return Ok(None);
    }''',
     '''fn alone(conn: &Connection, identity: &NodeIdentity) -> Result<Option<Alone>, PersonError> {''',
     [WRITTEN]),
    ("W3 a word with ` sent` writes the carried word", AT_RELAYS,
     '''    if said != Value::Text(applied_word(number, false)) {
        return Ok(None);
    }
    Ok(Some(Alone {''',
     '''    Ok(Some(Alone {''',
     [WRITTEN, REWRITTEN]),

    # ── Rule 4, conditions 2 to 4: the classes ──────────────────────
    ("W4 a relay that refuses the change lets the word be written", AT_RELAYS,
     '''            Some(Class::Ok | Class::Stuck | Class::OutHolding | Class::OutLacking)''',
     '''            Some(Class::Ok | Class::Stuck | Class::OutHolding | Class::OutLacking | Class::Refusing)''',
     [WRITTEN]),
    ("W5 a relay that is STUCK keeps the word from being written", AT_RELAYS,
     '''            Some(Class::Ok | Class::Stuck | Class::OutHolding | Class::OutLacking)''',
     '''            Some(Class::Ok | Class::OutHolding | Class::OutLacking)''',
     [WRITTEN]),
    ("W6 one relay in a class is enough", AT_RELAYS,
     '''    if relays.is_empty() || !relays.iter().all(classed) {''',
     '''    if relays.is_empty() || !relays.iter().any(classed) {''',
     [WRITTEN]),
    ("W7 every relay OK writes the carried word", AT_RELAYS,
     '''    if relays.iter().all(|relay| relay.class == Some(Class::Ok)) {
        return Ok(None);
    }''',
     '''''',
     [WRITTEN]),
    ("W8 what was carried is not asked of a relay's rows", AT_RELAYS,
     '''        if !held.contains(&key) && !carried_waits_at(conn, identity, &key)? {''',
     '''        if !held.contains(&key) {''',
     [WRITTEN, REWRITTEN]),
    ("W9 a relay that is OK need not hold what was carried", AT_RELAYS,
     '''    let ok_and_held = |relay: &Found| relay.class == Some(Class::Ok) && is_held(relay);''',
     '''    let ok_and_held = |relay: &Found| relay.class == Some(Class::Ok);''',
     [WRITTEN]),
    ("W10 a key named twice in the order is named twice", AT_RELAYS,
     '''        if !held.contains(&key) && !carried_waits_at(conn, identity, &key)? {''',
     '''        if !carried_waits_at(conn, identity, &key)? {''',
     [EIGHT]),
    ("W11 a relay of no known key is not counted as not yet", AT_RELAYS,
     '''    let not_yet = relays.iter().filter(|relay| !is_held(relay)).count() as u64;''',
     '''    let not_yet = relays.iter().filter(|relay| relay.key.is_some() && !is_held(relay)).count() as u64;''',
     [EIGHT]),
    ("W12 not yet counts the relays that are named", AT_RELAYS,
     '''    let not_yet = relays.iter().filter(|relay| !is_held(relay)).count() as u64;''',
     '''    let not_yet = relays.len() as u64;''',
     [WRITTEN, EIGHT, TOOK_ALL, REWRITTEN]),
    ("W13 more counts nothing", AT_RELAYS,
     '''    let more = held.len().saturating_sub(REACHED_WORD_MAX_RELAYS) as u64;''',
     '''    let more = 0;''',
     [EIGHT]),
    ("W14 the keys are not cut at eight", AT_RELAYS,
     '''    held.truncate(REACHED_WORD_MAX_RELAYS);''',
     '''''',
     [EIGHT]),
    ("W15 a count over its bound is written", AT_RELAYS,
     '''    if held.is_empty() || more > REACHED_WORD_MAX_COUNT || not_yet > REACHED_WORD_MAX_COUNT {''',
     '''    if held.is_empty() {''',
     [EIGHT]),
    ("W20 a word of no key is written over a standing one", AT_RELAYS,
     '''    if held.is_empty() || more > REACHED_WORD_MAX_COUNT || not_yet > REACHED_WORD_MAX_COUNT {''',
     '''    if more > REACHED_WORD_MAX_COUNT || not_yet > REACHED_WORD_MAX_COUNT {''',
     [STANDING]),
    ("W16 the keys are not in the order of the configuration", AT_RELAYS,
     '''    held.truncate(REACHED_WORD_MAX_RELAYS);''',
     '''    held.sort();
    held.truncate(REACHED_WORD_MAX_RELAYS);''',
     [EIGHT]),
    ("W17 the word is written again where nothing changed", AT_RELAYS,
     '''    if standing(conn, &alone, &identity.public_key())?.as_ref() == Some(&word) {
        return Ok(None);
    }''',
     '''''',
     [REWRITTEN, TO_COME]),
    ("W18 `sent` leaves the carried word standing", AT_RELAYS,
     '''            write_reached(conn, identity, &alone, Some(held.rev), Value::Delete, now)?;''',
     '''''',
     [REWRITTEN, PASS]),
    ("W19 the carried word is written in the band of no statement", AT_RELAYS,
     '''    let rev = next_under(held, alone.number).ok_or_else(|| {''',
     '''    let rev = next_under(held.map(|rev| rev + (1 << 52)), alone.number).ok_or_else(|| {''',
     [REWRITTEN]),

    # ── Rule 8's input: word_to_come ────────────────────────────────
    ("T1 `sent` to come is not said", AT_RELAYS,
     '''        if !waits {
            return Ok(true);
        }''',
     '''''',
     [TO_COME]),
    ("T2 the carried word to come is not said", AT_RELAYS,
     '''            reached_to_write(conn, identity, found)?.is_some()''',
     '''            false''',
     [TO_COME, PASS]),
    ("T4 a standing word to be rewritten or deleted is not said to come", AT_RELAYS,
     '''                || standing_to_mend(conn, identity, found)?.is_some()''',
     '''''',
     [STANDING]),

    # ── Rule 4: a standing word whose fields no longer hold ─────────
    ("M1 a standing word is rewritten though its fields say the same", AT_RELAYS,
     '''        Some(word) if word == stands => None,''',
     '''        Some(word) if word != word => None,''',
     [STANDING]),
    ("M2 a standing word that no relay holds is not deleted", AT_RELAYS,
     '''        None => Some(Mend::Delete),''',
     '''        None => None,''',
     [STANDING]),
    ("M3 a standing word whose fields changed is not rewritten", AT_RELAYS,
     '''        Some(word) => Some(Mend::Word(word)),''',
     '''        Some(_) => None,''',
     [STANDING]),
    ("M4 the pass does not mend a standing word", AT_RELAYS,
     '''            None => match standing_to_mend(conn, identity, relays)? {''',
     '''            None => match None::<Mend> {''',
     [STANDING]),
    ("M5 a standing word is mended though the device does not stand to write it", AT_RELAYS,
     '''pub fn standing_to_mend(
    conn: &Connection,
    identity: &NodeIdentity,
    relays: &[Found],
) -> Result<Option<Mend>, PersonError> {
    let Some(alone) = alone(conn, identity)? else {
        return Ok(None);
    };''',
     '''pub fn standing_to_mend(
    conn: &Connection,
    identity: &NodeIdentity,
    relays: &[Found],
) -> Result<Option<Mend>, PersonError> {
    let Some(alone) = alone(conn, identity)?.or_else(|| {
        let standing = Standing::to_write(conn).ok()?;
        let personal = derive::personal_secret(&standing.secret).ok()?;
        Some(Alone {
            number: standing.number(),
            channel: derive::channel_id(&personal).ok()?,
            personal,
            applied_rev: 0,
        })
    }) else {
        return Ok(None);
    };''',
     [STANDING]),
    ("T3 `sent` is to come though what was carried waits", AT_RELAYS,
     '''            waits |= carried_waits_at(conn, identity, relay)?;''',
     '''            waits |= false;''',
     [TO_COME]),

    # ── The node: the pass writes it ────────────────────────────────
    ("N1 the pass never writes the carried word", DEVICE,
     '''        if whole && !self.say_sent(relays) {
            self.say_reached(relays);
        }''',
     '''        if whole {
            self.say_sent(relays);
        }''',
     [PASS]),
    ("N2 a pass given fewer relays than the node has is believed", DEVICE,
     '''        if Some(relays.len()) != self.state.own_channels.relays_set_up() {
            return None;
        }''',
     '''''',
     [PASS]),
    ("N3 the key of the connection is not a relay's key", DEVICE,
     '''            .or(open.map(|link| link.relay().0))''',
     '''''',
     [e2e("a_relay_is_known_by_the_key_of_its_connection_before_it_answers")]),
    ("N4 the key of its latest answer is not a relay's key", DEVICE,
     '''            .or_else(|| known.of(&relay.id())?.answer.map(|answer| answer.by))''',
     '''''',
     [PASS]),
    ("N5 the status never says that a word is to come", DEVICE,
     '''            (latest, gone, keys, to_come.unwrap_or(false))''',
     '''            (latest, gone, keys, to_come.is_err())''',
     [PASS]),

    # ── Rule 5: the reader ──────────────────────────────────────────
    ("L1 a key that does not count is read", LOOK,
     '''        if !counting.counts(key) || self.applied_word(conn, key)? != Some((self.number, false)) {''',
     '''        if self.applied_word(conn, key)? != Some((self.number, false)) {''',
     [READ]),
    ("L2 the word is read beside any word under applied/", LOOK,
     '''        if !counting.counts(key) || self.applied_word(conn, key)? != Some((self.number, false)) {''',
     '''        if !counting.counts(key) || self.applied_word(conn, key)?.is_none() {''',
     [READ]),
    ("L3 the word is read beside `sent`", LOOK,
     '''        if !counting.counts(key) || self.applied_word(conn, key)? != Some((self.number, false)) {''',
     '''        if !counting.counts(key) || self.applied_word(conn, key)?.map(|(n, _)| n) != Some(self.number) {''',
     [READ]),
    ("L4 a word of another number is read", LOOK,
     '''            Ok(word) if word.number == self.number => Ok(Some(CarriedWordLook::of(&word)?)),''',
     '''            Ok(word) => Ok(Some(CarriedWordLook::of(&word)?)),''',
     [READ]),
    ("L5 another key's entry in the slot is read", LOOK,
     '''        let Some((_, value)) = self.word(conn, key, &reached_name(key)?)? else {''',
     '''        let any = |_: &[u8; 32]| true;
        let channel = derive::channel_id(&self.personal)?;
        let slot = slot_id(&derive::slot_key(&self.personal)?, &reached_name(key)?);
        let held = entries::slot_entries(conn, &channel, &slot)?;
        let read = version::current(&held, &self.personal, self.number, |by| any(by))?;
        let Some(value) = read.current.map(|version| version.value) else {''',
     [READ]),
    ("L6 a relay's rows are said the other way round", LOOK,
     '''            relay.has_what_was_carried = Some(!waits);''',
     '''            relay.has_what_was_carried = Some(waits);''',
     [TOOK_ALL]),
    ("L7 the rows are said where the device's own word is none", LOOK,
     '''    if !own.chain(added).any(|(this, word)| this && word.is_some()) {
        return Ok(());
    }''',
     '''''',
     [TOOK_ALL]),

    # ── Rule 6: a relay named three ways ────────────────────────────
    ("R1 the reader's own name for a relay is not used", LOOK,
     '''    if let Some((name, _)) = relays.iter().find(|(_, known)| *known == Some(key)) {
        return name.to_string();
    }''',
     '''''',
     [NAMED, LINES]),
    ("R2 a default relay is named by its key", LOOK,
     '''        Some(at) => FALLBACK_PEERS[at].to_string(),''',
     '''        Some(_) => format!("the relay whose key is {key}"),''',
     [NAMED]),
    ("R3 more is not said", LOOK,
     '''        more => format!("{} and {more} more", named.join(", ")),''',
     '''        _ => joined(&named),''',
     [NAMED, LINES]),

    # ── Rules 6 and 7: the lines ────────────────────────────────────
    ("D1 cordelia devices says still sending of a device whose word is read", CMD,
     '''            false if let Some(word) = carried_word_of(device) => {''',
     '''            false if let Some(word) = carried_word_of(device).filter(|_| false) => {''',
     [LINES]),
    ("D2 D1 says not yet of nothing", CMD,
     '''                if not_yet > 0 {
                    said.push_str(&format!(
                        "; not yet to {} that it is set up with''',
     '''                if not_yet > 0 || true {
                    said.push_str(&format!(
                        "; not yet to {} that it is set up with''',
     [LINES]),
    ("S1 the wait says still sending of a device whose word is read", CMD,
     '''            (true, false) if let Some(word) = carried_word_of(device) => {''',
     '''            (true, false) if let Some(word) = carried_word_of(device).filter(|_| false) => {''',
     [LINES]),
    ("S2 S5 leaves out what is not yet sent", CMD,
     '''                if not_yet > 0 {
                    said.push_str(&format!("; not yet to {}", other_relays(not_yet)));
                }''',
     '''''',
     [LINES]),
    ("S3 S4 is said where the device's own word is none", CMD,
     '''        now.push(match own_word.then(|| own_carried_line(seen)).flatten() {''',
     '''        now.push(match own_carried_line(seen) {''',
     [LINES]),
    ("S4 S4 counts a relay of no known rows as holding what was carried", CMD,
     '''        match relay["has_what_was_carried"] == true {''',
     '''        match relay["has_what_was_carried"] != false {''',
     [OVERLAP]),
    ("S5 S4 is said where no relay holds what was carried", CMD,
     '''    if held.is_empty() {
        return None;
    }
    let mut line = format!("this device has sent what it carried to {}", joined(&held));''',
     '''    let mut line = format!("this device has sent what it carried to {}", joined(&held));''',
     [OVERLAP]),
    ("S6 S4 leaves out what is not yet sent", CMD,
     '''    if !not_yet.is_empty() {
        line.push_str(&format!("; not yet to {}", joined(&not_yet)));
    }''',
     '''''',
     [LINES, OVERLAP]),
    ("S8 S4 is said of a word under another change", CMD,
     '''            device["applied"].as_u64() == Some(number) && carried_word_of(device).is_some()''',
     '''            carried_word_of(device).is_some()''',
     [LINES]),
    ("S7 one other relay is said as many", CMD,
     '''        1 => "1 other relay".into(),''',
     '''        1 => "1 other relays".into(),''',
     [LINES]),
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
