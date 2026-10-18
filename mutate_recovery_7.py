#!/usr/bin/env python3
"""Mutation checks for slice 7 of recovery and carrying: the read before a
carried name is let go (decision 2026-10-17 §4.2 items 1 and 4 to 8,
§4.3 and §4.6 for a device that sends). A part for each rule of the
slice: put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
LET_GO = 'crates/cordelia-api/src/let_go.rs'
SYNC = 'crates/cordelia-api/src/sync.rs'
NAMES = 'crates/cordelia-api/src/names.rs'
CARRY = 'crates/cordelia-api/src/carry.rs'
CARRYING = 'crates/cordelia-api/src/carrying.rs'
RECOVER = 'crates/cordelia-api/src/recover.rs'
ADDING = 'crates/cordelia-api/src/adding.rs'
OWN_READ = 'crates/cordelia-api/src/own_read.rs'
NODE_OWN_READ = 'crates/cordelia-node/src/device_entries/own_read.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
ORIG = {f: open(f).read() for f in (LET_GO, SYNC, NAMES, CARRY, CARRYING, RECOVER, ADDING,
                                    OWN_READ, NODE_OWN_READ, MAIN, PROTOCOL)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "carry_e2e"])
CORE = ("cordelia-core", ["--lib"])
def sync(test): return (API, "sync::tests::" + test)
def let_go(test): return (API, "let_go::tests::" + test)
def names(test): return (API, "names::tests::" + test)
def carrying(test): return (API, "carrying::tests::" + test)
def recover(test): return (API, "recover::tests::" + test)
def main(test): return (BIN, "tests::" + test)
def e2e(test): return (E2E, test)
def core(test): return (CORE, "protocol::tests::" + test)
def commands_api(test): return (("cordelia-api", ["--test", "commands_api"]), test)

HELD = sync("test_a_version_is_held_only_where_a_relay_read_after_the_ask_handed_it")
TIE = sync("test_an_entry_that_lost_a_tie_is_held_only_where_it_was_handed")
NO_VERSION = sync("test_an_entry_that_is_no_version_moves_nothing_on")
READS_ON = sync("test_a_let_go_reads_on_until_each_version_is_found")
ONLY_READ = sync("test_a_let_go_lets_go_only_of_what_was_read")
STOPPED = sync("test_a_stopped_device_lets_go_at_once_where_its_notes_show_nothing_unsent")
RELAYS_SAY = sync("test_what_is_said_of_each_relay_where_a_name_is_not_let_go")
NO_FOLDER = sync("test_a_name_that_a_carry_holds_with_no_folder_is_let_go")
FOLDER = sync("test_a_folders_unmapping_does_not_let_go_of_a_name_that_a_carry_holds")
UNDER_A_FOLDER = sync(
    "test_a_name_a_carry_brought_versions_into_under_a_folder_is_held_after_the_folders_unmapping")
ONLY_BROUGHT = sync("test_only_a_version_brought_in_marks_a_name")
BOUND = let_go("test_the_read_before_a_let_go_reads_on_for_so_long_at_most")
LOOK = recover(
    "test_a_name_the_look_brought_versions_into_under_a_folder_is_held_after_the_folders_unmapping")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── What is held (§4.2 item 5) ──
    ("H1 a slot of no version holds the entry", LET_GO,
     '''    let Some(current) = read.current else {
        return Ok(false);''',
     '''    let Some(current) = read.current else {
        return Ok(true);''',
     [NO_VERSION]),
    ("H2 a version above the entry does not hold it", LET_GO,
     '''    if current.rev > own.rev {
        return Ok(true);''',
     '''    if current.rev > own.rev {
        return Ok(false);''',
     [HELD]),
    ("H3 another text at the same revision is the same version", LET_GO,
     '''version.rev == mine.rev && version.value == mine.value''',
     '''version.rev == mine.rev''',
     [HELD]),
    ("H4 a lost version handed is not looked at", LET_GO,
     '''    Ok(same(&current) || read.lost.iter().any(same))''',
     '''    Ok(same(&current))''',
     [TIE]),
    ("H5 an entry by a key that does not count holds it", LET_GO,
     '''    let read = version::current(handed, secret, statement, &counts)?;''',
     '''    let read = version::current(handed, secret, statement, |_: &[u8; 32]| true)?;''',
     [HELD]),
    ("H6 the slot is read under a later statement", LET_GO,
     '''            if held_in(handed, &mine, &secret, standing.number(), counts)? {''',
     '''            if held_in(handed, &mine, &secret, standing.number() + 1, counts)? {''',
     [NO_VERSION]),
    # ── What is asked about (§4.2 item 4) ──
    ("A1 the entries of another author are asked about", LET_GO,
     '''        let Some(stored) = entries::author_entry(conn, &channel, &slot, &own)? else {''',
     '''        let Some(stored) = entries::author_entry(conn, &channel, &slot, &[0u8; 32])? else {''',
     [HELD, READS_ON]),
    ("A2 the entries asked about are counted twice", LET_GO,
     '''        found.asked += 1;''',
     '''        found.asked += 2;''',
     [HELD]),
    ("A3 an entry that no relay held is not noted", LET_GO,
     '''        if !held {
            found.not_held.push(stored.seq);
        }''',
     '''        if !held {}''',
     [HELD]),
    ("A4 what the store had taken is not noted", LET_GO,
     '''        not_held: Vec::new(),
        taken: kept_rows::last_taken(conn, &channel)?,''',
     '''        not_held: Vec::new(),
        taken: 0,''',
     [HELD]),
    # ── Reading on (§4.2 item 1) ──
    ("R1 the read goes on where each entry is held", LET_GO,
     '''    !found.each_held()
        && read.at''',
     '''    true
        && read.at''',
     [BOUND, READS_ON]),
    ("R2 the read goes on where no relay is read in part", LET_GO,
     '''        && read.at.iter().any(|at| at.read.reads_on())''',
     '''        && true''',
     [BOUND]),
    ("R3 the read has no bound", LET_GO,
     '''        && now.saturating_duration_since(read.begun) < READ_ON_MOST''',
     '''        && true''',
     [BOUND]),
    ("R4 the bound is one round", LET_GO,
     '''const READ_ON_MOST: Duration = Duration::from_secs(RECOVERY_READ_ON_MAX_SECS);''',
     '''const READ_ON_MOST: Duration = Duration::from_secs(CARRY_READ_MAX_SECS);''',
     [BOUND]),
    ("R5 the read's bound is counted from long before it began", OWN_READ,
     '''            begun: now,''',
     '''            begun: now.checked_sub(Duration::from_secs(1000)).unwrap_or(now),''',
     [BOUND]),
    ("R6 the bound reads one second longer", PROTOCOL,
     '''    / (PUSH_BYTES_PER_PEER_PER_MINUTE - SHOW_ANSWER_ROOM_BYTES)
    + CARRY_READ_MAX_SECS;''',
     '''    / (PUSH_BYTES_PER_PEER_PER_MINUTE - SHOW_ANSWER_ROOM_BYTES)
    + CARRY_READ_MAX_SECS
    + 1;''',
     [core("test_a_recovery_reads_on_for_what_a_channel_at_its_cap_takes_decision_2026_10_17_3")]),
    ("R10 a node with no network waits for a read that nothing makes", LET_GO,
     '''    if state.push_tx.is_none() {
        return Err(ApiError::Conflict(not_read_says(name)));
    }''',
     '''''',
     [commands_api("test_a_carry_by_command_holds_the_name_and_reads_each_generation_that_was_left")]),
    ("R7 a read of another channel is read on", LET_GO,
     '''                .is_some_and(|kept| kept.channel == channel);''',
     '''                .is_some();''',
     [ONLY_READ]),
    ("R8 a read that the node forgot during its round is taken as kept", LET_GO,
     '''    let Some(at) = reads.get(&read, Instant::now()) else {
        return Err(ApiError::Conflict(started_again_says(name)));
    };''',
     '''    let Some(at) = reads.get(&read, Instant::now()) else {
        unreachable!("the read is kept");
    };''',
     [ONLY_READ]),
    ("R9 every relay is said while the read goes on", SYNC,
     '''                .filter(|at| at.read.reads_on())
                .map(|at| serde_json::json!({ "relay": at.relay, "bytes": at.bytes }))''',
     '''                .filter(|_| true)
                .map(|at| serde_json::json!({ "relay": at.relay, "bytes": at.bytes }))''',
     [READS_ON]),
    # ── Bound to its read (§4.2 item 8) ──
    ("B1 a read the node no longer keeps lets go", SYNC,
     '''    let Some(kept) = reads.get(read, std::time::Instant::now()) else {
        return Err(ApiError::Conflict(check::started_again_says(name)));
    };''',
     '''    let Some(kept) = reads.get(read, std::time::Instant::now()) else {
        unreachable!("the read is kept");
    };''',
     [ONLY_READ]),
    ("B2 what the store took since the read is let go", SYNC,
     '''    if channel != Some(kept.channel) || taken != found.taken {''',
     '''    if channel != Some(kept.channel) || (taken != found.taken && false) {''',
     [ONLY_READ]),
    ("B3 a name whose channel is another since the read is let go", SYNC,
     '''    if channel != Some(kept.channel) || taken != found.taken {''',
     '''    if (channel != Some(kept.channel) && false) || taken != found.taken {''',
     [ONLY_READ]),
    ("B4 a name of which no relay held an entry is let go", SYNC,
     '''        if !found.each_held() {
            let said''',
     '''        if false {
            let said''',
     [HELD, NO_FOLDER]),
    ("B5 a let-go does not end its read", SYNC,
     '''        reads.forget(read);
    }
    let now''',
     '''    }
    let now''',
     [FOLDER]),
    ("B6 a name that no carry holds is let go", SYNC,
     '''    if !crate::names::carried(db).map_err(refused)?.contains(name) {
        return Ok(false);
    }
    if let Some((read, found)) = read {''',
     '''    if !crate::names::carried(db).map_err(refused)?.contains(name) && false {
        return Ok(false);
    }
    if let Some((read, found)) = read {''',
     [NO_FOLDER]),
    ("B7 a device that has stopped reads the relays", SYNC,
     '''                if stands != crate::at_relays::Stands::Applied {''',
     '''                if false {''',
     [STOPPED]),
    ("B8 a name that no carry holds is let go on a device that has stopped", SYNC,
     '''                if !crate::names::carried(&db).map_err(refused)?.contains(name) {
                    return Err(not_mapped);''',
     '''                if !crate::names::carried(&db).map_err(refused)?.contains(name) && false {
                    return Err(not_mapped);''',
     [STOPPED]),
    ("B9 the let-go does not say how many versions were asked about", SYNC,
     '''            status.let_go_versions = Some(found.asked);''',
     '''            status.let_go_versions = None;''',
     [HELD]),
    # ── What the refusal says (§4.6) ──
    ("S1 a relay read to its end is not said so", LET_GO,
     '''            ReadAt::ToItsEnd => "read to its end.".to_string(),''',
     '''            ReadAt::ToItsEnd => "read.".to_string(),''',
     [RELAYS_SAY, NO_FOLDER]),
    ("S2 a relay that holds none is not said so", LET_GO,
     '''            ReadAt::HoldsNone => "holds none of it.".to_string(),''',
     '''            ReadAt::HoldsNone => "read to its end.".to_string(),''',
     [RELAYS_SAY]),
    ("S3 a relay read in part is not said so", LET_GO,
     '''            ReadAt::InPart => "read in part.".to_string(),''',
     '''            ReadAt::InPart => "read to its end.".to_string(),''',
     [RELAYS_SAY]),
    ("S4 a relay not reached is not said so", LET_GO,
     '''            ReadAt::NotReached => "not reached.".to_string(),''',
     '''            ReadAt::NotReached => "read to its end.".to_string(),''',
     [RELAYS_SAY, NO_FOLDER]),
    ("S5 a relay read for the whole bound is not said so", LET_GO,
     '''                "read in part, for {} minutes.",''',
     '''                "read in part, for {} seconds.",''',
     [RELAYS_SAY]),
    ("S6 every entry held by no relay is said to have had no room", LET_GO,
     '''            .filter(|seq| refused.contains(seq))''',
     '''            .filter(|_| true)''',
     [RELAYS_SAY]),
    ("S7 when a relay last had no room is not said", LET_GO,
     '''            if let Some(last) = last {''',
     '''            if let Some(last) = last.filter(|_| false) {''',
     [NO_FOLDER]),
    ("S8 one version is said as them", LET_GO,
     '''                (1, 1) => "it".to_string(),''',
     '''                (1, 1) => "1 of them".to_string(),''',
     [NO_FOLDER]),
    ("S9 the relays are not said", LET_GO,
     '''    for line in relays {
        said.push('\\n');
        said.push_str(line);
    }''',
     '''    for _ in relays {}''',
     [NO_FOLDER]),
    ("S10 the refusal does not say how to let go now", LET_GO,
     '''To let it go now, with {them}, run `cordelia sync unmap {}` at a terminal.''',
     '''To let it go now, run `cordelia sync unmap {}`.''',
     [NO_FOLDER]),
    ("S11 home memory is not quoted in a command", LET_GO,
     '''        false => format!("'{name}'"),''',
     '''        false => name.to_string(),''',
     [let_go("test_a_name_is_typed_so_that_a_shell_reads_it")]),
    ("S12 a minute ago is said as just now", LET_GO,
     '''        s if s < 60 => return "just now".into(),''',
     '''        s if s < 120 => return "just now".into(),''',
     [let_go("test_how_long_ago_is_said")]),
    ("S13 the line of no room names no relay's key", NODE_OWN_READ,
     '''        at.key = Some(link.relay().0);''',
     '''        at.key = None;''',
     [e2e("a_carried_name_is_not_let_go_while_no_relay_holds_what_it_brought")]),
    # ── The list of 4.3 ──
    ("L1 a name with no folder is noted as brought in", NAMES,
     '''    if !has_folder(conn, name)? {
        return Ok(());
    }
    let mut kept = brought_in(conn)?;''',
     '''    let mut kept = brought_in(conn)?;''',
     [names("test_a_name_held_for_a_carry_is_listed_with_no_folder_and_with_sync_off"),
      carrying("test_what_a_removed_key_signed_comes_in_only_as_the_phrases_word_allows")]),
    ("L2 the list is not kept", NAMES,
     '''    let mut kept = brought_in(conn)?;
    if kept.insert(name.to_string()) {
        keep_brought_in(conn, &kept)?;
    }''',
     '''    let mut kept = brought_in(conn)?;
    kept.insert(name.to_string());''',
     [UNDER_A_FOLDER, LOOK]),
    ("L3 a folder's unmapping stops a name brought in", SYNC,
     '''            if brought_in.contains(name) {''',
     '''            if brought_in.contains(name) && false {''',
     [UNDER_A_FOLDER, LOOK]),
    ("L4 a name held after its folder is not held by a carry", NAMES,
     '''        let mut kept = carried(conn)?;
        if kept.insert(name.to_string()) {
            keep_carried(conn, &kept)?;
        }
        // With sync off''',
     '''        // With sync off''',
     [UNDER_A_FOLDER, LOOK]),
    ("L5 a name held after its folder has no word with sync off", NAMES,
     '''        if Standing::to_write(conn).is_ok() {
            say(conn, identity, name, now)?;''',
     '''        if Standing::to_write(conn).is_ok() && false {
            say(conn, identity, name, now)?;''',
     [UNDER_A_FOLDER]),
    ("L6 a name that is stopped stays in the list", NAMES,
     '''        if brought.remove(name) {
            keep_brought_in(conn, &brought)?;
        }''',
     '''        if brought.remove(name) {}''',
     [UNDER_A_FOLDER]),
    ("L7 a device that leaves its phrase keeps the list", ADDING,
     '''    meta::remove(conn, meta::PERSON_NAMES_BROUGHT_IN)?;
''',
     '''''',
     [names("test_a_name_held_for_a_carry_is_listed_with_no_folder_and_with_sync_off")]),
    ("L8 a bring that brought nothing marks the name", CARRY,
     '''        if brought == Brought::Carried {
            crate::names::note_brought_in(conn, name)?;''',
     '''        if true {
            crate::names::note_brought_in(conn, name)?;''',
     [ONLY_BROUGHT]),
    ("L9 the carry of `sync map` marks the name", CARRYING,
     '''            true => carry::bring,
            false => carry::bring_by_command,''',
     '''            true => carry::bring_by_command,
            false => carry::bring_by_command,''',
     [ONLY_BROUGHT]),
    ("L10 the carry by command marks no name", CARRYING,
     '''            true => carry::bring,
            false => carry::bring_by_command,''',
     '''            true => carry::bring,
            false => carry::bring,''',
     [UNDER_A_FOLDER]),
    ("L11 the carry `--from` marks no name", CARRYING,
     '''                    carry::bring_by_command(&conn, &state.identity, name, version, rule, now())?;''',
     '''                    carry::bring(&conn, &state.identity, name, version, rule, now())?;''',
     [carrying("test_what_a_removed_key_signed_comes_in_only_as_the_phrases_word_allows")]),
    ("L12 what a command hands under the phrase's word marks no name", CARRYING,
     '''                let brought = carry::bring_by_command(
                    &conn,
                    &state.identity,
                    &name,''',
     '''                let brought = carry::bring(
                    &conn,
                    &state.identity,
                    &name,''',
     [carrying("test_a_generation_never_held_is_read_by_the_command_and_handed_in_the_clear")]),
    ("L13 the look of a recovery marks no name", RECOVER,
     '''                    let brought = carry::bring_by_command(
                        &conn,
                        &state.identity,
                        name,''',
     '''                    let brought = carry::bring(
                        &conn,
                        &state.identity,
                        name,''',
     [LOOK]),
    # ── What the command says (§4.6) ──
    ("C1 a let-go says nothing of what a relay held", MAIN,
     '''            "a relay held each of its {n} versions when it was read just now, so nothing is \\
             lost by it."''',
     '''            "nothing is lost by it."''',
     [main("test_what_unmap_says_of_a_name_that_a_carry_held")]),
    ("C2 the command does not pass on how many versions were held", MAIN,
     '''            let versions = after["let_go_versions"].as_u64();''',
     '''            let versions = None;''',
     [main("test_what_unmap_says_of_the_nodes_answer_to_letting_go")]),
    ("C3 the line while reading counts in KiB", MAIN,
     '''                bytes as f64 / (1024.0 * 1024.0)''',
     '''                bytes as f64 / 1024.0''',
     [main("test_what_unmap_says_while_it_reads")]),
    ("C4 the command asks for the next round from the start", MAIN,
     '''        asking = serde_json::json!({ "folder": name, "read": read, "asks": asks });''',
     '''        asking = serde_json::json!({ "folder": name, "read": null, "asks": asks });''',
     [main("test_what_unmap_says_while_it_reads")]),
    ("C5 the command says nothing while it reads", MAIN,
     '''        for line in reading_says(name, &after["reading"]) {
            say(line);
        }''',
     '''        let _ = &mut say;''',
     [main("test_what_unmap_says_while_it_reads")]),
    ("C6 the line after a folder's unmapping says what it said before", MAIN,
     '''`cordelia sync unmap {}` lets it go, once a relay holds each of its versions.",''',
     '''`cordelia sync unmap {}` lets it go, once nothing of it waits to be sent.",''',
     [main("test_what_unmap_says_of_a_name_that_is_still_held_after_its_folder")]),
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
