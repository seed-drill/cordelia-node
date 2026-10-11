#!/usr/bin/env python3
"""Mutation checks for the status object, statements and the upgrade of
messages between a person's own agents: the `messages` object that
`/api/v1/status` answers on a personal node that stands applied, and that
`cordelia status --json` carries and nothing else reads; the messages
channel left out of every fact the level is worked out from; what a
statement does to messages, and what a removed device reads; sync off;
the summary's help with the texts of the hooks; and the version before
beside this one (decision 2026-10-09 §5, §8, §9.1, §9.2, §10). A part for
each rule of the slice: put each fault in, and confirm the test named for
it fails on an assertion. Run from the root of a checkout that nothing else
edits."""
import re, subprocess, sys

# One name for each file a part edits.
STORE = 'crates/cordelia-storage/src/messages.rs'
MSG = 'crates/cordelia-api/src/messages.rs'
HANDLERS = 'crates/cordelia-api/src/handlers.rs'
LEAVING = 'crates/cordelia-api/src/leaving.rs'
AT_RELAYS = 'crates/cordelia-api/src/at_relays.rs'
INDICATOR = 'crates/cordelia-node/src/indicator.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
CMD = 'crates/cordelia-node/src/msg_cmd.rs'
ENGINE = 'crates/cordelia-node/src/device_entries.rs'
ORIG = {f: open(f).read() for f in (STORE, MSG, HANDLERS, LEAVING, AT_RELAYS, INDICATOR,
                                     MAIN, CMD, ENGINE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "msg_e2e"])
ENTRIES = ("cordelia-node", ["--test", "device_entries_e2e"])
THREAT = ("cordelia-node", ["--test", "threat_model"])
def api(test): return (API, "messages::tests::" + test)
def reader(test): return (API, "reader::tests::" + test)
def leaving(test): return (API, "leaving::tests::" + test)
def indicator(test): return (BIN, "indicator::tests::" + test)
def e2e(test): return (E2E, test)
def entries(test): return (ENTRIES, test)
def threat(test): return (THREAT, test)

COUNTS = api("the_status_counts_messages_each_by_its_rule")
NEVER = indicator("messages_never_hold_a_level_or_change_the_line")
NOT_WAITING = leaving("test_the_messages_channel_is_not_counted_as_waiting_or_refused")
ANOTHER = entries("a_message_answered_another_is_not_said_in_another_form")
NO_PLACE = entries("past_the_limit_on_proofs_a_device_has_no_messages_and_says_so")
ROOM = threat("a_message_that_a_relay_refuses_for_room_leaves_the_level_and_the_line")
JSON = e2e("the_status_carries_the_messages_object_in_json")
EXPIRE = reader("the_old_generations_messages_expire_on_time")
FULL = reader("a_ring_slot_written_again_is_taken_by_a_full_relay")
STATEMENT = e2e(
    "a_statement_starts_an_empty_messages_channel_and_what_was_held_is_shown_until_it_expires")
REMOVED = e2e(
    "a_removed_device_reads_what_was_sent_in_its_generation_and_nothing_after_its_removal_was_applied")
SYNC_OFF = e2e("with_sync_off_messages_are_off")
HELP = e2e("the_summarys_help_prints_the_hook_and_the_instructions_line_and_exits_0")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The object: each field by its rule (§8) ──────────────────────
    ("S1 an agent is counted unread a message of a signer that does not count", MSG,
     '''                if counting.counts(&key_of(&message.signer)?) {
                    unread_by_an_agent += 1;
                }''',
     '''                unread_by_an_agent += 1;''',
     [COUNTS]),
    ("S2 unread by an agent is of the first mapped folder alone", MSG,
     '''        for name in &names {
            for message in marks::unread(conn, identity, name, now)? {''',
     '''        for name in names.iter().take(1) {
            for message in marks::unread(conn, identity, name, now)? {''',
     [COUNTS, JSON]),
    ("S3 a person is counted a message to a name not mapped here", MSG,
     '''                .is_none_or(|to| names.iter().any(|name| name == to));''',
     '''                .is_none_or(|_| true);''',
     [COUNTS]),
    ("S4 a person is counted what was sent here", MSG,
     '''            if to_here
                && message.signer[..] != own[..]
                && !kept''',
     '''            if to_here
                && !kept''',
     [COUNTS, JSON]),
    ("S5 a person is counted what a person read here", MSG,
     '''                && !kept(held::is_read_by_a_person(conn, &id_of(&message.id)?))?
            {''',
     '''            {''',
     [COUNTS, JSON]),
    ("S6 nothing is said to wait", MSG,
     '''            waiting: kept(held::kept_count(conn))?,''',
     '''            waiting: 0,''',
     [COUNTS, ROOM]),
    ("S7 a refused clearing is counted as a message", STORE,
     '''AND e.rev % 2 = 0 AND e.slot <> ?3''',
     '''AND e.slot <> ?3''',
     [COUNTS]),
    ("S8 a refused list is counted as a message", STORE,
     '''AND e.rev % 2 = 0 AND e.slot <> ?3''',
     '''AND e.rev % 2 = 0''',
     [COUNTS]),
    ("S9 a message refused by two relays is counted twice", STORE,
     '''"SELECT COUNT(DISTINCT r.seq) FROM at_relays_refused r''',
     '''"SELECT COUNT(r.seq) FROM at_relays_refused r''',
     [COUNTS]),
    ("S10 another device's refused entry is counted", STORE,
     '''WHERE r.channel = ?1 AND e.author = ?2 AND''',
     '''WHERE r.channel = ?1 AND ?2 = ?2 AND''',
     [COUNTS]),
    ("S11 who fills the channel is never named", MSG,
     '''            filled_by: filled_by(conn, |channel| own_channels.no_room_for_messages(channel))?,''',
     '''            filled_by: None,''',
     [COUNTS, ROOM, FULL]),
    ("S12 nothing is said to be held back", STORE,
     '''             WHERE i.placed_at IS NULL AND ?1 < {expires} AND {live}",
            expires = expires_sql(),
            live = live_sql(),
        ),
        [now],''',
     '''             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}",
            expires = expires_sql(),
            live = live_sql(),
        ),
        [now],''',
     [COUNTS, JSON]),
    ("S13 nothing is said to be overwritten", MSG,
     '''            overwritten: kept(held::overwritten_in_all(conn))?,''',
     '''            overwritten: 0,''',
     [COUNTS]),
    ("S14 the device always has a place", MSG,
     '''            no_place: own_channels.no_place(),
        }))''',
     '''            no_place: false,
        }))''',
     [COUNTS, NO_PLACE]),
    ("S15 a field of the object is not answered", MSG,
     '''            "held_back": self.held_back,''',
     '''''',
     [COUNTS, JSON]),
    ("S16 working the object out gives no places", MSG,
     '''        let own = identity.public_key();
        kept(held::give_places(conn, &own, now))?;
        let counting = who_counts(conn)?;
        let names: Vec<String>''',
     '''        let own = identity.public_key();
        let counting = who_counts(conn)?;
        let names: Vec<String>''',
     [COUNTS, JSON]),
    ("S17 the node answers no object", HANDLERS,
     '''    let messages = match older_kind || state.held.why().is_some() {''',
     '''    let messages = match true {''',
     [JSON, ROOM]),
    ("S18 status --json does not carry the object", MAIN,
     '''                out["messages"] = live["messages"].clone();''',
     '''''',
     [JSON, ROOM]),

    # ── Messages feed nothing the level is worked out from (§8, C13) ─
    ("L1 what waits of messages is taken into what waits", INDICATOR,
     '''    f.outbox_waiting = live["outbox_waiting"].as_u64().unwrap_or(0);''',
     '''    f.outbox_waiting = live["outbox_waiting"].as_u64().unwrap_or(0)
        + live["messages"]["waiting"].as_u64().unwrap_or(0);''',
     [NEVER]),
    ("L2 what a relay refused of messages is taken into what was refused", INDICATOR,
     '''        .filter(|r| r["refusals"].as_u64() >= Some(REFUSALS_BEFORE_ATTENTION))
        .count() as u64;''',
     '''        .filter(|r| r["refusals"].as_u64() >= Some(REFUSALS_BEFORE_ATTENTION))
        .count() as u64
        + live["messages"]["refused_for_room"].as_u64().unwrap_or(0);''',
     [NEVER]),
    ("L3 the messages channel is counted in what waits at a relay", LEAVING,
     '''        if channel.kind == Kind::Messages {
            continue;
        }
        let waits = waits_in(conn, identity, relay, &channel)?;''',
     '''        let waits = waits_in(conn, identity, relay, &channel)?;''',
     [NOT_WAITING, ROOM]),
    ("L4 a relay with no room for messages sets the hold", ENGINE,
     '''                if channel.kind != Kind::Messages {
                    self.no_room(link, done.refused == Some(Pushed::OverAllowance), false);''',
     '''                if true {
                    self.no_room(link, done.refused == Some(Pushed::OverAllowance), false);''',
     [ROOM]),
    ("L5 a refusal for room of messages is not kept for the object", ENGINE,
     '''                    self.state
                        .own_channels
                        .say_no_room_for_messages(&channel.id);''',
     '''''',
     [ROOM]),
    ("L6 an answer of another to a message is said in another form", ENGINE,
     '''            if done.another > 0 && channel.kind != Kind::Messages {''',
     '''            if done.another > 0 {''',
     [ANOTHER]),

    # ── A statement (§9.1) ───────────────────────────────────────────
    ("G1 only the generation applied is shown", STORE,
     '''             FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id",''',
     '''             FROM message_index i
             WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
               AND i.generation = (SELECT MAX(id) FROM message_generations)
             ORDER BY shown_at, i.id",''',
     [EXPIRE, STATEMENT]),
    ("G2 read never says that a message is from before the last change", MSG,
     '''            before_the_last_change: current != Some(message.generation),''',
     '''            before_the_last_change: false,''',
     [STATEMENT]),
    ("G3 a removed device shows what it holds", MSG,
     '''    if stands(conn)? != Stands::Applied {
        return Err(NotRead::Refused(Refused::NotApplied));
    }
    let Some(name) = agent_of(conn, folder).map_err(said)? else {
        return Err(NotRead::Refused(Refused::NotMapped));
    };''',
     '''    let Some(name) = agent_of(conn, folder).map_err(said)? else {
        return Err(NotRead::Refused(Refused::NotMapped));
    };''',
     [REMOVED]),

    # ── Sync off (§2.1, C12) ─────────────────────────────────────────
    ("O1 the messages channel is listed with sync off", AT_RELAYS,
     '''    if meta::get(conn, meta::SYNC_CLAUDE_DIR)?.is_some() {
        own.push(messages);
    }''',
     '''    own.push(messages);''',
     [SYNC_OFF]),

    # ── Hooks (§5) ───────────────────────────────────────────────────
    ("H1 summary takes --help as an argument it does not take", CMD,
     '''            Some("-h" | "--help") => return None,''',
     '''''',
     [HELP]),
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
