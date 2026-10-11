#!/usr/bin/env python3
"""Mutation checks for `cordelia msg log`, its route, and the end of a hold
between two agents: what log lists at a terminal and anywhere else, the
order of its threads and of their messages, what it says of each message
and frames as read does, what it counts after the threads, the one record
of what a relay refused for room that send and log read, the question,
and the mark read by a person that only its yes writes (decision
2026-10-09 §2.2, §2.3, §2.5, §3.1, §4.1, §4.2, §4.3, §6, §7.2, §9.1,
§10). A part for each rule of the slice: put each fault in, and confirm
the test named for it fails on an assertion. Run from the root of a
checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
STORE = 'crates/cordelia-storage/src/messages.rs'
MSG = 'crates/cordelia-api/src/messages.rs'
LIB = 'crates/cordelia-api/src/lib.rs'
CMD = 'crates/cordelia-node/src/msg_cmd.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
ORIG = {f: open(f).read() for f in (STORE, MSG, LIB, CMD, MAIN)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "msg_e2e"])
def api(test): return (API, "messages::tests::" + test)
def sender(test): return (API, "sender::tests::" + test)
def reader(test): return (API, "reader::tests::" + test)
def marks(test): return (API, "marks::tests::" + test)
def cmd(test): return (BIN, "msg_cmd::tests::" + test)
def main(test): return (BIN, "tests::" + test)
def e2e(test): return (E2E, test)

LISTS = api("log_lists_every_name_without_a_folder_and_the_folders_agent_with_one")
MARKS = api("log_marks_as_read_by_a_person_only_what_it_was_given")
OWN = api("log_says_what_waits_what_was_refused_for_room_and_what_may_not_have_reached_everyone")
HELD = api("log_lists_a_message_held_back_by_its_id_and_its_sender_alone")
OLDEST = api("oldest_first_is_by_shown_time_then_by_id")
ORDER = api("the_checks_are_made_in_one_order")
ROUTE = api("the_log_route_lists_marks_and_refuses_what_is_not_asked_rightly")
ROUTES = api("the_routes_of_messages_are_a_personal_nodes_and_each_needs_the_token")
HELD_UP = api("a_summary_of_another_version_or_while_held_up_is_nothing")
SEND_ROOM = api("a_send_after_a_refusal_for_room_names_who_fills_the_channel")
FULL = sender("a_ring_slot_written_again_is_taken_by_a_full_relay")
NO_HOLD = sender("held_back_messages_make_no_hold")
ENDS = sender("a_hold_ends_when_its_messages_expire_or_stop_being_live")
FALSELY = sender("a_relay_that_answers_falsely_makes_a_message_go_under_at_most_four_numbers")
PAIRS = sender("the_hold_is_by_the_pair_of_agents_and_every_name_is_a_pair_of_its_own")
GAP = reader("a_gap_in_a_signers_numbers_is_said_as_overwritten")
NOT_MSG = reader("a_message_in_a_slot_named_for_another_key_is_no_message")
LIES = marks("a_device_that_lies_in_its_list_hides_from_summaries_and_not_from_log")
WORDS = cmd("the_frame_the_summary_and_the_refusals_say_what_this_record_says")
PRINTS = cmd("log_frames_each_body_as_read_does_and_lists_what_is_held_back_without_it")
SET = cmd("every_character_of_the_set_is_taken_out_of_a_subject_a_name_a_label_and_a_link_and_escaped_in_a_body")
CUT = cmd("the_agents_name_is_cut_at_48_in_summary_read_and_send_and_the_subject_at_80")
CHECKS = cmd("the_checks_are_made_in_one_order")
NOT_KNOWN = cmd("a_request_not_answered_in_time_is_not_a_node_that_is_not_running")
HELP = main("the_logs_help_says_it_is_for_a_person_at_a_terminal")
OUTSIDE = e2e("log_outside_a_terminal_shows_only_the_folders_agent")
TEN = e2e("a_pair_stops_at_ten_until_a_person_reads_at_a_terminal_and_types_yes")
READ_MARKS = e2e("read_marks_by_the_agent_and_log_by_a_person_at_a_terminal_with_yes")
REMOVED = e2e("a_removed_device_is_shown_nothing_and_sends_nothing")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── The store ────────────────────────────────────────────────────
    ("LS1 a person's mark is not written", STORE,
     '''"INSERT OR IGNORE INTO message_read_by_a_person (id) VALUES (?1)",''',
     '''"DELETE FROM message_read_by_a_person WHERE id = ?1",''',
     [MARKS, NO_HOLD]),
    ("LS2 what waits for a place is what has one", STORE,
     '''WHERE i.placed_at IS NULL AND ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id''',
     '''WHERE i.placed_at IS NOT NULL AND ?1 < {expires} AND {live}
             ORDER BY shown_at, i.id''',
     [HELD]),
    ("LS3 the overwritten are read from H's column", STORE,
     '''                overwritten: from_sql(row.get(3)?),''',
     '''                overwritten: from_sql(row.get(2)?),''',
     [GAP]),
    ("LS4 the entries that were no message are read from another column", STORE,
     '''                not_messages: from_sql(row.get(4)?),''',
     '''                not_messages: from_sql(row.get(3)?),''',
     [NOT_MSG]),
    ("LS5 the dropped kept values are those that were not dropped", STORE,
     '''AND not_every_relay = 1 ORDER BY id''',
     '''AND not_every_relay = 0 ORDER BY id''',
     [OWN, FALSELY]),
    ("LS6 a refused clearing is taken for a refused message", STORE,
     '''WHERE r.channel = ?1 AND e.author = ?2 AND e.rev % 2 = 0''',
     '''WHERE r.channel = ?1 AND e.author = ?2 AND e.rev % 2 = 1''',
     [OWN, FULL]),
    ("LS7 a removed signer's label is not found in the index", STORE,
     '''"SELECT label FROM message_index WHERE signer = ?1 AND label != ''
             ORDER BY first_held DESC LIMIT 1",''',
     '''"SELECT label FROM message_index WHERE signer = ?1 AND label = ''
             ORDER BY first_held DESC LIMIT 1",''',
     [HELD]),

    # ── log at the node ──────────────────────────────────────────────
    ("LA1 a device that does not stand applied is listed", MSG,
     '''    if stands(conn)? != Stands::Applied {
        return Err(NotRead::Refused(Refused::NotApplied));
    }
    let name = match asked.folder {''',
     '''    let name = match asked.folder {''',
     [ORDER, HELD_UP]),
    ("LA2 the folder is asked before the device", MSG,
     '''    if stands(conn)? != Stands::Applied {
        return Err(NotRead::Refused(Refused::NotApplied));
    }
    let name = match asked.folder {''',
     '''    if asked.folder.is_none() && stands(conn)? != Stands::Applied {
        return Err(NotRead::Refused(Refused::NotApplied));
    }
    let name = match asked.folder {''',
     [ORDER]),
    ("LA3 an unmapped folder lists every name", MSG,
     '''            None => return Err(NotRead::Refused(Refused::NotMapped)),''',
     '''            None => None,''',
     [LISTS, ROUTE]),
    ("LA4 log gives no places", MSG,
     '''    kept(held::give_places(conn, &own, now))?;
    let counting = who_counts(conn)?;''',
     '''    let counting = who_counts(conn)?;''',
     [LISTS]),
    ("LA5 a folder's agent is shown messages to other names", MSG,
     '''            its_own || to.is_none_or(|to| to == name)''',
     '''            its_own || to.is_none_or(|to| to == name) || true''',
     [LISTS]),
    ("LA6 a folder's agent is not shown what it sent here", MSG,
     '''            let its_own = signer == own && from == name;''',
     '''            let its_own = signer == own && from == name && false;''',
     [LISTS]),
    ("LA7 every message listed is marked", MSG,
     '''        if asked.mark.contains(&id) {''',
     '''        if asked.mark.contains(&id) || !asked.mark.is_empty() {''',
     [MARKS]),
    ("LA8 the count of what was marked is wrong", MSG,
     '''            marked += 1;''',
     '''            marked += 2;''',
     [MARKS, ROUTE]),
    ("LA9 since is not kept to", MSG,
     '''        if asked.since.is_some_and(|since| message.shown_at < since) {''',
     '''        if asked.since.is_some_and(|since| message.shown_at < since - 1_000_000) {''',
     [LISTS]),
    ("LA10 a message to every name is read by no name", MSG,
     '''            None => names.iter().map(String::as_str).collect(),''',
     '''            None => Vec::new(),''',
     [LISTS]),
    ("LA11 this device's own table is not asked", MSG,
     '''            read_here |= on.here;''',
     '''            read_here |= false;''',
     [LISTS]),
    ("LA12 the other devices' lists are not asked", MSG,
     '''                if !read_on.contains(&key) {
                    read_on.push(key);''',
     '''                if read_on.contains(&key) {
                    read_on.push(key);''',
     [LIES]),
    ("LA13 a person's mark is not said", MSG,
     '''                read_by_a_person: kept(held::is_read_by_a_person(conn, &id))?,''',
     '''                read_by_a_person: false,''',
     [MARKS, ROUTE]),
    ("LA14 nothing is from before the last change", MSG,
     '''            current != Some(message.generation),
            Some(Said {''',
     '''            false,
            Some(Said {''',
     [OWN]),
    ("LA15 a signer that no longer counts is not said", MSG,
     '''        signer_removed: !counting.counts(&signer),''',
     '''        signer_removed: false,''',
     [HELD]),
    ("LA16 a message's thread is never its thread field", MSG,
     '''    let signer = key_of(signer)?;
    let thread = match id_of(thread) {''',
     '''    let signer = key_of(signer)?;
    let thread = match id_of(&[0u8; 16]) {''',
     [OLDEST]),
    ("LA17 in a thread, one shown time stands by the ID backwards", MSG,
     '''    listed.sort_by_key(|message| (message.shown_at, message.id));''',
     '''    listed.sort_by_key(|message| (message.shown_at, std::cmp::Reverse(message.id)));''',
     [OLDEST]),
    ("LA18 threads oldest first", MSG,
     '''    threads.sort_by(|(a, of_a), (b, of_b)| (newest(of_b), b).cmp(&(newest(of_a), a)));''',
     '''    threads.sort_by(|(a, of_a), (b, of_b)| (newest(of_a), a).cmp(&(newest(of_b), b)));''',
     [OLDEST, LISTS]),
    ("LA19 what is held back is not listed", MSG,
     '''    for message in kept(held::waiting_for_places(conn, now))? {''',
     '''    for message in Vec::<held::HeldBack>::new() {''',
     [HELD]),
    ("LA20 the overwritten are not counted", MSG,
     '''        counted.overwritten += signer.overwritten;''',
     '''        counted.overwritten += 0;''',
     [GAP]),
    ("LA21 the entries that were no message are not counted", MSG,
     '''        counted.not_messages += signer.not_messages;''',
     '''        counted.not_messages += 0;''',
     [NOT_MSG, FULL]),
    ("LA22 what is held back is not counted", MSG,
     '''        counted.held_back += held_back;''',
     '''        counted.held_back += 0;''',
     [HELD, NO_HOLD]),
    ("LA23 a signer with nothing counted is listed", MSG,
     '''        .filter(|c| c.overwritten + c.not_messages + c.held_back > 0)''',
     '''        .filter(|c| c.overwritten + c.not_messages + c.held_back >= 0)''',
     [OWN]),
    ("LA24 this device is counted under a label", MSG,
     '''                    true => None,
                    false => Some(signer_label(conn, statement, &key)?),''',
     '''                    true => Some(String::new()),
                    false => Some(signer_label(conn, statement, &key)?),''',
     [OWN]),
    ("LA25 a message refused for room is said to wait too", MSG,
     '''        .filter(|kept| Some(kept.generation) == current && !room.refused.contains(&kept.id))''',
     '''        .filter(|kept| Some(kept.generation) == current)''',
     [OWN, FULL]),
    ("LA26 what waited in a generation left still waits", MSG,
     '''        .filter(|kept| Some(kept.generation) == current && !room.refused.contains(&kept.id))''',
     '''        .filter(|kept| !room.refused.contains(&kept.id))''',
     [OWN]),
    ("LA27 a folder's agent is told of every own message", MSG,
     '''            .any(|m| m.id[..] == id[..] && m.signer[..] == own[..] && m.from == *name),''',
     '''            .any(|m| m.id[..] == id[..]),''',
     [OWN]),
    ("LA28 every own message may not have reached every device", MSG,
     '''        if message.signer[..] == own[..] && current != Some(message.generation) {''',
     '''        if message.signer[..] == own[..] {''',
     [OWN]),
    ("LA29 a refused message without the flag names no signer", MSG,
     '''    if !no_room(&channel) && refused.is_empty() {''',
     '''    if !no_room(&channel) {''',
     [OWN]),
    ("LA30 the flag of a refusal since the start names no signer", MSG,
     '''    if !no_room(&channel) && refused.is_empty() {''',
     '''    if refused.is_empty() {''',
     [SEND_ROOM]),
    ("LA31 the route's since is not taken", MSG,
     '''            Ok(at) => Some(at.timestamp()),''',
     '''            Ok(_) => None,''',
     [ROUTE]),
    ("LA32 the route takes a since that is no time", MSG,
     '''            Err(_) => {
                return Err(ApiError::BadRequest(format!("{since} is not a time")));
            }''',
     '''            Err(_) => None,''',
     [ROUTE]),
    ("LA33 the route takes an ID to mark that is not whole", MSG,
     '''        match whole_id(given) {''',
     '''        match whole_id(given).or(Some([0; 16])) {''',
     [ROUTE]),
    ("LA34 the route is not served", LIB,
     '''            .route("/send", web::post().to(messages::send))
            .route("/log", web::post().to(messages::log)),''',
     '''            .route("/send", web::post().to(messages::send)),''',
     [ROUTES]),
    ("LA35 what was held back is printed and marked", MSG,
     '''            .filter(|message| message.said.is_some())''',
     '''            .filter(|_| true)''',
     [HELD]),
    ("LA36 the route does not say what is held back", MSG,
     '''                            "held_back": m.said.is_none(),''',
     '''                            "held_back": false,''',
     [HELD]),

    # ── The command ──────────────────────────────────────────────────
    ("LC1 the first line says another thing", CMD,
     '''must not answer its question.";''',
     '''must not answer it.";''',
     [WORDS]),
    ("LC2 log does not begin with its line", CMD,
     r'''    written(&format!("{FOR_A_PERSON}\n"));''',
     '''''',
     [OUTSIDE]),
    ("LC3 outside a terminal its last line is not said", CMD,
     r'''        written(&format!("{NOT_MARKED}\n"));
        return Ok(());''',
     '''        return Ok(());''',
     [OUTSIDE]),
    ("LC4 a pipe for its output is taken for a terminal", CMD,
     '''    let at_a_terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();''',
     '''    let at_a_terminal = std::io::stdin().is_terminal() || std::io::stdout().is_terminal() || true;''',
     [OUTSIDE]),
    ("LC5 the question says another thing", CMD,
     '''         Type yes to mark them:"''',
     '''         Type yes:"''',
     [WORDS]),
    ("LC6 an answer but yes marks", CMD,
     '''    if typed.as_deref() != Some("yes") {''',
     '''    if typed.is_none() {''',
     [TEN]),
    ("LC7 after the yes nothing is sent to mark", CMD,
     '''    let request = json!({ "folder": null, "since": since, "mark": printed });''',
     '''    let request = json!({ "folder": null, "since": since, "mark": [] });''',
     [READ_MARKS]),
    ("LC8 with nothing printed it asks", CMD,
     '''    if printed.is_empty() {''',
     '''    if printed.is_empty() && false {''',
     [OUTSIDE]),
    ("LC9 a message held back is printed whole", CMD,
     '''            if message["held_back"] == true {''',
     '''            if message["held_back"] == false {''',
     [PRINTS]),
    ("LC10 what a person read is said the other way", CMD,
     r'''                true => out.push_str("Read by a person here.\n"),''',
     r'''                true => out.push_str("Not read by a person here.\n"),''',
     [PRINTS]),
    ("LC11 a signer that no longer counts is not said", CMD,
     '''            if message["signer_removed"] == true {''',
     '''            if message["signer_removed"] == false {''',
     [PRINTS]),
    ("LC12 before the last change is not said", CMD,
     '''            if message["before_the_last_change"] == true {''',
     '''            if message["before_the_last_change"] == false {''',
     [PRINTS]),
    ("LC13 the overwritten line says another thing", CMD,
     r'''were overwritten before they were shown on this device\n",''',
     r'''were overwritten before they were shown here\n",''',
     [WORDS, PRINTS]),
    ("LC14 a count of nothing is said", CMD,
     '''        if count("overwritten") > 0 {''',
     '''        if count("overwritten") >= 0 {''',
     [PRINTS]),
    ("LC15 what waits is not said", CMD,
     '''    for id in own("waiting") {''',
     '''    for id in own("nothing") {''',
     [PRINTS]),
    ("LC16 what a relay refused is not said", CMD,
     '''    for id in own("refused_for_room") {''',
     '''    for id in own("nothing") {''',
     [PRINTS]),
    ("LC17 what may not have reached every relay is not said", CMD,
     '''    for id in own("not_every_relay") {''',
     '''    for id in own("nothing") {''',
     [PRINTS]),
    ("LC18 what may not have reached every device is not said", CMD,
     '''    for id in own("not_every_device") {''',
     '''    for id in own("nothing") {''',
     [PRINTS]),
    ("LC19 what was printed is not what a yes marks", CMD,
     '''            printed.push(id);''',
     '''''',
     [PRINTS]),
    ("LC20 every frame has one value", CMD,
     '''            out.push_str(&framed(message, &marker()));''',
     '''            out.push_str(&framed(message, "0a0a0a0a0a0a"));''',
     [PRINTS]),
    ("LC21 a sender's name in log is neither cleaned nor cut", CMD,
     '''            let from = name_shown(message["from"].as_str().unwrap_or_default());''',
     '''            let from = message["from"].as_str().unwrap_or_default().to_string();''',
     [SET, CUT]),
    ("LC22 since is refused with another line", CMD,
     '''.map_err(|why| why.to_string())''',
     '''.map_err(|_| String::from("not a time"))''',
     [WORDS, CHECKS]),
    ("LC23 since is not checked by the command", CMD,
     '''    let since = since.map(|text| since_given(text).unwrap_or_else(|line| refuse(&line)));''',
     '''    let since = since.map(String::from);''',
     [OUTSIDE]),
    ("LC24 an answer that lists no thread is taken", CMD,
     '''        Posted::Answered(200, answer) if !answer["threads"].is_array() => Posted::NotKnown,''',
     '''        Posted::Answered(200, answer) if answer.is_null() => Posted::NotKnown,''',
     [NOT_KNOWN]),
    ("LC25 log refused says it sends no message", CMD,
     '''        refuse(&refused_by(status, &answer, &shown, Does::Show));
    }
    let (said, printed) = log_says(&answer, marker);''',
     '''        refuse(&refused_by(status, &answer, &shown, Does::Send));
    }
    let (said, printed) = log_says(&answer, marker);''',
     [REMOVED]),
    ("LC26 the line after a yes not answered says another thing", CMD,
     '''so it is not known whether the messages were marked.";''',
     '''so nothing was marked.";''',
     [WORDS]),
    ("LC27 what a yes says counts another thing", CMD,
     '''    match marked == printed as u64 {''',
     '''    match marked != printed as u64 {''',
     [PRINTS]),
    ("LC28 since is not given to log", MAIN,
     '''            MsgCommand::Log { since } => msg_cmd::log(&cli.config, since.as_deref()),''',
     '''            MsgCommand::Log { .. } => msg_cmd::log(&cli.config, None),''',
     [OUTSIDE]),
    ("LC29 the help says another thing", MAIN,
     '''    /// For a person at a terminal
    ///''',
     '''    /// For a person
    ///''',
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
