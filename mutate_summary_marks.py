#!/usr/bin/env python3
"""Mutation checks for `cordelia msg summary` marking a message announced
only once it printed its line: the node marks nothing when it answers, the
command tells the node the lines it printed within its 100 ms, and the node
marks those that are lines of the folder's agent (decision 2026-10-09
rule 14, §4.1 C5 and the table of the summary's 100 ms, §4.2, §7.2). A part
for each rule of the slice: put each fault in, and confirm the test named
for it fails on an assertion. Run from the root of a checkout that nothing
else edits."""
import re, subprocess, sys

# One name for each file a part edits.
MESSAGES = 'crates/cordelia-api/src/messages.rs'
MSG_CMD = 'crates/cordelia-node/src/msg_cmd.rs'
ORIG = {f: open(f).read() for f in (MESSAGES, MSG_CMD)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "msg_e2e"])
def api(test): return (API, "messages::tests::" + test)
def cmd(test): return (BIN, "msg_cmd::tests::" + test)
def e2e(test): return (E2E, test)

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("SM1 the node marks a line announced when it answers it", MESSAGES,
     '''            let (subject, subject_cut) = subject_of(&message.body);
            lines.push(Line {''',
     '''            kept(held::announce(conn, &id, &name))?;
            let (subject, subject_cut) = subject_of(&message.body);
            lines.push(Line {''',
     [api("a_summary_marks_nothing_until_it_is_told_what_was_printed"),
      e2e("the_summary_answers_within_its_time_or_prints_nothing")]),
    ("SM2 the node marks nothing it is told", MESSAGES,
     '''            kept(held::announce(conn, &id, &name))?;
            marked += 1;''',
     '''            marked += 1;''',
     [api("a_summary_marks_nothing_until_it_is_told_what_was_printed"),
      api("the_node_marks_announced_what_the_command_says_it_printed")]),
    ("SM3 the node marks a message to every name it is told", MESSAGES,
     '''            if message.to.is_none()
                || !ids.contains(&id)''',
     '''            if !ids.contains(&id)''',
     [api("only_a_line_of_the_folders_agent_is_marked_announced")]),
    ("SM4 the node marks a line it was not told", MESSAGES,
     '''            if message.to.is_none()
                || !ids.contains(&id)''',
     '''            if message.to.is_none()''',
     [api("only_a_line_of_the_folders_agent_is_marked_announced")]),
    ("SM5 the route takes more IDs than a summary has lines", MESSAGES,
     '''    if body.version != env!("CARGO_PKG_VERSION") || body.ids.len() > AGENT_MESSAGE_SUMMARY_LINES {''',
     '''    if body.version != env!("CARGO_PKG_VERSION") {''',
     [api("the_node_marks_announced_what_the_command_says_it_printed")]),
    ("SM6 the route takes a command of another version", MESSAGES,
     '''    if body.version != env!("CARGO_PKG_VERSION") || body.ids.len() > AGENT_MESSAGE_SUMMARY_LINES {''',
     '''    if body.ids.len() > AGENT_MESSAGE_SUMMARY_LINES {''',
     [api("the_node_marks_announced_what_the_command_says_it_printed")]),
    ("SM7 the command waits past its deadline and tells the node the lines of an answer that came late", MSG_CMD,
     ['''    let Posted::Answered(status, answer) = node.post("/api/v1/messages/summary", &request, left)''',
      '''    if status != 200 || Instant::now() >= deadline {
        return None;
    }
    let said = summary_for(&answer, given)?;'''],
     ['''    let Posted::Answered(status, answer) =
        node.post("/api/v1/messages/summary", &request, Duration::from_secs(2))''',
      '''    if status != 200 {
        return None;
    }
    if Instant::now() >= deadline {
        let told = json!({
            "folder": folder.display().to_string(),
            "ids": printed_ids(&answer),
            "version": env!("CARGO_PKG_VERSION"),
        });
        node.post("/api/v1/messages/announced", &told, Duration::from_millis(20));
        return None;
    }
    let said = summary_for(&answer, given)?;'''],
     [e2e("the_summary_answers_within_its_time_or_prints_nothing")]),
    ("SM8 the command tells the node lines it could not write", MSG_CMD,
     '''    if !written(&said) {
        return None;
    }''',
     '''    let _ = written(&said);''',
     [e2e("a_summary_that_could_not_print_its_line_marks_nothing")]),
    ("SM9 the command tells the node the IDs of the count line too", MSG_CMD,
     '''        .filter_map(|line| line["id"].as_str().map(String::from))
        .collect()''',
     '''        .filter_map(|line| line["id"].as_str().map(String::from))
        .chain(
            answer["waiting"]["ids"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|id| id.as_str().map(String::from)),
        )
        .collect()''',
     [cmd("the_node_is_told_the_lines_printed_and_not_the_count")]),
    ("SM10 the command never tells the node what it printed", MSG_CMD,
     '''        node.post("/api/v1/messages/announced", &told, left);''',
     '''        let _ = (&told, left);''',
     [e2e("the_summary_announces_a_message_once_and_then_counts_it"),
      e2e("a_message_from_one_device_is_announced_once_and_read_on_the_other")]),
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
