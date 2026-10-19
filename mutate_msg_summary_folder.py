#!/usr/bin/env python3
"""Mutation checks for `cordelia msg summary --folder <dir>`, the folder a
summary acts for where a session runs in another folder (decision
2026-10-09 §3.1, §4.1, §5). A part for each rule of the slice: put each
fault in, and confirm the test named for it fails on an assertion. Run
from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
MSG = 'crates/cordelia-node/src/msg_cmd.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
ORIG = {f: open(f).read() for f in (MSG, MAIN)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "msg_e2e"])
def unit(test): return (BIN, "msg_cmd::tests::" + test)
def main_test(test): return (BIN, "tests::" + test)
def e2e(test): return (E2E, test)

ORDER = unit("the_summarys_folder_comes_before_claude_codes_variable_and_the_hooks")
ASKED = unit("the_summarys_folder_is_taken_from_its_command_line")
TILDE = unit("the_summarys_folder_takes_a_leading_tilde_as_home")
HELP = main_test("the_summarys_help_says_when_to_give_its_folder")
SHOWN = e2e("the_summarys_folder_comes_before_the_session_and_the_hooks")
SILENT = e2e("the_summary_of_a_folder_given_that_does_not_sync_prints_nothing")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("SF1 Claude Code's variable comes before --folder", MSG,
     '''    if folder.is_some() {
        return folder;''',
     '''    if folder.is_some() && project_dir.is_none() {
        return folder;''',
     [ORDER, SHOWN]),
    ("SF2 the hook's cwd comes before --folder", MSG,
     '''        return folder;''',
     '''        return hook_cwd().or(folder);''',
     [ORDER, SHOWN]),
    ("SF3 a --folder that is no directory is passed over", MSG,
     '''    if folder.is_some() {''',
     '''    if folder.as_ref().is_some_and(|dir| dir.is_dir()) {''',
     [ORDER, SILENT]),
    ("SF4 the hook's input is read where --folder is given", MSG,
     '''        return folder;''',
     '''        let _ = hook_cwd();
        return folder;''',
     [ORDER]),
    ("SF5 a leading ~/ is not the home directory", MSG,
     '''home.join(&text[2..]),''',
     '''PathBuf::from(text),''',
     [TILDE, SHOWN]),
    ("SF6 the summary does not expand the folder it was given", MSG,
     '''    let folder = folder.map(|given| folder_given(given, home));''',
     '''    let _ = home;
    let folder = folder.map(PathBuf::from);''',
     [SHOWN]),
    ("SF7 --folder <dir> is not taken", MSG,
     '''            Some("--folder") if after_summary => {''',
     '''            Some("--no-folder") if after_summary => {''',
     [ASKED, SHOWN]),
    ("SF8 --folder=<dir> is not taken", MSG,
     '''text.starts_with("--folder=")''',
     '''text.starts_with("--no-folder=")''',
     [ASKED, SHOWN]),
    ("SF9 main does not hand the folder to the summary", MAIN,
     '''msg_cmd::summary(&asked.config, started, asked.folder, asked.others);''',
     '''msg_cmd::summary(&asked.config, started, None, asked.others);''',
     [SHOWN]),
    ("SF10 a --folder with no folder, or an empty one, is taken", MSG,
     '''(folders == 1 && folder.as_ref().is_none_or(|f| f.is_empty()))''',
     '''(folders == 1 && false)''',
     [ASKED]),
    ("SF11 a --folder given twice is taken", MSG,
     '''folders > 1 ||''',
     '''false ||''',
     [ASKED]),
    ("SF12 a --folder before msg summary is the summary's", MSG,
     '''let after_summary = words.len() >= 2;''',
     '''let after_summary = true;''',
     [ASKED]),
    ("SF13 the help does not say when to give --folder", MAIN,
     '''        /// Use it when your session runs in one folder and the agent's''',
     '''        /// Give it when the agent's''',
     [HELP]),
    ("SF14 the help does not show the hook's line with --folder", MAIN,
     '''        /// "command": "cordelia msg summary --folder ~/notes"''',
     '''        /// "command": "cordelia msg summary"''',
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
