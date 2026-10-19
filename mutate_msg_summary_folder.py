#!/usr/bin/env python3
"""Mutation checks for `--folder <dir>` of `cordelia msg summary`, `msg read`
and `msg send`, the folder they act for where a session runs in another
folder, and the lines the summary and `read` print with it (decision
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
THERE = e2e("a_message_the_summary_shows_by_its_folder_is_read_and_answered_there")
LINES = unit("the_lines_to_read_and_to_answer_carry_the_folder_given")
NOT_A_FOLDER = unit("a_word_after_the_summarys_folder_that_is_a_flag_or_not_text_is_no_folder")

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
     '''home.join(&given[2..]),''',
     '''PathBuf::from(given),''',
     [TILDE, SHOWN]),
    ("SF6 the summary does not expand the folder it was given", MSG,
     '''    let folder = given.map(|given| folder_given(given, home()));
    let dir = directory(folder, project_dir, || {''',
     '''    let folder = given.map(PathBuf::from);
    let dir = directory(folder, project_dir, || {''',
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
     '''(folders == 1 && folder.as_deref().is_none_or(str::is_empty))''',
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
    ("SF15 read does not take its --folder", MSG,
     '''folder_here(given, node.git_wait())''',
     '''folder_here(None, node.git_wait())''',
     [THERE]),
    ("SF16 send does not take its --folder", MSG,
     '''folder_here(flags.folder.as_deref(), node.git_wait())''',
     '''folder_here(None, node.git_wait())''',
     [THERE]),
    ("SF17 Claude Code's variable comes before the --folder of read and send", MSG,
     '''    let dir = directory(folder, std::env::var_os(PROJECT_DIR), || None)''',
     '''    let dir = directory(folder.filter(|_| std::env::var_os(PROJECT_DIR).is_none()), std::env::var_os(PROJECT_DIR), || None)''',
     [THERE]),
    ("SF18 read and send do not take a leading ~ of --folder as home", MSG,
     '''    let folder = given.map(|given| folder_given(given, home()));
    let dir = directory(folder, std::env::var_os(PROJECT_DIR), || None)''',
     '''    let folder = given.map(PathBuf::from);
    let dir = directory(folder, std::env::var_os(PROJECT_DIR), || None)''',
     [THERE]),
    ("SF19 a --folder of read and send that is no folder is passed over", MSG,
     '''    let dir = directory(folder, std::env::var_os(PROJECT_DIR), || None)''',
     '''    let dir = directory(folder.filter(|dir| dir.is_dir()), std::env::var_os(PROJECT_DIR), || None)''',
     [THERE]),
    ("SF20 the summary's line to read one does not carry the folder", MSG,
     '''        Some(folder) => format!("cordelia msg read {} <id>", folder_arg(folder)),''',
     '''        Some(_) => "cordelia msg read <id>".into(),''',
     [LINES, THERE]),
    ("SF21 the summary does not hand its folder to its header", MSG,
     '''    summary_for(&answer, given)''',
     '''    summary_for(&answer, None)''',
     [THERE]),
    ("SF22 read's line to answer does not carry the folder", MSG,
     '''                        "cordelia msg send",''',
     '''                        "cordelia msg send --nothing",''',
     [LINES, THERE]),
    ("SF23 read does not hand its folder to its line to answer", MSG,
     '''readout_for(&answer, &marker(), given)''',
     '''readout_for(&answer, &marker(), None)''',
     [THERE]),
    ("SF24 a folder that begins with - is printed where it reads as a flag", MSG,
     '''        true => format!("--folder={}", shell_quoted(folder)),''',
     '''        true => format!("--folder {}", shell_quoted(folder)),''',
     [LINES]),
    ("SF25 main does not hand read its folder", MAIN,
     '''msg_cmd::read(&cli.config, &id, folder.as_deref())''',
     '''msg_cmd::read(&cli.config, &id, folder.as_deref().filter(|_| false))''',
     [THERE]),
    ("SF26 main does not hand send its folder", MAIN,
     '''                    re,
                    folder,
                },''',
     '''                    re,
                    folder: folder.filter(|_| false),
                },''',
     [THERE]),
    ("SF27 the help does not say where a --folder hook goes", MAIN,
     '''        /// Put that hook in the settings of the project your session runs''',
     '''        /// Put that hook where you like, in the settings of a project your session runs''',
     [HELP]),
    ("SF28 the help of read and send does not give their --folder", MAIN,
     '''        /// Read as the agent of this folder, not of the one you run in:''',
     '''        /// The agent of this folder, not of the one you run in:''',
     [HELP]),
    ("SF29 a flag after --folder is taken as the folder", MSG,
     '''                    .filter(|next| !next.starts_with('-'))''',
     '''                    .filter(|_| true)''',
     [NOT_A_FOLDER]),
    ("SF30 --folder <dir> takes a folder that is not UTF-8", MSG,
     '''                    .and_then(|next| next.to_str())''',
     '''                    .map(|next| next.to_string_lossy().into_owned())''',
     [NOT_A_FOLDER]),
    ("SF31 --folder=<dir> takes a folder that is not UTF-8", MSG,
     '''            word => words.push(word),''',
     '''            None if after_summary && arg.as_encoded_bytes().starts_with(b"--folder=") => {
                folders += 1;
                folder = Some(arg.to_string_lossy()["--folder=".len()..].to_string());
            }
            word => words.push(word),''',
     [NOT_A_FOLDER]),
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
