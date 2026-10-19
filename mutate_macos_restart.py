#!/usr/bin/env python3
"""Mutation checks for the restart of a node on macOS: the install script
restarts a running node by launchctl bootout of the agent, then launchctl
bootstrap of the plist it has just written (tried again within a bound,
failed for good after it), and the node's own sentences name the same two
commands (operations.md §7.1, §10.2). A part for each rule of the slice:
put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
INSTALL = 'scripts/install.sh'
COMMANDS = 'crates/cordelia-api/src/commands.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
ORIG = {f: open(f).read() for f in (INSTALL, COMMANDS, MAIN)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
# A crate of "sh" is the install script's tests: the test is a case's name.
API = ("cordelia-api", ["--lib"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
SH = ("sh", [])
def api(test): return (API, "commands::tests::" + test)
def node(test): return (NODE, "tests::" + test)
def case(name): return (SH, name)

SCRIPT_PRINTS = api("test_the_restart_command_is_the_one_the_install_script_prints")
MACOS_SENTENCES = node("test_a_restart_on_macos_is_a_bootout_then_a_bootstrap")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("MR1 the agent is kickstarted again, not booted out and bootstrapped", INSTALL,
     '''        darwin) restart_agent ;;''',
     '''        darwin) launchctl kickstart -k "$AGENT_TARGET" ;;''',
     [case("a-running-node-on-a-mac")]),
    ("MR2 no bootout before the bootstrap", INSTALL,
     '''    launchctl bootout "$AGENT_TARGET" 2>/dev/null || :\n''',
     '''''',
     [case("a-running-node-on-a-mac")]),
    ("MR3 the bootout comes after the bootstrap", INSTALL,
     ['''    launchctl bootout "$AGENT_TARGET" 2>/dev/null || :\n''',
      '''    done\n}\n\n# Wait, for so many tries a second apart, until the node answers.'''],
     ['''''',
      '''    done\n    launchctl bootout "$AGENT_TARGET" 2>/dev/null || :\n}\n\n# Wait, for so many tries a second apart, until the node answers.'''],
     [case("a-running-node-on-a-mac")]),
    ("MR4 a bootout of a job already gone ends the restart", INSTALL,
     '''    launchctl bootout "$AGENT_TARGET" 2>/dev/null || :''',
     '''    launchctl bootout "$AGENT_TARGET" 2>/dev/null || return 1''',
     [case("a-mac-agent-that-is-gone-already")]),
    ("MR5 what a bootout of a job already gone said is printed", INSTALL,
     '''    launchctl bootout "$AGENT_TARGET" 2>/dev/null || :''',
     '''    launchctl bootout "$AGENT_TARGET" || :''',
     [case("a-mac-agent-that-is-gone-already")]),
    ("MR6 a bootstrap that fails is not tried again", INSTALL,
     '''        if [ "$waited" -ge "$BOOTSTRAP_WAIT_SECS" ]; then''',
     '''        if :; then''',
     [case("a-mac-agent-that-is-still-going-once")]),
    ("MR7 the bound is a second longer than 30 seconds", INSTALL,
     '''BOOTSTRAP_WAIT_SECS=$(seconds_or "${CORDELIA_BOOTSTRAP_WAIT_SECS:-}" 30)''',
     '''BOOTSTRAP_WAIT_SECS=$(seconds_or "${CORDELIA_BOOTSTRAP_WAIT_SECS:-}" 31)''',
     [case("a-mac-agent-that-does-not-bootstrap")]),
    ("MR8 the wait given is not heeded", INSTALL,
     '''BOOTSTRAP_WAIT_SECS=$(seconds_or "${CORDELIA_BOOTSTRAP_WAIT_SECS:-}" 30)''',
     '''BOOTSTRAP_WAIT_SECS=$(seconds_or "" 30)''',
     [case("a-mac-agent-that-does-not-bootstrap-in-a-wait-given")]),
    ("MR9 no wait between the tries of a bootstrap", INSTALL,
     '''        sleep 1\n        waited=$((waited + 1))\n    done\n}\n\n# Wait, for so many tries a second apart, until the node answers.''',
     '''        waited=$((waited + 1))\n    done\n}\n\n# Wait, for so many tries a second apart, until the node answers.''',
     [case("a-mac-agent-that-does-not-bootstrap"), case("a-mac-agent-that-is-still-going-once")]),
    ("MR10 a bootstrap that fails for good is taken as done", INSTALL,
     '''            sed 's/^/  /' "${TMPDIR}/bootstrap.err" 2>/dev/null || true\n            return 1''',
     '''            sed 's/^/  /' "${TMPDIR}/bootstrap.err" 2>/dev/null || true\n            return 0''',
     [case("a-mac-agent-that-does-not-bootstrap")]),
    ("MR11 what launchctl said of a bootstrap that failed for good is not printed", INSTALL,
     '''            sed 's/^/  /' "${TMPDIR}/bootstrap.err" 2>/dev/null || true\n''',
     '''''',
     [case("a-mac-agent-that-does-not-bootstrap")]),
    ("MR12 the bootstrap is of the job's label, not the domain", INSTALL,
     '''    until launchctl bootstrap "$AGENT_DOMAIN" "$PLIST_FILE"''',
     '''    until launchctl bootstrap "$AGENT_TARGET" "$PLIST_FILE"''',
     [case("a-running-node-on-a-mac")]),
    ("MR13 the bootstrap is of a plist other than the one just written", INSTALL,
     '''        darwin) restart_agent ;;''',
     '''        darwin) PLIST_FILE="${PLIST_FILE}.old"; restart_agent ;;''',
     [case("a-running-node-on-a-mac")]),
    ("MR14 the restart printed runs its second command only where the first found the job", INSTALL,
     '''    RESTART_CMD="launchctl bootout ${AGENT_TARGET}; launchctl bootstrap ${AGENT_DOMAIN} ${PLIST_FILE}"''',
     '''    RESTART_CMD="launchctl bootout ${AGENT_TARGET} && launchctl bootstrap ${AGENT_DOMAIN} ${PLIST_FILE}"''',
     [case("a-mac-agent-that-does-not-bootstrap"), case("a-mac-node-left-as-it-is-when-asked"),
      case("a-mac-node-that-does-not-answer"), SCRIPT_PRINTS]),
    ("MR15 the restart printed is the kickstart", INSTALL,
     '''    RESTART_CMD="launchctl bootout ${AGENT_TARGET}; launchctl bootstrap ${AGENT_DOMAIN} ${PLIST_FILE}"''',
     '''    RESTART_CMD="launchctl kickstart -k ${AGENT_TARGET}"''',
     [case("a-mac-agent-that-does-not-bootstrap"), SCRIPT_PRINTS]),
    ("MR16 a first install on a Mac restarts the agent", INSTALL,
     '''    echo "  Stop:   launchctl unload ${PLIST_FILE}"''',
     '''    echo "  Stop:   launchctl unload ${PLIST_FILE}"; restart_agent >/dev/null 2>&1 || :''',
     [case("a-first-install-on-a-mac")]),
    ("MR17 the start on a Mac is a bootstrap", INSTALL,
     '''    START_CMD="launchctl load ${PLIST_FILE}"''',
     '''    START_CMD="launchctl bootstrap ${AGENT_DOMAIN} ${PLIST_FILE}"''',
     [case("a-first-install-on-a-mac")]),
    ("MR18 the stop on a Mac is a bootout", INSTALL,
     '''    echo "  Stop:   launchctl unload ${PLIST_FILE}"''',
     '''    echo "  Stop:   launchctl bootout ${AGENT_TARGET}"''',
     [case("a-first-install-on-a-mac")]),
    ("MN1 the node names the kickstart on macOS", COMMANDS,
     '''            "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia; launchctl bootstrap \\
             gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist"
        }''',
     '''            "launchctl kickstart -k gui/$(id -u)/ai.seeddrill.cordelia"
        }''',
     [SCRIPT_PRINTS, MACOS_SENTENCES, api("test_a_node_under_the_old_key_names_the_command_that_restarts_it"),
      node("test_the_restart_command_is_the_systems_own"),
      node("test_a_port_that_is_taken_is_said_to_be_a_node_that_runs_already"),
      (NODE, "person_cmd::tests::a_new_key_ends_with_the_command_that_restarts_the_node"),
      (NODE, "person_cmd::tests::a_refusal_of_what_answered_names_the_command_that_restarts_the_node")]),
    ("MN2 the node's second command runs only where the first found the job", COMMANDS,
     '''        "macos" => {\n            "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia; launchctl bootstrap \\''',
     '''        "macos" => {\n            "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia && launchctl bootstrap \\''',
     [SCRIPT_PRINTS, MACOS_SENTENCES]),
    ("MN3 the node's two commands are on two lines", COMMANDS,
     '''        "macos" => {\n            "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia; launchctl bootstrap \\''',
     '''        "macos" => {\n            "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia;\\nlaunchctl bootstrap \\''',
     [SCRIPT_PRINTS, MACOS_SENTENCES]),
    ("MN4 the node bootstraps before it boots out", COMMANDS,
     '''            "launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia; launchctl bootstrap \\
             gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist"
        }''',
     '''            "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist; \\
             launchctl bootout gui/$(id -u)/ai.seeddrill.cordelia"
        }''',
     [SCRIPT_PRINTS, MACOS_SENTENCES]),
    ("MN5 the version check names the restart of the system it runs on, not the one named", MAIN,
     '''        restart_command(os)
    );
    match node {''',
     '''        restart_command(std::env::consts::OS)
    );
    match node {''',
     [MACOS_SENTENCES]),
    ("MN6 --seen names the restart of the system it runs on, not the one named", MAIN,
     '''         restart it with `{}`; otherwise stop it and start it again.",
        restart_command(os)
    )
}''',
     '''         restart it with `{}`; otherwise stop it and start it again.",
        restart_command(std::env::consts::OS)
    )
}''',
     [MACOS_SENTENCES]),
    ("MN7 the start on macOS is a bootstrap", COMMANDS,
     '''        "macos" => "launchctl load ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist",''',
     '''        "macos" => "launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.seeddrill.cordelia.plist",''',
     [api("test_the_sentence_that_starts_a_node_names_the_service_of_each_system")]),
]
# Rules of the slice that no test can tell, each with why. Leave it
# empty unless the record itself says the rule cannot be tested.
UNTOLD = []

def edits(a, b):
    return list(zip(a, b)) if isinstance(a, list) else [(a, b)]

TEST_MAX_SECS = 1500
BASELINE_TRIES = 3

def run_sh(name):
    """The install script's tests, read for the case named: a verdict in
    the words cargo test uses, so that verdict_of reads it."""
    import os, signal
    p = subprocess.Popen(["sh", "scripts/test-install.sh"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         start_new_session=True)
    try:
        out, _ = p.communicate(timeout=TEST_MAX_SECS)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return (out or "") + "\ntest result: FAILED. 0 passed; 1 failed; THE TEST DID NOT END\n"
    failed = [l for l in out.splitlines() if l.startswith(f"FAILED: {name}:")]
    if failed:
        return out + "\n" + "\n".join("panicked at " + l for l in failed) + \
            "\ntest result: FAILED. 0 passed; 1 failed\n"
    if p.returncode == 0 and re.search(r"install\.sh: \d+ cases pass", out):
        return out + "\ntest result: ok. 1 passed; 0 failed\n"
    return out + "\nthe case did not fail, and the script did not end with every case passing\n"

def run(where, test):
    import os, signal
    crate, args = where
    if crate == "sh":
        return run_sh(test)
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
