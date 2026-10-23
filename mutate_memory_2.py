#!/usr/bin/env python3
"""Mutation checks for slice 2 of change F: small pages for a peer that
is not a relay listed by key, and the reads that follow them (decision
2026-10-22, memory across connections, rule 3 and rule 7 for pages, with
section 9's slice 2). A part for each rule of the slice: put each fault
in, and confirm the test named for it fails on an assertion. Run from
the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PULL = 'crates/cordelia-storage/src/relay.rs'
SERVE = 'crates/cordelia-node/src/relay_entries.rs'
LEAVE = 'crates/cordelia-node/src/device_entries/leave.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
ORIG = {f: open(f).read() for f in (PULL, SERVE, LEAVE, P2P)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
STORAGE = ("cordelia-storage", ["--lib"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
DEVICE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def storage(test): return (STORAGE, "relay::tests::" + test)
def serve(test): return (NODE, "relay_entries::tests::" + test)
def p2p(test): return (NODE, "p2p::tests::" + test)
def device(test): return (DEVICE_E2E, test)

UNLISTED_PAGE = serve("a_page_for_an_unlisted_peer_holds_at_most_a_small_page_and_says_there_is_more")
LISTED_PAGE = serve("a_page_for_a_relay_listed_by_key_is_not_cut_to_a_small_page")
PULL_BYTES = storage("a_page_holds_at_most_its_bytes_and_at_least_one_entry_and_says_there_is_more")
PAIR_READ = device("the_pair_read_at_accept_finds_a_hand_over_behind_an_entry_of_the_largest_size")
PASS_READ = device("a_pass_reads_a_channel_of_the_largest_entries_in_small_pages_to_its_end")
FETCH = p2p("an_older_kind_fetch_answer_over_a_small_page_waits_for_a_large_permit")
PAIR_STOP = device("the_pair_read_at_accept_stops_at_a_page_that_does_not_move_the_place")
PAIR_FAILS = device("the_pair_read_at_accept_ends_where_a_later_page_fails")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("SP1 the bound on a page: an unlisted peer is given full pages", SERVE,
     '''            false => SMALL_PAGE_BYTES,''',
     '''            false => ENTRY_PAGE_MAX_BYTES,''',
     [UNLISTED_PAGE, PASS_READ]),
    ("SP2 the bound on a page: the store ignores the bytes it is given", PULL,
     '''            if !page.entries.is_empty() && bytes + travels > most_bytes {''',
     '''            if !page.entries.is_empty() && bytes + travels > ENTRY_PAGE_MAX_BYTES {''',
     [PULL_BYTES]),
    ("SP3 its at least one entry: a page may hold none", PULL,
     '''            if !page.entries.is_empty() && bytes + travels > most_bytes {''',
     '''            if bytes + travels > most_bytes {''',
     [PULL_BYTES]),
    ("SP4 the more it says: a page that stops at its bytes says the place of the entry it left out", PULL,
     '''            if !page.entries.is_empty() && bytes + travels > most_bytes {
                return Ok(page);''',
     '''            if !page.entries.is_empty() && bytes + travels > most_bytes {
                page.next = held.channel_place.max(0) as u64;
                return Ok(page);''',
     [PULL_BYTES, UNLISTED_PAGE]),
    ("SP5 the pair read's loop: accept reads one page", LEAVE,
     '''            if page.entries.is_empty() || reached == place || !reads(&lock(db), unix()) {''',
     '''            if true || page.entries.is_empty() || reached == place || !reads(&lock(db), unix()) {''',
     [PAIR_READ]),
    ("SP6 the fetch answer's permit: an older-kind answer over a small page is written without one", P2P,
     '''                if !small
                    && !listed''',
     '''                if false
                    && !small
                    && !listed''',
     [FETCH]),
    ("SP7 a listed relay waits for a permit for a fetch answer over a small page", P2P,
     '''                if !small
                    && !listed''',
     '''                if !small
                    && true''',
     [FETCH]),
    ("SP8 a listed relay is cut to a small page on the stream of entries", SERVE,
     '''            true => ENTRY_PAGE_MAX_BYTES,''',
     '''            true => SMALL_PAGE_BYTES,''',
     [LISTED_PAGE]),
    ("SP9 a listed relay is cut to a small page between relays", SERVE,
     '''                    pull.limit,
                    ENTRY_PAGE_MAX_BYTES,''',
     '''                    pull.limit,
                    SMALL_PAGE_BYTES,''',
     [LISTED_PAGE]),
    ("SP10 the fetch answer with no permit in time is not refused with ERR_LARGE_MESSAGE_LATER", P2P,
     '''                            tracing::debug!(peer = %peer_id, channel = %channel, bytes, "a fetch answer over a small page, and no permit for now; refused");
                            refuse_large_later(send, recv);''',
     '''                            tracing::debug!(peer = %peer_id, channel = %channel, bytes, "a fetch answer over a small page, and no permit for now; refused");''',
     [FETCH]),
    ("SP11 one permit a stream: the fetch answer asks for a second beside its frame's", P2P,
     '''                    && permit.is_none()
                    && let Some(permits) = permits''',
     '''                    && let Some(permits) = permits''',
     [FETCH]),
    ("SP12 the fetch answer's items are loaded before the permit comes", P2P,
     '''                let small = bytes <= cordelia_core::protocol::SMALL_PAGE_BYTES as u64;''',
     '''                let small = bytes <= cordelia_core::protocol::SMALL_PAGE_BYTES as u64;
                let _loaded = state.db.lock().ok().map(|db| cordelia_storage::items::get_items_by_ids(&db, &channel, &freq.item_ids));''',
     [FETCH]),
    ("SP13 the pair read does not stop at a page that leaves the place where it was", LEAVE,
     '''page.entries.is_empty() || reached == place ||''',
     '''page.entries.is_empty() ||''',
     [PAIR_STOP]),
    ("SP14 a later page's failure, with nothing judged, is not said", LEAVE,
     '''                Err(refused) if read.is_empty() => return Err(refused),''',
     '''                Err(refused) if false => return Err(refused),''',
     [PAIR_FAILS]),
    ("SP15 a later page's failure undoes what was judged before it", LEAVE,
     '''                _ => break,
            };
            // Each entry is checked''',
     '''                _ => return Err(not("a later page failed")),
            };
            // Each entry is checked''',
     [PAIR_FAILS]),
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
