#!/usr/bin/env python3
"""Mutation checks for slice 3 of change F: the relay's own fetch reads
each answer by its length, a long one only under a large permit, and
fails where none comes (decision 2026-10-22, memory across connections,
rule 6 and rule 7 for the fetch, with section 9's slice 3). A part for
each rule of the slice: put each fault in, and confirm the test named
for it fails on an assertion. Run from the root of a checkout that
nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
P2P = 'crates/cordelia-node/src/p2p.rs'
ORIG = {f: open(f).read() for f in (P2P,)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
NODE = ("cordelia-node", ["--bin", "cordelia"])
def p2p(test): return (NODE, "p2p::tests::" + test)

SMALL_AT_ONCE = p2p("a_fetch_reads_an_answer_within_a_small_message_with_every_permit_held")
WAITS_AND_FAILS = p2p("a_long_answer_waits_unread_for_a_permit_and_the_fetch_fails_without_one")
PAGE_FAILS = p2p("a_long_page_waits_unread_for_a_permit_and_the_fetch_fails_without_one")
FETCH_FAILS = p2p("a_long_fetch_answer_waits_unread_for_a_permit_and_the_fetch_fails_without_one")
PAGE_LET_GO = p2p("a_pages_permit_is_let_go_before_its_entries_are_fetched")
LONG_LIST = p2p("a_long_channel_list_is_read_under_a_permit_and_the_channels_asked_of_a_peer_are_kept_a_different_part_each_time")
ONE_REQUEST = p2p("a_page_of_100_headers_is_fetched_in_one_request")
LISTED = p2p("a_relay_listed_by_key_has_its_long_list_read_with_every_permit_held")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("OF1 an answer read by its length: every frame waits for a permit, however short", P2P,
     '''    let permit = if len > cordelia_core::protocol::SMALL_MESSAGE_BYTES && !listed {''',
     '''    let permit = if !listed {''',
     [SMALL_AT_ONCE]),
    ("OF2a the permit for a large one, at the list: read whole, with no permit", P2P,
     '''let (listed, permit) = match ask(send, recv, request, permits, address, listed_by_key).await''',
     '''let (listed, permit) = match ask(send, recv, request, None, address, listed_by_key).await''',
     [WAITS_AND_FAILS]),
    ("OF2b the permit for a large one, at a page: read whole, with no permit", P2P,
     '''let (resp, permit) = match ask(send, recv, request, permits, address, listed_by_key)''',
     '''let (resp, permit) = match ask(send, recv, request, None, address, listed_by_key)''',
     [PAGE_FAILS]),
    ("OF2c the permit for a large one, at a fetch's answer: read whole, with no permit", P2P,
     '''                    request,
                    permits,
                    address,
                    listed_by_key,
                )''',
     '''                    request,
                    None,
                    address,
                    listed_by_key,
                )''',
     [FETCH_FAILS]),
    ("OF3a the fetch failed and asked again without one, at the list: it ends as if there were more, and is asked again at once", P2P,
     '''                tracing::debug!(peer = %target, "a channel list over a small message, and no permit for now; the fetch fails");
                refuse_large_later(send, recv);
                return (Fetched::Failed, 0);''',
     '''                tracing::debug!(peer = %target, "a channel list over a small message, and no permit for now; the fetch fails");
                refuse_large_later(send, recv);
                return (Fetched::More, 0);''',
     [WAITS_AND_FAILS]),
    ("OF3b the fetch failed and asked again without one, at a page: it ends as if there were more", P2P,
     '''"a page over a small message, and no permit for now; the fetch fails");
                    refuse_large_later(send, recv);
                    fetched = Fetched::Failed;''',
     '''"a page over a small message, and no permit for now; the fetch fails");
                    refuse_large_later(send, recv);
                    fetched = Fetched::More;''',
     [PAGE_FAILS]),
    ("OF3c the fetch failed and asked again without one, at a fetch's answer: it ends as if there were more", P2P,
     '''"a fetch answer over a small message, and no permit for now; the fetch fails");
                        refuse_large_later(send, recv);
                        fetched = Fetched::Failed;''',
     '''"a fetch answer over a small message, and no permit for now; the fetch fails");
                        refuse_large_later(send, recv);
                        fetched = Fetched::More;''',
     [FETCH_FAILS]),
    ("OF7 the page's permit let go before its fetch: held through the fetch and its answer", P2P,
     '''            drop(resp);
            drop(permit);''',
     '''            drop(resp);
            let _page_permit = permit;''',
     [PAGE_LET_GO]),
    ("OF8a the refusal with ERR_LARGE_MESSAGE_LATER, at the list: the stream is left as it is", P2P,
     '''"a channel list over a small message, and no permit for now; the fetch fails");
                refuse_large_later(send, recv);''',
     '''"a channel list over a small message, and no permit for now; the fetch fails");''',
     [WAITS_AND_FAILS]),
    ("OF8b the refusal with ERR_LARGE_MESSAGE_LATER, at a page: the stream is left as it is", P2P,
     '''"a page over a small message, and no permit for now; the fetch fails");
                    refuse_large_later(send, recv);''',
     '''"a page over a small message, and no permit for now; the fetch fails");''',
     [PAGE_FAILS]),
    ("OF8c the refusal with ERR_LARGE_MESSAGE_LATER, at a fetch's answer: the stream is left as it is", P2P,
     '''"a fetch answer over a small message, and no permit for now; the fetch fails");
                        refuse_large_later(send, recv);''',
     '''"a fetch answer over a small message, and no permit for now; the fetch fails");''',
     [FETCH_FAILS]),
    ("OF4 the first MAX_CHANNELS_ASKED_OF_A_PEER kept of a long list: every channel listed is kept", P2P,
     '''channels_to_ask(channels, listed, most)''',
     '''channels_to_ask(channels, listed, usize::MAX)''',
     [LONG_LIST]),
    ("OF5 a page of 100 headers fetched in one request: one entry a request", P2P,
     '''item_ids: fetch_ids.clone(),''',
     '''item_ids: fetch_ids[..1].to_vec(),''',
     [ONE_REQUEST]),
    ("OF6 a relay listed by key has its answers read whole (rule 7): it waits for a permit as any peer", P2P,
     '''        listed_by_key,
    } = from;''',
     '''        listed_by_key: _,
    } = from;
    let listed_by_key = false;''',
     [LISTED]),
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
