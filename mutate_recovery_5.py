#!/usr/bin/env python3
"""Mutation checks for slice 5 of the recovery and carrying record: a
recovery reads the personal channel of the change it recovers from on,
from the place each relay reached, round after round, until each relay
has handed it to its end or holds none of it, or has been asked in
RECOVERY_READ_ON_READS rounds, its own count; a relay not reached in a
round is not asked again, and one whose connection changed is asked in
the next, after it is read again within the first round, as the read of
today does; a relay that handed nothing and holds none said to hold none,
and one that handed nothing said so, with why; the lines after each
round, and the line before the yes with why each relay stopped; and the line of step 1 before the yes (decision
2026-10-17 §3.1 to §3.3; §1, properties 10 and 11). With it: the bytes a
relay handed, as the node says them; a device that keeps back the room a
relay keeps for a show, and waits out a pull refused for now, on slice
6's count of refusals: asking a relay at its count nothing, the door
holding its pull to the count after its proof, and asking again only
within a minute of the last page; and reads
that keep each entry once. A part for each rule of the slice: put each
fault in, and confirm the test named for it fails on an assertion. Run
from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
CARRYING = 'crates/cordelia-api/src/carrying.rs'
CARRY_CMD = 'crates/cordelia-node/src/carry_cmd.rs'
RECOVER_CMD = 'crates/cordelia-node/src/recover_cmd.rs'
ENTRIES = 'crates/cordelia-node/src/device_entries.rs'
LEAVE = 'crates/cordelia-node/src/device_entries/leave.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, CARRYING, CARRY_CMD, RECOVER_CMD, ENTRIES, LEAVE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
API = ("cordelia-api", ["--lib"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
NODE_E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
RECOVER_E2E = ("cordelia-node", ["--test", "recover_e2e"])
def core(test): return (CORE, "protocol::tests::" + test)
def api(test): return (API, "carrying::tests::" + test)
def cmd(test): return (NODE, "recover_cmd::tests::" + test)
def carry(test): return (NODE, "carry_cmd::tests::" + test)

BOUND = core("test_a_recovery_reads_on_for_what_a_channel_at_its_cap_takes_decision_2026_10_17_3")
BYTES = api("test_what_is_said_of_a_relay_says_how_many_entries_it_handed")
ONCE = api("test_a_read_with_proofs_hands_each_entry_once")
AGAIN = carry("test_proofs_are_made_again_where_a_connection_changed")
NAMES_ONLY = carry("test_a_read_on_asks_only_the_relays_it_names")
PLACE_SAID = carry("test_what_is_said_of_a_relay_carries_the_place_it_reached")
TO_ITS_END = cmd("test_a_recovery_reads_its_personal_channel_on_until_its_end")
AT_THE_BOUND = cmd("test_a_recovery_stops_reading_on_at_the_bound")
LEAVES = cmd("test_a_page_that_leaves_the_place_ends_the_reading_as_read_to_its_end")
NOT_REACHED = cmd("test_a_relay_not_reached_in_a_round_is_not_asked_again")
PHRASE = cmd("test_a_phrase_channel_not_read_to_its_end_is_said_again_before_the_yes")
IN_PART = cmd("test_a_recovery_goes_on_with_what_it_could_read_of_the_personal_channel")
SHOW_ROOM = (NODE_E2E, "a_device_takes_from_a_relay_no_page_from_the_room_kept_for_a_show")
NOT_NOW = (NODE_E2E, "a_read_of_a_left_channel_waits_out_a_pull_refused_for_now")
NODE_LIB = ("cordelia-node", ["--lib"])
CUT_OFF = (NODE_LIB, "device_entries::leave::tests::a_request_is_refused_for_now_only_by_the_rate_limits_code")
CHANGING = cmd("test_a_relay_whose_connection_keeps_changing_costs_no_reading_beyond_the_bound")
ONE_READING = carry("test_one_reading_reads_no_relay_again_and_asks_for_the_sessions_where_one_changed")
WHY = cmd("test_what_is_said_of_a_read_in_part_says_why_each_relay_stopped")
HOLDS_NONE = cmd("test_a_relay_whose_connection_changed_and_that_holds_none_is_said_to_hold_none")
DOOR_COUNT = (NODE_E2E, "a_read_through_the_carry_door_holds_its_pull_to_the_count_after_its_proof")
LARGER = (RECOVER_E2E, "a_recovery_reads_a_personal_channel_larger_than_one_read_to_its_end")
STAYS = (RECOVER_E2E, "a_recovery_whose_personal_channel_stays_read_in_part_goes_on_to_the_look")
TWO_RELAYS = (RECOVER_E2E, "a_recovery_says_at_which_relay_the_personal_channel_was_not_read")

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("RO1 a recovery reads on for a round more", PROTOCOL,
     '''    + CARRY_READ_MAX_SECS;

// Checked at compile time: a recovery reads on for more than one round.''',
     '''    + 2 * CARRY_READ_MAX_SECS;

// Checked at compile time: a recovery reads on for more than one round.''',
     [BOUND, AT_THE_BOUND]),
    ("RO2 the bound keeps no room for a show", PROTOCOL,
     '''pub const RECOVERY_READ_ON_MAX_SECS: u64 = 60 * MAX_ENTRY_CHANNEL_BYTES_AT_RELAY
    / (PUSH_BYTES_PER_PEER_PER_MINUTE - SHOW_ANSWER_ROOM_BYTES)''',
     '''pub const RECOVERY_READ_ON_MAX_SECS: u64 = 60 * MAX_ENTRY_CHANNEL_BYTES_AT_RELAY
    / PUSH_BYTES_PER_PEER_PER_MINUTE''',
     [BOUND]),
    ("RO3 the node says no bytes of what a relay handed", CARRYING,
     '''bytes = costs.map(|entry| entry_cost(entry.content.len())).sum();''',
     '''bytes = costs.map(|_| 0).sum();''',
     [BYTES]),
    ("RO4 the bytes said leave out what an entry takes beyond its content", CARRYING,
     '''bytes = costs.map(|entry| entry_cost(entry.content.len())).sum();''',
     '''bytes = costs.map(|entry| entry.content.len() as u64).sum();''',
     [BYTES]),
    ("RO5 a read with proofs hands an entry as often as it was handed", CARRYING,
     '''                if seen.insert(bytes.clone()) {''',
     '''                if seen.insert(bytes.clone()) || true {''',
     [ONCE]),
    ("RO6 a reading again keeps an entry as often as it was handed", CARRY_CMD,
     '''        let (handed, relays) = read(sessions)?;
        for entry in handed {
            if kept.insert(entry.id()) {''',
     '''        let (handed, relays) = read(sessions)?;
        for entry in handed {
            if kept.insert(entry.id()) || true {''',
     [AGAIN]),
    ("RO7 a reading again keeps the bytes said last, not the most", CARRY_CMD,
     '''                    if bytes_before > bytes_handed(of) {''',
     '''                    if false && bytes_before > bytes_handed(of) {''',
     [AGAIN]),
    ("RO8 a read on makes proofs for every relay", CARRY_CMD,
     '''        .filter(|(relay, _)| is_asked(relay))''',
     '''        .filter(|(_, _)| true)''',
     [NAMES_ONLY]),
    ("RO9 a read on keeps what is said of a relay it did not ask", CARRY_CMD,
     '''    relays.retain(|said| is_asked(text(said, "relay")));''',
     '''    relays.retain(|_| true);''',
     [NAMES_ONLY]),
    ("RO10 what is said of a relay drops the place reached", CARRY_CMD,
     '''        said["mark"] = at["mark"].clone();
        said["place"] = at["place"].clone();''',
     '''        said["mark"] = at["mark"].clone();''',
     [PLACE_SAID]),
    ("RO11 the command asks the node from no place", CARRY_CMD,
     '''json!({ "channel": hex::encode(channel), "proofs": proofs, "from": from }),''',
     '''json!({ "channel": hex::encode(channel), "proofs": proofs, "from": [] }),''',
     [LARGER]),
    ("RO12 a recovery reads one round only", RECOVER_CMD,
     '''        if asked.is_empty() {
            break;
        }''',
     '''        if true {
            break;
        }''',
     [TO_ITS_END, LARGER]),
    ("RO13 a relay is asked in a reading more than the bound", RECOVER_CMD,
     '''            if relay.readings >= RECOVERY_READ_ON_READS {''',
     '''            if relay.readings > RECOVERY_READ_ON_READS {''',
     [AT_THE_BOUND, CHANGING]),
    ("RO14 a reading is not counted", RECOVER_CMD,
     '''            relay.readings += 1;''',
     '''            relay.readings += 0;''',
     [AT_THE_BOUND]),
    ("RO15 a relay not reached in a round is asked again", RECOVER_CMD,
     '''                read => format!("it was {read}"),
            };
            return self.in_part(&why);''',
     '''                read => format!("it was {read}"),
            };
            self.on = true;
            return why;''',
     [NOT_REACHED]),
    ("RO16 a relay that answers to its end under no mark is read whole", RECOVER_CMD,
     '''            || (read == "whole" && place.as_ref().is_some_and(|(mark, _)| *mark == no_mark()));''',
     '''            || false;''',
     [NOT_REACHED]),
    ("RO17 a relay that holds none now is said not to be reached", RECOVER_CMD,
     '''        let holds_none = read == "not held"''',
     '''        let holds_none = false''',
     [NOT_REACHED]),
    ("RO18 a round that does not move the place is progress", RECOVER_CMD,
     '''        if place.is_none() || place == self.place {''',
     '''        if place.is_none() {''',
     [NOT_REACHED]),
    ("RO19 a first round to its end under no mark with nothing is read whole", RECOVER_CMD,
     '''                0 => "not held".into(),''',
     '''                0 => "whole".into(),''',
     [NOT_REACHED]),
    ("RO20 a first round to its end under no mark after a part is read whole", RECOVER_CMD,
     '''                _ => "part".into(),
            };''',
     '''                _ => "whole".into(),
            };''',
     [NOT_REACHED]),
    ("RO21 a first round in part at the start is read on", RECOVER_CMD,
     '''                    .is_some_and(|(mark, next)| (mark.as_str(), *next) != (no_mark().as_str(), 0)));''',
     '''                    .is_some());''',
     [NOT_REACHED]),
    ("RO22 a relay read to its end is said in part", RECOVER_CMD,
     '''            self.read = "whole".into();
            self.place = place;''',
     '''            self.read = "part".into();
            self.place = place;''',
     [TO_ITS_END, LEAVES]),
    ("RO23 a relay read to its end is read on", RECOVER_CMD,
     '''        if read == "whole" {
            self.read = "whole".into();''',
     '''        if read == "whole" && false {
            self.read = "whole".into();''',
     [LEAVES]),
    ("RO24 the entries handed are those of the last round alone", RECOVER_CMD,
     '''        self.handed += entries_handed(said);''',
     '''        self.handed = entries_handed(said);''',
     [TO_ITS_END]),
    ("RO25 the bytes read are those of the last round alone", RECOVER_CMD,
     '''        self.bytes += bytes_handed(said);''',
     '''        self.bytes = bytes_handed(said);''',
     [TO_ITS_END]),
    ("RO26 a round is asked from the start", RECOVER_CMD,
     '''        Some(json!({ "relay": self.relay, "mark": mark, "place": place }))''',
     '''        Some(json!({ "relay": self.relay, "mark": mark, "place": 0 }))''',
     [TO_ITS_END]),
    ("RO27 the place a round reached is not kept", RECOVER_CMD,
     '''        self.place = place;
        self.on = true;''',
     '''        self.on = true;''',
     [TO_ITS_END]),
    ("RO28 a read on keeps an entry as often as it was handed", RECOVER_CMD,
     '''    let mut keep = |handed: Vec<CheckedEntry>| {
        for entry in handed {
            if kept.insert(entry.id()) {''',
     '''    let mut keep = |handed: Vec<CheckedEntry>| {
        for entry in handed {
            if kept.insert(entry.id()) || true {''',
     [NOT_REACHED, LEAVES]),
    ("RO29 what a later round handed is not kept", RECOVER_CMD,
     '''        keep(handed);
        for relay in at.iter_mut()''',
     '''        let _ = handed;
        for relay in at.iter_mut()''',
     [TO_ITS_END]),
    ("RO30 nothing is said after a round", RECOVER_CMD,
     '''            say(relay.round(said));''',
     '''            relay.round(said);''',
     [TO_ITS_END, NOT_REACHED]),
    ("RO31 nothing is said of reading on after the first round", RECOVER_CMD,
     '''        .max()
    {''',
     '''        .max()
        .filter(|_| false)
    {''',
     [TO_ITS_END, LARGER]),
    ("RO32 a relay whose reads were all made is not said", RECOVER_CMD,
     '''                say(relay.in_part(&made));''',
     '''                relay.in_part(&made);''',
     [AT_THE_BOUND]),
    ("RO33 the first round counts as all the readings", RECOVER_CMD,
     '''.copied().unwrap_or(1);''',
     '''.copied().unwrap_or(RECOVERY_READ_ON_READS);''',
     [TO_ITS_END]),
    ("RO34 the line of a read in part says no relay's reason", RECOVER_CMD,
     '''        let part = of.at_with_why(&[ReadAs::Part]);''',
     '''        let part = of.at(&[ReadAs::Part]);''',
     [WHY, STAYS]),
    ("RO35 the phrase's own channel is not said before the yes", RECOVER_CMD,
     '''        if !self.phrase_not_read.is_empty() {''',
     '''        if false {''',
     [PHRASE, TWO_RELAYS]),
    ("RO36 a relay that holds none of the phrase's channel is said", RECOVER_CMD,
     '''            phrase_not_read: not_read_at(phrase),''',
     '''            phrase_not_read: phrase.iter().map(|r| text(r, "relay").to_string()).collect(),''',
     [PHRASE]),
    ("RO37 the change recovered from is said to be the latest whatever it is", RECOVER_CMD,
     '''            let latest = match self.latest == number {''',
     '''            let latest = match true {''',
     [PHRASE]),
    ("RO38 the command hands no phrase's read to what is said before the yes", RECOVER_CMD,
     '''WasRead::of(statement.number, personal_read, &phrase_read, latest)''',
     '''WasRead::of(statement.number, personal_read, &[], latest)''',
     [TWO_RELAYS]),
    # A read that a relay refuses for now waits it out (RO40), so the
    # recovery of a larger channel reads it to its end either way: the
    # rule is told by the count of pages a relay is asked for.
    ("RO39 a device takes a page from the room a relay keeps for a show", ENTRIES,
     '''        taken_from(of).room() >= entry_cost(MAX_ITEM_BYTES) + SHOW_ANSWER_ROOM_BYTES''',
     '''        taken_from(of).room() >= entry_cost(MAX_ITEM_BYTES)''',
     [SHOW_ROOM]),
    ("RO40 a pull refused for now ends the read", ENTRIES,
     '''                Err(LeftRefused::NotNow) => {
                    proved = true;''',
     '''                Err(LeftRefused::NotNow) if false => {
                    proved = true;''',
     [NOT_NOW]),
    ("RO41 a pull refused for now is not told from one not answered", LEAVE,
     '''            Err(Refused::NotNow) => return Err(LeftRefused::NotNow),''',
     '''            Err(Refused::NotNow) if false => return Err(LeftRefused::NotNow),''',
     [NOT_NOW]),
    ("RO42 a stream reset with any code is taken as refused for now", LEAVE,
     '''    let code = quinn::VarInt::from_u32(ERR_RATE_LIMIT);
    let Some(inner) = io.get_ref() else {''',
     '''    let code = quinn::VarInt::from_u32(0);
    let Some(inner) = io.get_ref() else {''',
     [NOT_NOW]),
    ("RO43 the proof is sent again after a pull refused for now", ENTRIES,
     '''                    proved = true;
                    let within''',
     '''                    let within''',
     [NOT_NOW]),
    ("RO44 a reading asks for the sessions again where no connection changed", CARRY_CMD,
     '''    if relays.iter().any(connection_changed) {''',
     '''    if true {''',
     [ONE_READING]),
    ("RO45 a relay whose connection changed is not asked in the next round", RECOVER_CMD,
     '''        if read == CONNECTION_CHANGED {
            self.on = true;''',
     '''        if read == CONNECTION_CHANGED {
            self.on = false;''',
     [CHANGING]),
    ("RO46 a relay whose connection changed in the first round is not read on", RECOVER_CMD,
     '''        at.on = at.changed
            ||''',
     '''        at.on = false
            ||''',
     [AT_THE_BOUND, CHANGING]),
    ("RO47 a reading asks for no sessions where a connection changed", CARRY_CMD,
     '''    if relays.iter().any(connection_changed) {
        *sessions = ask()?;''',
     '''    if relays.iter().any(connection_changed) {
        let _ = ask;''',
     [ONE_READING]),
    ("RO48 what a relay handed in a round that ended early is not counted", RECOVER_CMD,
     '''        if let Some(said) = said {
            self.handed += entries_handed(said);''',
     '''        let gone = |said: &&Value| {
            text(said, "read") == "not held"
                || place_of(said).is_none_or(|(mark, _)| mark == no_mark())
        };
        if let Some(said) = said.filter(|said| !gone(said)) {
            self.handed += entries_handed(said);''',
     [NOT_REACHED]),
    ("RO49 a proof refused for now is said as a page's", LEAVE,
     '''                Err(Refused::NotNow) => return Err(not(PROOF_NOT_NOW)),''',
     '''                Err(Refused::NotNow) => return Err(not("refused for now")),''',
     [NOT_NOW]),
    ("RO50 a request stopped with the rate-limit code is not refused for now", LEAVE,
     '''        || matches!(inner.downcast_ref(), Some(quinn::WriteError::Stopped(at)) if *at == code)''',
     '''        || false''',
     [CUT_OFF]),
    ("RO54 the first line of reading on says other reads", RECOVER_CMD,
     '''            CARRY_READ_MAX_SECS / 60
        ));''',
     '''            CARRY_READ_MAX_SECS / 30
        ));''',
     [TO_ITS_END]),
    ("RO55 what is said of a relay read in part says no reason", RECOVER_CMD,
     '''            said["why"] = why.as_str().into();''',
     '''            let _ = why;''',
     [AT_THE_BOUND, WHY]),
    ("RO56 a relay read in part keeps no reason", RECOVER_CMD,
     '''        self.why = Some(why.to_string());''',
     '''        let _ = why;''',
     [AT_THE_BOUND, WHY]),
    ("RO51 a read asks again after a refusal for now at the relay's count", ENTRIES,
     '''                    if !within || !self.asks_again_after_a_refusal(link) {''',
     '''                    if !within {''',
     [NOT_NOW]),
    ("RO52 a read asks a relay at its count", ENTRIES,
     '''            if !self.asks_after_refusals(link) {''',
     '''            if false && !self.asks_after_refusals(link) {''',
     [NOT_NOW]),
    ("RO53 a read that asked a relay at its count nothing says it was not reached", ENTRIES,
     '''                    true => LeftRead::NotRead(AT_ITS_COUNT.into()),''',
     '''                    true => LeftRead::NotReached,''',
     [NOT_NOW]),
    ("RO57 a relay whose connection changed is not read again in the first round", RECOVER_CMD,
     '''    for _ in 0..CARRY_PROOFS_MADE_AGAIN {''',
     '''    for _ in 0..0 {''',
     [HOLDS_NONE, AT_THE_BOUND, CHANGING]),
    ("RO58 the first round reads a relay again once more than the read of today", RECOVER_CMD,
     '''    for _ in 0..CARRY_PROOFS_MADE_AGAIN {''',
     '''    for _ in 0..CARRY_PROOFS_MADE_AGAIN + 1 {''',
     [AT_THE_BOUND, CHANGING]),
    ("RO59 a reading again within the first round is not counted", RECOVER_CMD,
     '''            *readings.entry(relay.clone()).or_insert(1) += 1;''',
     '''            *readings.entry(relay.clone()).or_insert(1) += 0;''',
     [AT_THE_BOUND, CHANGING]),
    ("RO60 the first round reads every relay again where a connection changed", RECOVER_CMD,
     '''        let (handed, again) = round(Some(&changed), &[])?;''',
     '''        let (handed, again) = round(None, &[])?;''',
     [HOLDS_NONE]),
    ("RO61 what a relay read again in the first round said is not taken", RECOVER_CMD,
     '''            if let Some(of) = of {
                *of = said;''',
     '''            if let Some(of) = of {
                let _ = (of, said);''',
     [HOLDS_NONE]),
    ("RO62 a relay that handed nothing and holds none is said in part", RECOVER_CMD,
     '''        if holds_none && self.handed == 0 {''',
     '''        if false {''',
     [HOLDS_NONE]),
    ("RO63 a relay that handed nothing and holds none is not said to hold none", RECOVER_CMD,
     '''            self.read = "not held".into();
            return format!("  {}: it holds none of it.", self.relay);''',
     '''            return format!("  {}: it holds none of it.", self.relay);''',
     [HOLDS_NONE]),
    ("RO64 a relay that handed nothing is said to be read in part", RECOVER_CMD,
     '''            0 => format!("  {}: nothing of it was read: {why}.", self.relay),''',
     '''            0 => format!("  {}: read in part, 0.0 MiB: {why}.", self.relay),''',
     [HOLDS_NONE, CHANGING]),
    ("RO65 a relay whose connection changed is said larger than one read", RECOVER_CMD,
     '''.filter(|r| r.on && !r.changed)''',
     '''.filter(|r| r.on)''',
     [AT_THE_BOUND]),
    ("RO66 a relay whose connection changed in the first round is not said", RECOVER_CMD,
     '''    for relay in at.iter().filter(|relay| relay.on) {
        say(match relay.changed {''',
     '''    for relay in at.iter().filter(|relay| relay.on && !relay.changed) {
        say(match relay.changed {''',
     [HOLDS_NONE, AT_THE_BOUND]),
    ("RO67 the first line of reading on counts no read made", RECOVER_CMD,
     '''.map(|r| RECOVERY_READ_ON_READS.saturating_sub(r.readings))''',
     '''.map(|_| RECOVERY_READ_ON_READS)''',
     [TO_ITS_END, LARGER]),
    ("RO68 reads made with a change at the last say nothing of it", RECOVER_CMD,
     '''                let made = match relay.changed {''',
     '''                let made = match false {''',
     [CHANGING, WHY]),
    ("RO69 a later round does not say whether its connection changed", RECOVER_CMD,
     '''        self.changed = read == CONNECTION_CHANGED;''',
     '''''',
     [AT_THE_BOUND, WHY]),
    ("RO70 a relay of which nothing was read is named with no reason", RECOVER_CMD,
     '''        let nothing = of.at_with_why(&[ReadAs::Nothing]);''',
     '''        let nothing = of.at(&[ReadAs::Nothing]);''',
     [CHANGING]),
    ("RO71 a relay not read to its end where another was is named with no reason", RECOVER_CMD,
     '''            let not_to_the_end = of.at_with_why(&[ReadAs::Part, ReadAs::Nothing]);''',
     '''            let not_to_the_end = of.at(&[ReadAs::Part, ReadAs::Nothing]);''',
     [HOLDS_NONE]),
    ("RO72 the door sends a pull at the relay's count after its proof", LEAVE,
     '''        if self.at_its_count(&link.relay().0) {
            return Err(LeftRefused::AtItsCount);''',
     '''        if false {
            return Err(LeftRefused::AtItsCount);''',
     [DOOR_COUNT]),
    ("RO73 a pull the door held to the count is said as a read in part", ENTRIES,
     '''                Err(LeftRefused::AtItsCount) if read.is_empty() && !proved => {''',
     '''                Err(LeftRefused::AtItsCount) if false => {''',
     [DOOR_COUNT]),
    ("RO74 a read asks again after a refusal more than a minute after a page", ENTRIES,
     '''                    let within = self.clock.now() < paged + own_read::A_MINUTE;''',
     '''                    let within = true;''',
     [NOT_NOW]),
    ("RO75 a page does not begin the minute again", ENTRIES,
     '''                    paged = self.clock.now();
                    let moved''',
     '''                    let moved''',
     [NOT_NOW]),
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
