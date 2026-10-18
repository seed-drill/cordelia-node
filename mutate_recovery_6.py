#!/usr/bin/env python3
"""Mutation checks for a pull of a device's own channel with places of
its own, slice 6 of decision 2026-10-17 (section 4.2, items 1 to 3): a
page taken through take_page and the one door without writing the
stored place or what was sent, the read's places and notes kept in
memory under its ID, read on round by round, within the pass's budget at
each relay, and outside the database's lock. A part for each rule of the
slice: put each fault in, and confirm the test named for it fails on an
assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
AT_RELAYS = 'crates/cordelia-api/src/at_relays.rs'
OWN_READ = 'crates/cordelia-api/src/own_read.rs'
NODE_READ = 'crates/cordelia-node/src/device_entries/own_read.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
LEAVE = 'crates/cordelia-node/src/device_entries/leave.rs'
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
ORIG = {f: open(f).read() for f in (AT_RELAYS, OWN_READ, NODE_READ, DEVICE, PROTOCOL, LEAVE)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
CORE = ("cordelia-core", ["--lib"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def at_relays(test): return (API, "at_relays::tests::" + test)
def own_read(test): return (API, "own_read::tests::" + test)
def e2e(test): return (E2E, test)

LEAVES = at_relays("test_a_page_under_places_of_a_reads_own_leaves_the_stored_place_and_what_was_sent")
READ_AGAIN = at_relays("test_a_page_under_places_of_a_reads_own_that_makes_a_key_count_has_everything_read_again")
KEPT_PULL = at_relays("test_a_pull_goes_on_from_the_place_kept_and_from_the_start_under_another_mark")
STARTS = own_read("test_a_read_starts_from_the_start_and_goes_on_from_the_place_each_page_reaches")
TO_ITS_END = own_read("test_a_relay_is_read_to_its_end_by_a_page_of_nothing_or_one_that_leaves_the_place")
HOLDS_NONE = own_read("test_a_relay_that_holds_none_and_one_that_handed_part_and_then_holds_none")
NOT_THE_PAGE = own_read("test_a_page_that_is_not_the_channels_leaves_the_relay_read_in_part")
NOTED = own_read("test_what_each_relay_handed_is_noted_in_each_slot")
NOT_REACHED = own_read("test_a_relay_not_reached_in_a_round_is_not_read_on")
KEPT_UNDER_ID = own_read("test_a_read_is_kept_under_its_id_and_a_new_read_of_its_channel_takes_its_place")
E2E_STARTS = e2e("a_read_with_places_of_its_own_starts_from_the_start_and_leaves_the_stored_place_and_what_was_sent")
E2E_LOCK = e2e("a_read_with_places_of_its_own_does_not_hold_the_lock_while_it_reads")
E2E_READS_ON = e2e("a_read_with_places_of_its_own_reads_on_under_its_id_from_the_place_it_reached")
E2E_TAKES = e2e("a_read_with_places_of_its_own_takes_within_what_the_pass_takes_from_a_relay")
E2E_ASKS = e2e("a_read_with_places_of_its_own_asks_within_what_the_device_asks_of_a_relay")
STANDS = own_read("test_a_read_stands_for_so_long_from_the_end_of_its_last_round")
CONSTANTS = (CORE, "protocol::tests::test_a_carry_by_command_and_a_recovery_decision_2026_10_04_7_3_and_9")
E2E_RESET = e2e("a_read_with_places_of_its_own_waits_out_a_pull_refused_for_now")
E2E_EVERY = e2e("a_relay_that_refuses_every_pull_is_not_reached_and_holds_up_no_other_read")
E2E_CLOSED = e2e("a_connection_that_closes_mid_read_leaves_the_relay_not_reached")
E2E_OVERSIZE = e2e("a_page_of_more_entries_than_a_page_holds_is_not_taken_by_a_read")
E2E_LAST_PAGE = e2e("a_refusal_for_now_is_waited_out_for_a_minute_from_the_last_page")
E2E_DEADLINE = e2e("a_round_ends_at_its_time_while_a_relay_is_waited_for_or_asked")
E2E_GONE = e2e("a_round_whose_asker_has_gone_stops")
E2E_PROVES_ONCE = e2e("a_pass_proves_again_only_after_a_no_given_to_a_read_and_once")
E2E_COUNTED = e2e("what_a_relay_refused_for_now_is_counted_for_the_relay_over_the_window")
E2E_PROOF_TIME = e2e("a_round_ends_at_its_time_while_its_proof_is_not_answered")
UNIT_NOT_NOW = (("cordelia-node", ["--lib"]), "device_entries::leave::tests::a_request_is_refused_for_now_only_by_the_rate_limits_code")
E2E_LEFT_ROOM = e2e("a_read_of_a_left_channel_takes_no_page_from_the_room_kept_for_a_show")
E2E_PROOF = e2e("a_relay_that_answered_a_reads_proof_with_no_is_sent_the_channel_again")
E2E_ROUND_MOST = e2e("a_round_of_a_read_lasts_no_longer_than_a_carry_may_read")
E2E_REPLACED = e2e("a_read_that_another_read_of_its_channel_replaced_stops")
E2E_ONE_ROUND = e2e("one_round_of_a_read_runs_at_a_time_on_the_node")
E2E_FAILED = e2e("a_page_that_a_read_could_not_take_leaves_the_relay_not_reached")
E2E_CHANGE = e2e("a_round_after_a_change_asks_a_relay_nothing")
E2E_RACE = e2e("a_pull_in_flight_when_every_place_is_forgotten_keeps_no_place")

OWN_BRANCH = '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            if read_again {'''

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    ("TP1 a page of a read's own writes the stored place", AT_RELAYS,
     OWN_BRANCH,
     '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            if page.mark != NO_MARK {
                kept_rows::keep_place(conn, page.relay, &page.channel.id, &page.mark, page.next)?;
            }
            if read_again {''',
     [LEAVES]),
    ("TP2 a page of a read's own marks what it brought as sent", AT_RELAYS,
     OWN_BRANCH,
     '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            let last = kept_rows::last_taken(conn, &page.channel.id)?;
            kept_rows::sent(conn, page.relay, &page.channel.id, last)?;
            if read_again {''',
     [LEAVES]),
    ("TP3 a page of a read's own under no holding starts the relay again", AT_RELAYS,
     OWN_BRANCH,
     '''            let (each, read_again) = through_the_door(conn, identity, page, now)?;
            if page.mark == NO_MARK && page.entries.is_empty() {
                kept_rows::start_again(conn, page.relay, &page.channel.id)?;
            }
            if read_again {''',
     [LEAVES]),
    ("TP4 a page of a read's own that makes a key count forgets no place", AT_RELAYS,
     '''            if read_again {
                kept_rows::forget_places(conn)?;
            }
            Ok(PageTaken::Taken { each, read_again })
        });''',
     '''            Ok(PageTaken::Taken { each, read_again })
        });''',
     [READ_AGAIN]),
    ("TP5 a pass's page is taken as a read's own", AT_RELAYS,
     '''    if places == Places::Own {''',
     '''    if places == Places::Own || places == Places::Kept {''',
     [KEPT_PULL]),
    ("TP6 a read's own page is taken as a pass's", AT_RELAYS,
     '''    if places == Places::Own {''',
     '''    if places != Places::Own && places == Places::Own {''',
     [LEAVES]),
    ("OR1 a read starts at a place that is not the start", OWN_READ,
     '''            place: (NO_MARK, 0),''',
     '''            place: (NO_MARK, 1),''',
     [STARTS, KEPT_UNDER_ID]),
    ("OR2 a page that is not the channel's is read on", OWN_READ,
     '''                self.read = ReadAt::InPart;
                return false;''',
     '''                self.read = ReadAt::Reading;
                return false;''',
     [NOT_THE_PAGE]),
    ("OR3 holding none and read in part are swapped", OWN_READ,
     '''                true => ReadAt::HoldsNone,
                false => ReadAt::InPart,''',
     '''                true => ReadAt::InPart,
                false => ReadAt::HoldsNone,''',
     [HOLDS_NONE]),
    ("OR4 the mark of no holding is not read as holding none", OWN_READ,
     '''        if mark == NO_MARK && entries.is_empty() {''',
     '''        if mark == NO_MARK && entries.is_empty() && false {''',
     [HOLDS_NONE]),
    ("OR5 a page that leaves the place is not the end", OWN_READ,
     '''        if entries.is_empty() || (mark, next) == self.place {''',
     '''        if entries.is_empty() {''',
     [TO_ITS_END]),
    ("OR6 a page of nothing that moves the place is not the end", OWN_READ,
     '''        if entries.is_empty() || (mark, next) == self.place {''',
     '''        if (mark, next) == self.place {''',
     [TO_ITS_END]),
    ("OR7 the place does not move with the page", OWN_READ,
     '''        self.place = (mark, next);''',
     '''        let _ = (mark, next);''',
     [STARTS]),
    ("OR8 an entry handed again is noted twice", OWN_READ,
     '''            if !slot.iter().any(|held| held.id() == entry.id()) {''',
     '''            if !slot.iter().any(|held| held.id() == entry.id()) || true {''',
     [NOTED]),
    ("OR9 what was handed is not noted", OWN_READ,
     '''                slot.push(entry.clone());''',
     '''                let _ = entry;''',
     [NOTED, STARTS]),
    ("OR10 a relay not reached is read in part with nothing handed", OWN_READ,
     '''            true => ReadAt::NotReached,
            false => ReadAt::InPart,''',
     '''            true => ReadAt::InPart,
            false => ReadAt::NotReached,''',
     [NOT_REACHED]),
    ("OR11 a relay read in part and stopped is read on", OWN_READ,
     '''        self == Self::Reading''',
     '''        self != Self::ToItsEnd''',
     [NOT_THE_PAGE, KEPT_UNDER_ID]),
    ("OR12 what was handed is not counted", OWN_READ,
     '''                self.bytes += counted;
                (entries, mark, next)''',
     '''                (entries, mark, next)''',
     [STARTS]),
    ("OR13 a new read of a channel keeps the one before", OWN_READ,
     '''        reads.retain(|_, kept| kept.channel != *channel);''',
     '''        reads.retain(|_, _| true);''',
     [KEPT_UNDER_ID]),
    ("OR14 a round is taken while another runs", OWN_READ,
     '''.filter(|kept| !kept.reading)?;''',
     '''.filter(|_| true)?;''',
     [KEPT_UNDER_ID]),
    ("OR15 a round takes every relay, not those read in part", OWN_READ,
     '''            .filter(|at| at.read.reads_on())''',
     '''            .filter(|_| true)''',
     [KEPT_UNDER_ID]),
    ("OR16 a round that ends leaves the read running", OWN_READ,
     '''        kept.reading = false;''',
     '''        let _ = &kept.reading;''',
     [KEPT_UNDER_ID]),
    ("OR17 every read is named by the same ID", OWN_READ,
     '''        id.copy_from_slice(&random[..16]);''',
     '''        let _ = random;''',
     [KEPT_UNDER_ID]),
    ("NR1 the node takes a read's page as a pass's", NODE_READ,
     '''take_page(db, identity, &page, Places::Own, now)''',
     '''take_page(db, identity, &page, Places::Kept, now)''',
     [E2E_STARTS]),
    ("NR2 the node reads from the place that the pass keeps", NODE_READ,
     '''            let (mark, after) = at.place;''',
     '''            let (mark, after) = at_relays::place(&lock(&self.state.db), &relay, &channel.id)
                .unwrap_or(at.place);''',
     [E2E_STARTS]),
    ("NR3 the read's proof answered no starts the relay again", NODE_READ,
     '''self.prove(&asks, channel, false)''',
     '''self.prove(&asks, channel, true)''',
     [E2E_STARTS]),
    ("NR4 the read takes beyond the minute's room", NODE_READ,
     '''            if !self.room_to_take(link) {''',
     '''            if !self.room_to_take(link) && false {''',
     [E2E_TAKES]),
    ("NR5 what the read takes is not counted with the pass", NODE_READ,
     '''                    self.took(link, handed);''',
     '''                    let _ = handed;''',
     [E2E_TAKES]),
    ("NR6 asked enough ends the relay's read instead of waiting", NODE_READ,
     '''                Err(Refused::AskedEnough) => {''',
     '''                Err(Refused::NotARequest) => {''',
     [E2E_ASKS]),
    ("NR7 the read holds the database's lock", NODE_READ,
     '''        let relay = link.relay().0;
        let reads = self.state.own_channels.reads();''',
     '''        let relay = link.relay().0;
        std::mem::forget(lock(&self.state.db));
        let reads = self.state.own_channels.reads();''',
     [E2E_LOCK]),
    ("NR8 a channel that a pass does not pull begins a read", NODE_READ,
     '''            if !own.iter().any(|own| own.id == *channel && own.is_pulled()) {''',
     '''            if !own.iter().any(|own| own.id == *channel && own.is_pulled()) && false {''',
     [E2E_READS_ON]),
    ("NR9 a read that the node does not know is answered as known", NODE_READ,
     '''        let Some((channel, under, at)) = reads.to_read(read, self.clock.now()) else {
            return false;''',
     '''        let Some((channel, under, at)) = reads.to_read(read, self.clock.now()) else {
            return true;''',
     [E2E_READS_ON]),
    ("NR10 a relay not connected stays read on", NODE_READ,
     '''                    one.not_reached();''',
     '''                    let _ = &mut one;''',
     [E2E_READS_ON]),
    ("NR11 a node that is held up begins a read", NODE_READ,
     '''        if self.state.held.why().is_some() {
            return None;
        }''',
     '''''',
     [E2E_READS_ON]),
    ("NR12 a node that is held up reads a round", NODE_READ,
     '''(self.state.held.why().is_none())''',
     '''(true)''',
     [E2E_READS_ON]),
    ("NR13 a refusal for now ends the relay's read", NODE_READ,
     '''                Err(Refused::NotNow) => {''',
     '''                Err(Refused::NotARequest) => {''',
     [E2E_RESET]),
    ("NR19 a refusal for now is waited out after the minute", NODE_READ,
     '''                    let within = self.clock.now() < paged + A_MINUTE;''',
     '''                    let within = self.clock.now() < paged + 100 * A_MINUTE;''',
     [E2E_EVERY]),
    ("NR20 every failure on a request is a refusal for now", LEAVE,
     '''            match refused_for_now(&e) {''',
     '''            match !refused_for_now(&e) || refused_for_now(&e) {''',
     [E2E_OVERSIZE, E2E_RESET]),
    ("NR22 a wait for a refusal runs past the round's time", NODE_READ,
     '''                    tokio::time::sleep(LEFT_ROOM_WAIT.min(left)).await;
                    continue;
                }
                Err(_) => {''',
     '''                    tokio::time::sleep(LEFT_ROOM_WAIT).await;
                    continue;
                }
                Err(_) => {''',
     [E2E_DEADLINE]),
    ("NR26 refusals for now are asked again without bound", DEVICE,
     '''        refused.len() < (BAN_THRESHOLD - 1) as usize''',
     '''        refused.len() < usize::MAX''',
     [E2E_EVERY, E2E_COUNTED]),
    ("NR27 refusals for now are asked again up to the relay's count", DEVICE,
     '''        refused.len() < (BAN_THRESHOLD - 1) as usize''',
     '''        refused.len() < BAN_THRESHOLD as usize''',
     [E2E_EVERY, E2E_COUNTED]),
    ("NR32 a page resets the count of refusals", NODE_READ,
     '''                    paged = self.clock.now();''',
     '''                    paged = self.clock.now();
                    lock(&self.kept).refused_for_now.remove(&link.relay().0);''',
     [E2E_COUNTED]),
    ("NR33 each round starts its count of refusals again", NODE_READ,
     '''        let asks = At {''',
     '''        lock(&self.kept).refused_for_now.remove(&link.relay().0);
        let asks = At {''',
     [E2E_COUNTED]),
    ("NR34 a refusal never leaves the window", DEVICE,
     '''        refused.retain(|at| now.saturating_duration_since(*at) < BAN_WINDOW);''',
     '''        refused.retain(|_| true);''',
     [E2E_COUNTED]),
    ("NR28 the proof runs past the round's time", NODE_READ,
     '''tokio::time::timeout(left, self.prove(&asks, channel, false))''',
     '''tokio::time::timeout(left + ROUND_MOST, self.prove(&asks, channel, false))''',
     [E2E_PROOF_TIME]),
    ("NR29 a wait for room runs past the round's time", NODE_READ,
     '''            if !self.room_to_take(link) {
                tokio::time::sleep(LEFT_ROOM_WAIT.min(left)).await;''',
     '''            if !self.room_to_take(link) {
                tokio::time::sleep(LEFT_ROOM_WAIT).await;''',
     [E2E_TAKES]),
    ("NR30 a wait for asking runs past the round's time", NODE_READ,
     '''                Err(Refused::AskedEnough) => {
                    tokio::time::sleep(LEFT_ROOM_WAIT.min(left)).await;''',
     '''                Err(Refused::AskedEnough) => {
                    tokio::time::sleep(LEFT_ROOM_WAIT).await;''',
     [E2E_ASKS]),
    ("NR31 a first round goes on after its asker has gone", NODE_READ,
     '''                        _ = answer.closed() => return self.asker_gone(read),''',
     '''                        _ = std::future::pending::<()>() => return self.asker_gone(read),''',
     [E2E_GONE]),
    ("LV1 a reset for now is not told from any other", LEAVE,
     '''    matches!(inner.downcast_ref(), Some(quinn::ReadError::Reset(at)) if *at == code)
        || matches!(inner.downcast_ref(), Some(quinn::WriteError::Stopped(at)) if *at == code)''',
     '''    let _ = (inner, code);
    false''',
     [UNIT_NOT_NOW, E2E_RESET]),
    ("LV2 a request stopped for now is not told", LEAVE,
     '''        || matches!(inner.downcast_ref(), Some(quinn::WriteError::Stopped(at)) if *at == code)''',
     '''        || false''',
     [UNIT_NOT_NOW]),
    ("LV3 a reset with any code is a refusal for now", LEAVE,
     '''    matches!(inner.downcast_ref(), Some(quinn::ReadError::Reset(at)) if *at == code)''',
     '''    matches!(inner.downcast_ref(), Some(quinn::ReadError::Reset(_)))''',
     [UNIT_NOT_NOW, E2E_RESET]),
    ("NR21 the minute is counted from the round's start", NODE_READ,
     '''                    paged = self.clock.now();''',
     '''                    let _ = &mut paged;''',
     [E2E_LAST_PAGE]),
    ("NR23 a request runs past the round's time", NODE_READ,
     '''            let Ok(taken) = tokio::time::timeout(left, taken).await else {''',
     '''            let Ok(taken) = tokio::time::timeout(left + ROUND_MOST, taken).await else {''',
     [E2E_DEADLINE]),
    ("NR24 a round goes on after its asker has gone", NODE_READ,
     '''                    _ = answer.closed() => return self.asker_gone(&read),''',
     '''                    _ = std::future::pending::<()>() => return self.asker_gone(&read),''',
     [E2E_GONE]),
    ("NR25 the read of a gone asker is kept", NODE_READ,
     '''        self.state.own_channels.reads().forget(read);''',
     '''        let _ = read;''',
     [E2E_GONE]),
    ("DE4 an unheeded no is never cleared", DEVICE,
     '''                    false => of.no_unheeded.remove(&channel.id),''',
     '''                    false => false,''',
     [E2E_PROVES_ONCE]),
    ("DE5 a read's yes is kept as an unheeded no", DEVICE,
     '''                match !proved && !held {''',
     '''                match !held {''',
     [E2E_PROVES_ONCE]),
    ("DE6 an empty page from a forgotten place is the channel's end", DEVICE,
     '''                Ok(Some(page)) if page.entries == 0 && !page.stale => return Step::Done(true),''',
     '''                Ok(Some(page)) if page.entries == 0 => return Step::Done(true),''',
     [E2E_RACE]),
    ("DE7 a page from a forgotten place got nowhere", DEVICE,
     '''                                got_somewhere: places == Places::Own
                                    || got_somewhere(''',
     '''                                got_somewhere: false
                                    || got_somewhere(''',
     [E2E_RACE]),
    ("DE8 the door's read takes beyond the minute's room", DEVICE,
     '''            if !self.room_to_take(link) {
                tokio::time::sleep(LEFT_ROOM_WAIT).await;''',
     '''            if false {
                tokio::time::sleep(LEFT_ROOM_WAIT).await;''',
     [E2E_LEFT_ROOM]),
    ("NR14 a round lasts as long as its asker said", NODE_READ,
     '''                let until = until.min(self.clock.now() + ROUND_MOST);
                let begun = self.begin_own(relays, &channel);''',
     '''                let begun = self.begin_own(relays, &channel);''',
     [E2E_ROUND_MOST]),
    ("NR15 a read that another took the place of reads on", NODE_READ,
     '''            if now >= until || !reads.stands(read) {''',
     '''            if now >= until {''',
     [E2E_REPLACED]),
    ("NR16 rounds of two reads run at once", NODE_READ,
     '''        let Ok(_one_round) = tokio::time::timeout(wait, self.own_rounds.lock()).await else {''',
     '''        let Ok(_one_round) = tokio::time::timeout(wait, async { Ok::<(), ()>(()) }).await else {''',
     [E2E_ONE_ROUND]),
    ("NR17 a page the store could not take is read as handed", NODE_READ,
     '''                Pulled::Failed => {
                    at.not_reached();
                    return at;
                }''',
     '''                Pulled::Failed => Handed::NotThePage { counted },''',
     [E2E_FAILED]),
    ("NR18 a round reads under the change entry kept now", NODE_READ,
     ['''                    .find(|own| own.id == channel && own.is_pulled())''',
      '''            under: *under,
        };'''],
     ['''                    .find(|own| own.is_pulled() && matches!(own.kind, at_relays::Kind::Name(_)))''',
      '''            under: at_relays::kept_id(&lock(&self.state.db)).ok().flatten().unwrap_or(*under),
        };'''],
     [E2E_CHANGE]),
    ("DE1 a read's no fills the pass's proof", DEVICE,
     '''            if lately && !(held && unheeded) {''',
     '''            if lately {''',
     [E2E_PROOF]),
    ("DE2 a device takes a page into the room kept for a show", DEVICE,
     '''        taken_from(of).room() >= entry_cost(MAX_ITEM_BYTES) + SHOW_ANSWER_ROOM_BYTES''',
     '''        taken_from(of).room() >= entry_cost(MAX_ITEM_BYTES) + 0 * SHOW_ANSWER_ROOM_BYTES''',
     [E2E_TAKES, E2E_LEFT_ROOM]),
    ("DE3 a pull in flight keeps its place when every place was forgotten", DEVICE,
     '''                            Ok(kept) if kept == (mark, after) => Places::Kept,''',
     '''                            Ok(_) => Places::Kept,''',
     [E2E_RACE]),
    ("OR18 a read stands for ever", OWN_READ,
     '''        reads.retain(|_, kept| kept.reading || now.saturating_duration_since(kept.ended) < STANDS);''',
     '''        reads.retain(|_, _| true);''',
     [STANDS]),
    ("OR19 a read is forgotten while a round of it runs", OWN_READ,
     '''        reads.retain(|_, kept| kept.reading || now.saturating_duration_since(kept.ended) < STANDS);''',
     '''        reads.retain(|_, kept| now.saturating_duration_since(kept.ended) < STANDS);''',
     [STANDS]),
    ("OR20 a read stands from when it began, not its last round", OWN_READ,
     '''        kept.ended = now;''',
     '''        let _ = now;''',
     [STANDS]),
    ("PR1 a read stands a second longer", PROTOCOL,
     '''pub const LET_GO_READ_STANDS_SECS: u64 = CARRY_WORD_SECS as u64;''',
     '''pub const LET_GO_READ_STANDS_SECS: u64 = CARRY_WORD_SECS as u64 + 1;''',
     [CONSTANTS]),
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
