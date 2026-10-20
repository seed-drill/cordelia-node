#!/usr/bin/env python3
"""Mutation checks for slice 1 of a relay out of reach: what the node keeps
of each relay, the classes, and the dial (decision 2026-10-19 §1, rules 2,
3 and 13, §10). A part for each rule of the slice: put each fault in, and
confirm the test named for it fails on an assertion. Run from the root of
a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
PROTOCOL = 'crates/cordelia-core/src/protocol.rs'
KNOWN = 'crates/cordelia-api/src/at_relays/known.rs'
ADDING = 'crates/cordelia-api/src/adding.rs'
LEAVING = 'crates/cordelia-api/src/leaving.rs'
REACH = 'crates/cordelia-node/src/device_entries/reach.rs'
DEVICE = 'crates/cordelia-node/src/device_entries.rs'
P2P = 'crates/cordelia-node/src/p2p.rs'
ORIG = {f: open(f).read() for f in (PROTOCOL, KNOWN, ADDING, LEAVING, REACH, DEVICE, P2P)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
CORE = ("cordelia-core", ["--lib"])
API = ("cordelia-api", ["--lib"])
NODE = ("cordelia-node", ["--lib"])
BIN = ("cordelia-node", ["--bin", "cordelia"])
E2E = ("cordelia-node", ["--test", "device_entries_e2e"])
def core(test): return (CORE, "protocol::tests::" + test)
def known(test): return (API, "at_relays::known::tests::" + test)
def reach(test): return (NODE, "device_entries::reach::tests::" + test)
def p2p(test): return (BIN, "p2p::tests::" + test)
def e2e(test): return (E2E, test)

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── §10, the constant ───────────────────────────────────────────
    ("C1 out of reach is a second longer than the amber's five minutes", PROTOCOL,
     '''pub const OUT_OF_REACH_SECS: u64 = STATUS_AMBER_WAIT_SECS;''',
     '''pub const OUT_OF_REACH_SECS: u64 = STATUS_AMBER_WAIT_SECS + 1;''',
     [core("test_out_of_reach_is_the_five_minutes_of_the_status_line_decision_2026_10_19_10"),
      reach("a_relay_is_out_of_reach_after_five_minutes_of_failed_attempts")]),

    # ── §1, rule 2: what is kept in the database ────────────────────
    ("K1 an answer about another entry holds the kept one", KNOWN,
     '''            match answer.entry == kept && answer.holds && by_its_key {''',
     '''            match answer.holds && by_its_key {''',
     [known("the_latest_answer_writes_over_the_one_before")]),
    ("K2 an answer that says it does not hold it holds it", KNOWN,
     '''            match answer.entry == kept && answer.holds && by_its_key {''',
     '''            match answer.entry == kept && by_its_key {''',
     [known("the_latest_answer_writes_over_the_one_before")]),
    ("K3 a relay given no key holds the change though not connected to the key that answered", KNOWN,
     '''            let by_its_key = of.relay.key.is_some() || connected_by == Some(answer.by);''',
     '''            let by_its_key = true;''',
     [known("a_relay_given_no_key_holds_only_while_connected_to_the_key_that_answered"),
      e2e("a_relay_given_no_key_holds_only_while_connected_to_the_key_that_answered")]),
    ("K4 a mark of another entry is the third state", KNOWN,
     '''        None if of.mark == Some(kept) => Holds::Neither,''',
     '''        None if of.mark.is_some() => Holds::Neither,''',
     [known("a_relay_in_the_third_state_neither_holds_nor_lacks")]),
    ("K5 the third state is taken for holding", KNOWN,
     '''        None if of.mark == Some(kept) => Holds::Neither,''',
     '''        None if of.mark == Some(kept) => Holds::Holds,''',
     [known("a_relay_in_the_third_state_neither_holds_nor_lacks"),
      known("the_mark_is_written_at_phrase_and_at_a_first_start_under_statement_1")]),
    ("K6 an answer that repeats what is kept writes it again", KNOWN,
     '''        let same = of
            .answer
            .is_some_and(|was| was.entry == *entry && was.holds == holds && was.by == *by);''',
     '''        let same = false;''',
     [known("the_latest_answer_writes_over_the_one_before")]),
    ("K7 a later answer does not write over the one before", KNOWN,
     '''        if !same {
            of.answer = Some(Answer {''',
     '''        if of.answer.is_none() {
            of.answer = Some(Answer {''',
     [known("the_latest_answer_writes_over_the_one_before"),
      e2e("each_answer_that_says_writes_over_the_one_before")]),
    ("K8 a mark is written over an answer", KNOWN,
     '''            if of.answer.is_none() {
                of.mark = Some(entry);''',
     '''            if true {
                of.mark = Some(entry);''',
     [known("the_mark_is_written_only_at_its_three_moments")]),
    ("K9 the first start marks under any statement", KNOWN,
     '''            if let Some((entry, 1)) = kept {''',
     '''            if let Some((entry, _)) = kept {''',
     [known("a_removal_made_on_alpha_12_leaves_a_relay_that_never_answers_lacking_after_the_upgrade")]),
    ("K10 every start is a first start", KNOWN,
     '''        if first {
            known.first_started = Some(now);''',
     '''        if true {
            known.first_started = Some(now);''',
     [known("the_mark_is_written_at_phrase_and_at_a_first_start_under_statement_1"),
      known("the_two_times_are_kept")]),
    ("K11 a relay set up no longer is not forgotten", KNOWN,
     '''        known.relays.retain(|of| relays.contains(&of.relay));''',
     '''''',
     [known("what_is_kept_survives_a_restart_and_goes_with_the_relay")]),
    ("K12 when the kept entry came to be kept is written only once", KNOWN,
     '''            Some(entry) if held != Some(entry) => {''',
     '''            Some(entry) if held.is_none() => {''',
     [known("the_two_times_are_kept")]),
    ("K13 a mark does not keep when this version first started", KNOWN,
     '''        // written by this version, which runs now.
        known.first_started.get_or_insert(now);''',
     '''''',
     [known("the_mark_is_written_at_phrase_and_at_a_first_start_under_statement_1")]),
    ("K14 a value that cannot be read is no error", KNOWN,
     '''    Ok(serde_json::from_str(&value).unwrap_or_default())''',
     '''    Ok(serde_json::from_str(&value).unwrap())''',
     [known("a_value_that_cannot_be_read_is_nothing_known")]),
    ("K15 leaving a phrase keeps what was known", ADDING,
     '''    crate::at_relays::known::forget(conn)?;''',
     '''''',
     [known("adding_leave_forgets_it")]),
    ("K16 a hand-over taken writes no mark", ADDING,
     '''        ) {
            crate::at_relays::known::mark(conn, set_up, now)?;
        }''',
     '''        ) {
        }''',
     [known("the_mark_is_written_only_at_its_three_moments")]),
    ("K17 a hand-over refused writes a mark", ADDING,
     '''        if matches!(
            &accepted,
            Accepted::Joined(_) | Accepted::Moved(_) | Accepted::Applied(_)
        ) {''',
     '''        if true {''',
     [known("the_mark_is_written_only_at_its_three_moments")]),
    ("K18 cordelia phrase writes no mark", LEAVING,
     '''        crate::at_relays::known::mark(conn, set_up, now)?;''',
     '''''',
     [known("the_mark_is_written_at_phrase_and_at_a_first_start_under_statement_1"),
      known("adding_leave_forgets_it")]),

    # ── §1, rule 2: what is kept in memory ──────────────────────────
    ("R1 out of reach a second early", REACH,
     '''const OUT_OF_REACH: Duration = Duration::from_secs(OUT_OF_REACH_SECS);''',
     '''const OUT_OF_REACH: Duration = Duration::from_secs(OUT_OF_REACH_SECS - 1);''',
     [reach("a_relay_is_out_of_reach_after_five_minutes_of_failed_attempts")]),
    ("R2 the reference's five minutes are not waited for", REACH,
     '''            .max(self.reference(common).at + OUT_OF_REACH)''',
     '''            .max(since)''',
     [reach("a_relay_is_out_of_reach_after_five_minutes_of_failed_attempts")]),
    ("R3 an attempt need not be within the last five minutes", REACH,
     '''        let until = now.at.min(begun + OUT_OF_REACH);''',
     '''        let until = now.at;''',
     [reach("not_with_no_attempt_in_the_five_minutes")]),
    ("R4 an attempt in flight does not hold it up", REACH,
     '''        if self.out_since.is_some() || self.reached.is_some() || self.in_flight() {''',
     '''        if self.out_since.is_some() || self.reached.is_some() {''',
     [reach("not_while_an_attempt_is_in_flight")]),
    ("R5 a relay that is reached can be out of reach", REACH,
     '''        if self.out_since.is_some() || self.reached.is_some() || self.in_flight() {''',
     '''        if self.out_since.is_some() || self.in_flight() {''',
     [reach("being_reached_ends_it_at_once")]),
    ("R7 out of reach outlives a move of the reference", REACH,
     '''        self.last_begun = None;
        self.out_since = None;''',
     '''        self.last_begun = None;''',
     [reach("a_new_kept_entry_starts_the_five_minutes_again")]),
    ("R8 a new kept entry moves no reference", REACH,
     '''        if inner.kept.is_some_and(|was| was != kept) {
            inner.common = now;''',
     '''        if inner.kept.is_some_and(|was| was != kept) {''',
     [reach("a_new_kept_entry_starts_the_five_minutes_again"),
      reach("a_start_a_sleep_a_new_kept_entry_and_being_reached_each_move_the_reference")]),
    ("R9 a sleep moves no reference", REACH,
     '''        let mut inner = lock(&self.inner);
        inner.common = now;
        for of in inner.relays.values_mut() {
            of.starts_again(now);
        }''',
     '''        let inner = lock(&self.inner);
        drop(inner);''',
     [reach("a_start_a_sleep_a_new_kept_entry_and_being_reached_each_move_the_reference")]),
    ("R10 an answer that says does not make the relay reached", REACH,
     '''                Said::Holds | Said::Lacks => {
                    of.reached = Some(link);''',
     '''                Said::Holds | Said::Lacks => {''',
     [reach("being_reached_ends_it_at_once"),
      e2e("each_answer_that_says_writes_over_the_one_before")]),
    ("R11 a show that says neither leaves the relay reached", REACH,
     '''                    if of.reached == Some(link) {''',
     '''                    if false {''',
     [reach("a_connected_relay_whose_shows_go_unanswered_is_out_of_reach"),
      e2e("show_whole_not_signed_a_reset_and_a_time_out_write_nothing")]),
    ("R12 a connection that closed leaves the relay reached", REACH,
     '''            if of.reached.is_some() && of.reached != open {''',
     '''            if false {''',
     [reach("a_start_a_sleep_a_new_kept_entry_and_being_reached_each_move_the_reference")]),
    ("R13 a dial that connected waits for a show though its connection closed", REACH,
     '''            of.awaiting = None;
            keyless''',
     '''            keyless''',
     [reach("not_while_an_attempt_is_in_flight"),
      p2p("a_dial_that_connected_ends_when_its_connection_goes_before_a_show")]),
    ("R14 a dial that connected is not in flight", REACH,
     '''            if connected {
                of.awaiting = Some(now.at);
            }''',
     '''''',
     [reach("not_while_an_attempt_is_in_flight")]),
    ("R15 a dial at its address for another relay is no attempt", REACH,
     '''                true => of.last_begun = Some(now.at),''',
     '''                true => {}''',
     [reach("another_key_and_a_name_that_does_not_resolve_are_failed_attempts")]),
    ("R16 a failed lookup or wrong-key tick is no attempt", REACH,
     '''        self.with(relay, |of, _, now| of.last_begun = Some(now.at));''',
     '''        self.with(relay, |_, _, _| ());''',
     [reach("another_key_and_a_name_that_does_not_resolve_are_failed_attempts")]),
    ("R17 a relay lacks the change though the device has none to show", REACH,
     '''        inner.shows
            && inner
                .relays''',
     '''        inner
                .relays''',
     [reach("a_relay_that_comes_to_lack_the_change_is_said_once_and_wakes_the_lookups")]),
    ("R18 a relay comes to lack the change though the device has none to show", REACH,
     '''            if *holds == Holds::Lacks && !was_lacking && shows {''',
     '''            if *holds == Holds::Lacks && !was_lacking {''',
     [reach("a_relay_that_comes_to_lack_the_change_is_said_once_and_wakes_the_lookups")]),
    ("R19 a relay that lacks the change is said again at each pass", REACH,
     '''            if *holds == Holds::Lacks && !was_lacking && shows {''',
     '''            if *holds == Holds::Lacks && shows {''',
     [reach("a_relay_that_comes_to_lack_the_change_is_said_once_and_wakes_the_lookups")]),
    ("R20 the lookups are not woken", REACH,
     '''        if woke {
            self.lookups.notify_one();
        }''',
     '''''',
     [reach("a_relay_that_comes_to_lack_the_change_is_said_once_and_wakes_the_lookups"),
      p2p("a_wait_already_set_is_cut_when_the_relay_comes_to_lack_the_change")]),
    ("R21 a relay set up no longer is kept", REACH,
     '''        inner
            .relays
            .retain(|relay, _| each.iter().any(|(set_up, ..)| set_up == relay));''',
     '''''',
     [reach("a_relay_that_comes_to_lack_the_change_is_said_once_and_wakes_the_lookups")]),
    ("R22 a relay that never held has lacked it only since the pass found it", REACH,
     '''            let since = if of.holds.is_none() { common } else { now };''',
     '''            let since = now;''',
     [reach("a_relay_that_never_held_the_change_has_lacked_it_since_the_start")]),
    ("R23 a relay that came to lack it has not lacked it since", REACH,
     '''            Holds::Lacks => {
                self.lacking_since.get_or_insert(now);''',
     '''            Holds::Lacks => {''',
     [reach("a_relay_that_held_and_then_refuses_is_refusing_five_minutes_on")]),
    ("R24 holding it again does not start the refusal's five minutes again", REACH,
     '''            Holds::Holds | Holds::Neither => {
                self.lacking_since = None;
                false''',
     '''            Holds::Holds | Holds::Neither => {
                false''',
     [reach("a_relay_that_held_and_then_refuses_is_refusing_five_minutes_on")]),
    ("R25 refusing is not counted for five minutes", REACH,
     '''            let refused_long = refused_since.is_some_and(|since| five_minutes(since.at));''',
     '''            let refused_long = refused_since.is_some();''',
     [reach("a_relay_that_held_and_then_refuses_is_refusing_five_minutes_on"),
      e2e("a_relay_that_held_and_then_refuses_is_refusing_five_minutes_on")]),
    ("R26 what waits is refused at once", REACH,
     '''                    (true, Some(since)) if five_minutes(since) => Waits::Refused,''',
     '''                    (true, Some(_)) => Waits::Refused,''',
     [reach("what_waits_is_refused_for_five_minutes_before_a_relay_is_stuck"),
      reach("every_unclassed_state_ends_in_a_class")]),
    ("R27 nothing waiting does not start the refusal of what waits again", REACH,
     '''            if !something {
                of.refusing_waits_since = None;
            }''',
     '''''',
     [reach("what_waits_is_refused_for_five_minutes_before_a_relay_is_stuck")]),
    ("R28 taking something does not start the refusal of what waits again", REACH,
     '''        self.with(relay, |of, _, _| of.refusing_waits_since = None);''',
     '''        self.with(relay, |_, _, _| ());''',
     [reach("what_waits_is_refused_for_five_minutes_before_a_relay_is_stuck")]),
    ("R29 a relay that is reached and holds the change with nothing waiting is not OK", REACH,
     '''            Some(Waits::Nothing) => Some(Class::Ok),''',
     '''            Some(Waits::Nothing) => None,''',
     [reach("the_classes_agree_with_the_model_over_every_relay_state")]),
    ("R30 a relay that refuses what waits is not STUCK", REACH,
     '''            Some(Waits::Refused) => Some(Class::Stuck),''',
     '''            Some(Waits::Refused) => Some(Class::Ok),''',
     [reach("the_classes_agree_with_the_model_over_every_relay_state")]),
    ("R31 a relay that moves what waits is OK", REACH,
     '''            Some(Waits::Moving) | None => None,''',
     '''            Some(Waits::Moving) => Some(Class::Ok),
            None => None,''',
     [reach("the_classes_agree_with_the_model_over_every_relay_state")]),
    ("R32 a relay that lacks the change is REFUSING at once", REACH,
     '''        (true, Holds::Lacks) => refused_long.then_some(Class::Refusing),''',
     '''        (true, Holds::Lacks) => Some(Class::Refusing),''',
     [reach("the_classes_agree_with_the_model_over_every_relay_state")]),
    ("R33 a relay that holds it is OUT though not out of reach", REACH,
     '''        (false, Holds::Holds) if out_of_reach => Some(Class::OutHolding),''',
     '''        (false, Holds::Holds) => Some(Class::OutHolding),''',
     [reach("the_classes_agree_with_the_model_over_every_relay_state")]),
    ("R34 a relay that lacks it is OUT though not out of reach", REACH,
     '''        (false, Holds::Lacks) if out_of_reach => Some(Class::OutLacking),''',
     '''        (false, Holds::Lacks) => Some(Class::OutLacking),''',
     [reach("the_classes_agree_with_the_model_over_every_relay_state")]),
    ("R35 a relay in the third state is in a class", REACH,
     '''        (false, Holds::Lacks) if out_of_reach => Some(Class::OutLacking),''',
     '''        (false, Holds::Lacks | Holds::Neither) if out_of_reach => Some(Class::OutLacking),''',
     [reach("the_classes_agree_with_the_model_over_every_relay_state")]),

    # ── The pass: answers, shows and what waits ─────────────────────
    ("D1 the pass tells nothing of what it finds", DEVICE,
     '''        self.observe(relays, stands);
        self.forget_gone(links);''',
     '''        self.forget_gone(links);''',
     [e2e("a_relay_lacks_the_change_only_where_the_device_has_one_to_show")]),
    ("D2 a sleep that the pass finds moves no reference", DEVICE,
     '''        if self.leave.reaches(&names, links) {
            self.reach.slept();
        }''',
     '''        self.leave.reaches(&names, links);''',
     [e2e("a_wake_after_no_connection_does_not_move_another_relays_reference")]),
    ("D3 an answer is not kept in the database", DEVICE,
     '''        let noted = known::note_answer(&lock(&self.state.db), &relay, &entry.id(), holds, &by, now);''',
     '''        let noted: Result<bool, cordelia_api::person::PersonError> = Ok(true);
        let _ = (&relay, &by, now, holds);''',
     [e2e("each_answer_that_says_writes_over_the_one_before"),
      e2e("a_relay_given_a_key_is_known_by_its_name_and_its_key")]),
    ("D4 held or taken does not say that it holds", DEVICE,
     '''                    self.holds(link, entry, true);
                    round.said = Some(Said::Holds);''',
     '''                    self.holds(link, entry, true);
                    round.said = None;''',
     [e2e("each_answer_that_says_writes_over_the_one_before")]),
    ("D5 no room does not say that it lacks it", DEVICE,
     '''                    round.said = Some(Said::Lacks);
                    self.no_room(link, over_allowance, true);''',
     '''                    round.said = None;
                    self.no_room(link, over_allowance, true);''',
     [e2e("each_answer_that_says_writes_over_the_one_before"),
      e2e("a_relay_that_held_and_then_refuses_is_refusing_five_minutes_on")]),
    ("D6 not signed says something", DEVICE,
     '''                        "a relay says that the change entry this device keeps is not signed as it must be"
                    );
                    round.said = None;''',
     '''                        "a relay says that the change entry this device keeps is not signed as it must be"
                    );
                    round.said = Some(Said::Lacks);''',
     [e2e("show_whole_not_signed_a_reset_and_a_time_out_write_nothing"),
      e2e("each_answer_of_the_third_kind_is_a_failed_attempt")]),
    ("D7 show it whole to a whole show says something", DEVICE,
     '''                ShowAnswer::Whole => {
                    round.said = None;''',
     '''                ShowAnswer::Whole => {
                    round.said = Some(Said::Lacks);''',
     [e2e("show_whole_not_signed_a_reset_and_a_time_out_write_nothing"),
      e2e("each_answer_of_the_third_kind_is_a_failed_attempt")]),
    ("D8 a show not answered says something", DEVICE,
     '''"a show was not answered");
                    round.said = None;''',
     '''"a show was not answered");
                    round.said = Some(Said::Lacks);''',
     [e2e("show_whole_not_signed_a_reset_and_a_time_out_write_nothing"),
      e2e("each_answer_of_the_third_kind_is_a_failed_attempt")]),
    ("D9 word of another says nothing", DEVICE,
     '''                    round.said = Some(Said::Lacks);
                    if !short || shows.apart == Some(id) {''',
     '''                    if !short || shows.apart == Some(id) {''',
     [e2e("each_answer_that_says_writes_over_the_one_before")]),
    ("D10 another entry handed says nothing", DEVICE,
     '''                    round.said = Some(Said::Lacks);
                    let Some(another) = Entry::from_wire(&bytes)''',
     '''                    let Some(another) = Entry::from_wire(&bytes)''',
     [e2e("each_answer_that_says_writes_over_the_one_before")]),
    ("D11 a show is no attempt", DEVICE,
     '''                self.reach.show_begins(&self.id_of(link));''',
     '''''',
     [e2e("each_answer_of_the_third_kind_is_a_failed_attempt")]),
    ("D12 a round's end is not told", DEVICE,
     '''        if round.shown {
            self.round_ended(link, &round);
        }''',
     '''''',
     [e2e("each_answer_that_says_writes_over_the_one_before"),
      e2e("each_answer_of_the_third_kind_is_a_failed_attempt")]),
    ("D13 a relay given a key is known by its name alone", DEVICE,
     '''            .find(|id| id.key == Some(link.relay().0))''',
     '''            .find(|_| false)''',
     [e2e("a_relay_given_a_key_is_known_by_its_name_and_its_key")]),
    ("D14 a relay given no key holds by an answer from any key", DEVICE,
     '''                let holds = known::holds(of, kept, open.map(|link| link.relay().0));''',
     '''                let holds = known::holds(of, kept, of.and_then(|of| of.answer).map(|a| a.by));''',
     [e2e("a_relay_given_no_key_holds_only_while_connected_to_the_key_that_answered")]),
    ("D15 a device with no change entry to show has relays that lack it", DEVICE,
     '''        let shows = matches!(stands, Stands::Applied | Stands::Stopped(State::Fork));''',
     '''        let shows = true;''',
     [e2e("a_relay_lacks_the_change_only_where_the_device_has_one_to_show")]),
    ("D16 when the kept entry came to be kept is not noted at a pass", DEVICE,
     '''            if let Err(e) = known::note_kept(&db, now) {''',
     '''            if let Err(e) = Ok::<bool, cordelia_api::person::PersonError>(now > 0) {''',
     [e2e("a_relay_lacks_the_change_only_where_the_device_has_one_to_show")]),
    ("D17 a relay that takes what waits is not told", DEVICE,
     '''            if took {
                self.reach.took_what_waits(&relay);
            }''',
     '''''',
     [e2e("a_relay_that_refuses_what_waits_for_five_minutes_is_stuck")]),
    ("D18 a relay that refuses what waits is not told", DEVICE,
     '''            if refused {
                self.reach.refused_what_waits(&relay);
            }''',
     '''''',
     [e2e("a_relay_that_refuses_what_waits_for_five_minutes_is_stuck")]),
    ("D19 what waits at a relay that is reached is not told", DEVICE,
     '''                    self.reach.waits(&id, waits > 0);''',
     '''                    let _ = (&id, waits);''',
     [e2e("a_relay_that_refuses_what_waits_for_five_minutes_is_stuck")]),
    ("D20 a status says nothing of a relay's reach", DEVICE,
     '''                    reach: self.reach.of(&relay.id()),''',
     '''                    reach: Default::default(),''',
     [e2e("each_answer_that_says_writes_over_the_one_before")]),

    # ── Rule 3, the dial and the lookups ────────────────────────────
    ("P1 a relay that lacks the change is paced as with another connected", P2P,
     '''    any_connected && !reach.is_some_and(|reach| reach.lacks(&reach_id(relay)))''',
     '''    any_connected''',
     [p2p("a_relay_that_lacks_the_change_is_dialled_at_the_pace_of_a_node_cut_off")]),
    ("P2 a failed dial is no attempt", P2P,
     '''        reach.dial_ends(&reach_id(&relay), false);''',
     '''        let _ = (reach, &relay);''',
     [p2p("a_relay_that_lacks_the_change_is_dialled_at_the_pace_of_a_node_cut_off")]),
    ("P3 a wait already set is not cut", P2P,
     '''            *next = (*next).min(latest);''',
     '''            *next = (*next).max(latest);''',
     [p2p("a_wait_already_set_is_cut_when_the_relay_comes_to_lack_the_change")]),
    ("P4 a wait is cut to the cap of a node with another relay", P2P,
     '''    let latest = now + std::time::Duration::from_secs(cordelia_core::protocol::BACKOFF_BASE_SECS);''',
     '''    let latest = now + std::time::Duration::from_secs(cordelia_core::protocol::BACKOFF_MAX_SECS);''',
     [p2p("a_wait_already_set_is_cut_when_the_relay_comes_to_lack_the_change")]),
    ("P5 a name that does not resolve is no attempt", P2P,
     '''            reach.failed(&relay);
            lacking |= reach.lacks(&relay);''',
     '''            lacking |= reach.lacks(&relay);''',
     [p2p("a_lookup_that_resolves_is_no_attempt")]),
    ("P6 a name that resolves is an attempt", P2P,
     '''        if let (false, Some(reach)) = (found, reach) {''',
     '''        if let (_, Some(reach)) = (found, reach) {''',
     [p2p("a_lookup_that_resolves_is_no_attempt")]),
    ("P7 a relay that lacks the change does not speed the lookups", P2P,
     '''    let wait = if have_any && !lacking {''',
     '''    let wait = if have_any {''',
     [p2p("names_are_looked_up_every_half_minute_while_a_relay_that_lacks_the_change_does_not_resolve")]),
    ("P8 a tick that passes a relay with the wrong key over is no attempt", P2P,
     '''        reach.failed(&reach_id(&tried_relay(relay)));''',
     '''        let _ = (reach, relay);''',
     [p2p("a_relay_with_the_wrong_key_where_another_is_connected_is_out_of_reach_with_no_dial")]),
    ("P9 the relays a mark is written for are not said", P2P,
     '''    own.set_up_as(relays.iter().map(Relay::id).collect());''',
     '''''',
     [p2p("a_same_relay_name_is_never_one")]),
    ("P10 a relay is not given its key", P2P,
     '''                key: relay.key,
                link,''',
     '''                key: None,
                link,''',
     [p2p("a_same_relay_name_is_never_one")]),
    # ── The review's fixes: a dial ended for the relays it was begun
    # for, and bounded; the wiring of the dial loop ────────────────────
    ("F1 a dial lost is never given up", REACH,
     '''        let mut ended = self.dials.iter().map(ends).filter(|end| *end <= now).max();
        self.dials.retain(|begun| ends(begun) > now);''',
     '''        let mut ended = None;''',
     [reach("a_dial_whose_result_is_lost_is_given_up_after_five_minutes")]),
    ("F2 a connection that waits for a show is never given up", REACH,
     '''        if let Some(end) = self.awaiting.as_ref().map(ends).filter(|end| *end <= now) {''',
     '''        if let Some(end) = None::<Instant> {''',
     [reach("a_dial_whose_result_is_lost_is_given_up_after_five_minutes")]),
    ("F3 a relay is out of reach before its lost dial is given up", REACH,
     '''            .max(given_up.unwrap_or(since));''',
     '''            .max(since);
        let _ = given_up;''',
     [reach("a_dial_whose_result_is_lost_is_given_up_after_five_minutes")]),
    ("F4 a relay whose address moved is not ended when its dial is answered", P2P,
     '''    for moved in begun.into_iter().filter(|tried| !judged.contains(tried)) {''',
     '''    for moved in begun.into_iter().filter(|_| false) {''',
     [p2p("a_dial_ends_for_the_relays_it_was_begun_for")]),
    ("F5 a relay whose address moved is not ended when its dial fails", P2P,
     '''    for begun in dialling.remove(&addr).unwrap_or_default() {''',
     '''    for begun in Vec::<TriedRelay>::new() {''',
     [p2p("a_dial_ends_for_the_relays_it_was_begun_for")]),
    ("F6 a dial does not keep the relays it was begun for", P2P,
     '''    dialling.insert(relay.addr, at_its_address.map(tried_relay).collect());''',
     '''    let _ = at_its_address;''',
     [p2p("a_dial_ends_for_the_relays_it_was_begun_for")]),
    ("M1 the dial loop begins no attempt where it dials", P2P,
     '''        reach.dial_begins(&reach_id(&id));''',
     '''        let _ = (reach, &id);''',
     [p2p("a_dial_that_the_loop_begins_is_in_flight")]),
    ("M2 a dial that connected is not ended", P2P,
     '''            reach.dial_ends(&reach_id(&tried_relay(relay)), true);''',
     '''            let _ = (reach, relay);''',
     [p2p("a_dial_that_connected_ends_when_its_connection_goes_before_a_show")]),
    ("M3 the dial loop does not see a connection gone", P2P,
     '''        reach.connection(&reach_id(&id), None);''',
     '''        let _ = (reach, &id);''',
     [p2p("a_dial_that_connected_ends_when_its_connection_goes_before_a_show")]),
    ("M5 a relay that closed at once is paced as with another connected", P2P,
     '''    let another = paced_with_another(tick.any_connected, reach, &id);''',
     '''    let another = tick.any_connected;''',
     [p2p("a_relay_that_lacks_the_change_and_closed_at_once_is_dialled_within_half_a_minute")]),
    ("M6 a refusal of the messages channel counts as one of what waits", DEVICE,
     '''    if *kind == Kind::Messages {
        return (false, false);
    }''',
     '''''',
     [(NODE, "device_entries::tests::what_waits_is_heard_of_memory_and_not_of_messages")]),
    ("F7 a new kept entry leaves a relay reached", REACH,
     '''                if of.reached.take().is_some() {
                    of.last_reached = Some(now);
                }''',
     '''''',
     [reach("a_new_kept_entry_ends_reached")]),
    ("L1 a relay given no key holds the change with no connection until the next pass", REACH,
     '''            keyless && of.holds == Some(Holds::Holds) && of.holds_now(Holds::Lacks, now)''',
     '''            let _ = (keyless, now);
            false''',
     [reach("a_relay_given_no_key_lacks_the_change_once_its_connection_is_gone")]),
    ("L2 an answer that it lacks the change is not believed unwritten", DEVICE,
     '''        let holds = if said == Said::Lacks {''',
     '''        let holds = if false {''',
     [e2e("an_answer_that_it_lacks_the_change_is_believed_though_it_was_not_written")]),
    ("L3 a pass's stale read is written over what a show said", REACH,
     '''            if of.shown > read && of.holds.is_some() {
                continue;
            }''',
     '''''',
     [reach("a_show_that_ends_while_a_pass_reads_stands_over_what_it_read")]),
    ("L4 a start after an unreadable value keeps no first start", KNOWN,
     '''        // start is the earliest this version is known to have started.
        known.first_started.get_or_insert(now);''',
     '''''',
     [known("a_value_that_cannot_be_read_is_nothing_known")]),
    ("L7 leaving a phrase forgets when this version first started", KNOWN,
     '''    let first_started = read(conn)?.first_started;''',
     '''    let first_started: Option<i64> = None;''',
     [known("adding_leave_forgets_it")]),
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
