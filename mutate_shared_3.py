#!/usr/bin/env python3
"""Mutation checks for slice 3 of a shared channel: the person's list, in
the personal channel, with schema step 20 (decision 2026-10-10 section 3.4,
with the read of 3.5 at a recovery, and the refusal of 2.2 in `cordelia
sync map`): taking an act, the order with its last tie-break by the act's
bytes, the dating with its count at the time bound and with removed keys'
times left out, copies, items not in force, drops and moves that take no
place, the bounds with makers that count first, fresh lists, freeing,
coming back, the recovery's read, and what a device keeps of it. Since the
second review: an act of a key the device does not know, which hides
the older acts on its item, and undoes that need no place. A part
for each rule of the slice: put each fault in, and confirm the test named
for it fails on an assertion. Run from the root of a checkout that
nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
LISTS = 'crates/cordelia-api/src/lists.rs'
SYNC = 'crates/cordelia-api/src/sync.rs'
LEAVING = 'crates/cordelia-api/src/leaving.rs'
SCHEMA = 'crates/cordelia-storage/src/schema.rs'
STORE = 'crates/cordelia-storage/src/shared_lists.rs'
ACTS = 'crates/cordelia-crypto/src/acts.rs'
ORIG = {f: open(f).read() for f in (LISTS, SYNC, LEAVING, SCHEMA, STORE, ACTS)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
API = ("cordelia-api", ["--lib"])
STORAGE = ("cordelia-storage", ["--lib"])
CRYPTO = ("cordelia-crypto", ["--lib"])
def lists(test): return (API, "lists::tests::" + test)
def sync(test): return (API, "sync::tests::" + test)
def leaving(test): return (API, "leaving::tests::" + test)
def schema(test): return (STORAGE, "schema::tests::" + test)
def store(test): return (STORAGE, "shared_lists::tests::" + test)
def acts(test): return (CRYPTO, "acts::tests::" + test)

MAKER = lists("every_act_names_its_maker_and_a_copy_keeps_it")
NOT_TAKEN = lists("an_act_whose_signature_fails_or_whose_maker_was_never_a_device_is_not_taken")
VALID = lists("which_makers_are_valid_comes_from_the_statement_alone")
BYTES = lists("two_acts_alike_but_for_their_bytes_are_ordered_by_them_on_every_device")
ORDER = lists("two_acts_on_one_item_are_ordered_by_time_maker_count_key_and_bytes")
DATED = lists("a_new_act_is_dated_above_what_the_device_holds")
AHEAD = lists("a_word_dated_ahead_is_followed_by_the_next_act")
REMOVED_LIFT = lists("the_acts_of_a_removed_key_lift_the_dating_of_no_other_item")
AT_BOUND = lists("an_act_at_the_bound_leaves_room_to_undo_it")
TWO_AT_BOUND = lists("two_acts_after_an_undo_at_the_bound_each_take_effect")
FREED_BOUND = lists("a_freed_act_at_the_bound_holds_back_what_orders_at_or_below_it")
FAR = lists("a_fetched_time_far_ahead_refuses_nothing")
FRESH = lists("freshness_goes_by_first_holding_and_the_fetch")
FIRST_HELD = lists("a_list_first_held_90_days_before_is_not_fresh_whatever_its_fetched_time")
TAKEN_FIRST = lists("an_act_taken_in_the_place_of_another_is_first_held_when_it_is_taken")
PLACE = lists("a_drop_and_a_move_take_no_place")
BOUND = lists("past_a_bound_the_undone_items_stay")
FREES = lists("an_undone_act_frees_its_place_90_days_after_it_was_first_held")
NOBODY = lists("a_drop_of_a_channel_nobody_filed_is_not_taken")
HELD_ITSELF = lists("a_drop_of_a_channel_this_device_held_is_taken_after_it_freed_its_own")
REFUSED = lists("an_act_is_refused_past_its_part_and_where_it_has_nothing_to_do")
WRITES = lists("a_device_writes_its_list_at_an_act_and_at_a_whole_fetch_only_where_it_must")
AWAY = lists("a_device_away_for_more_than_90_days_brings_nothing_back")
NO_RELAY = lists("an_act_made_with_no_relay_survives_coming_back")
OWN_FRESH = lists("a_device_whose_own_list_is_fresh_takes_nothing_out")
OWN_ENTRY = lists("a_list_is_read_only_from_its_writers_own_entry_under_the_statement")
RECOVERY = lists("a_recovery_reads_the_lists_by_the_newest_fetch_of_devices_not_in_other_hands")
LISTS_IN = lists("the_lists_a_recovery_reads_are_each_shown_devices_own")
NEVER_HAD = lists("an_act_of_a_key_the_person_never_had_hides_and_takes_no_place")
SETTLED = lists("a_device_added_after_a_settlement_holds_what_the_older_devices_hold")
UNDO_NO_PLACE = lists("undoing_a_copy_not_in_force_needs_no_place")
HIDES_AT_RECOVERY = lists("at_a_recovery_an_act_of_a_key_no_device_is_hides_its_item")
IN_FORCE = lists("a_place_is_taken_only_by_an_item_in_force")
UNDO_NOTHING = lists("an_undo_of_what_nobody_did_is_not_taken")
BEFORE_UNDOES = lists("past_a_bound_the_makers_that_count_come_before_a_removed_keys_undoes")
BEHIND = lists("a_list_whose_clock_is_90_days_behind_is_named_and_not_taken")
LEFT_BACK = lists("a_device_that_comes_back_takes_out_what_it_left_out_too")
DB_ERROR = lists("a_whole_fetch_that_cannot_read_the_database_says_so")
MAP = sync("sync_map_refuses_a_name_a_shared_channel_is_filed_under")
FORGETS = leaving("test_a_device_that_forgets_keeps_its_names_and_nothing_else_of_its_person")
STEP = schema("each_step_of_this_record_adds_its_tables_and_changes_no_older_row")
STEP_BOUNDS = schema("step_20s_bounds_are_those_of_protocol_rs")
BEFORE = schema("the_version_before_stops_on_a_database_stepped_past_19")
FROM_ANY = schema("test_a_database_stepped_from_any_version_has_what_every_later_step_makes")
KEPT = store("what_is_kept_of_a_list_is_read_back_and_replaced")
BY_ITEM = store("first_holding_and_freed_acts_are_kept_by_item")
WRITTEN = acts("an_acts_bytes_are_those_a_list_writes_for_it")

# The count of the order, as it is written.
COUNT_AT_BOUND = '''            count: if time == SHARED_ACT_TIME_MAX {
                count
            } else {
                0
            },'''

# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # ── Which acts are in force ──
    ("L01 an act of a key in no list is in force", LISTS,
     '''        self != Maker::InNoList''',
     '''        true''',
     [VALID]),
    ("L02 no maker counts", LISTS,
     '''        if self.counting.counts(key) {''',
     '''        if false {''',
     [MAKER, VALID]),
    ("L03 a removed key's acts are not in force", LISTS,
     '''        } else if self.removed.contains(key) {''',
     '''        } else if false {''',
     [VALID]),
    # ── The order ──
    ("L04 whether the maker counts orders before the time", LISTS,
     '''struct Order {
    time: u64,
    counts: bool,''',
     '''struct Order {
    counts: bool,
    time: u64,''',
     [ORDER]),
    ("L06 the count orders below the bound too", LISTS,
     COUNT_AT_BOUND,
     '''            count,''',
     [ORDER]),
    ("L07 the count orders nothing at the bound", LISTS,
     COUNT_AT_BOUND,
     '''            count: count & 0,''',
     [TWO_AT_BOUND, ORDER]),
    ("L08 the maker's key orders nothing", LISTS,
     '''            maker,
            written,
        }''',
     '''            maker: [0; 32],
            written,
        }''',
     [MAKER, ORDER]),
    ("L09 two acts alike but for their bytes are not ordered by them", LISTS,
     '''            maker,
            written,
        }''',
     '''            maker,
            written: written[..0].to_vec(),
        }''',
     [BYTES, ORDER]),
    ("L10 the oldest act is taken", LISTS,
     '''    ordered.sort_by(|a, b| b.0.cmp(&a.0));''',
     '''    ordered.sort_by(|a, b| a.0.cmp(&b.0));''',
     [AHEAD, MAKER]),
    # ── Drops of channels nobody filed ──
    ("L16 a channel whose drop the device freed does not admit a drop", LISTS,
     '''        .chain(lists.freed.keys().cloned())
''',
     '''''',
     [HELD_ITSELF]),
    # ── Freed acts ──
    ("L17 a freed act holds nothing back", LISTS,
     '''.is_none_or(|floor| Order::of_act(act, makers) > *floor)''',
     '''.is_none_or(|_| true)''',
     [FREES, FREED_BOUND]),
    ("L18 a freed act does not hold back an act at its own order", LISTS,
     '''.is_none_or(|floor| Order::of_act(act, makers) > *floor)''',
     '''.is_none_or(|floor| Order::of_act(act, makers) >= *floor)''',
     [FREED_BOUND]),
    ("L19 a freed act is kept whatever carries it", LISTS,
     '''    lists.freed.retain(|key, _| carried.contains(key));''',
     '''    let _ = &carried;''',
     [FREES]),
    ("L20 a freed act is let go while a fresh list carries it", LISTS,
     '''    lists.freed.retain(|key, _| carried.contains(key));''',
     '''    lists.freed.retain(|key, _| carried.contains(key) && false);''',
     [FREES, FREED_BOUND, TWO_AT_BOUND]),
    ("L21 an act held keeps no first holding", LISTS,
     '''        let at = lists.first_held_of(&act).unwrap_or(now);''',
     '''        let at = now;''',
     [FREES, FRESH]),
    ("L22 an undone act is freed a second late", LISTS,
     '''        if act.undone() && now - at >= KEPT_SECS {''',
     '''        if act.undone() && now - at > KEPT_SECS {''',
     [FREES, FRESH, TAKEN_FIRST]),
    ("L23 an act in force is freed too", LISTS,
     '''        if act.undone() && now - at >= KEPT_SECS {''',
     '''        if now - at >= KEPT_SECS {''',
     [AWAY]),
    ("L24 a new act on an item keeps the old act's first holding", LISTS,
     '''        (*signature == act.signature()).then_some(*at)''',
     '''        Some(*at).filter(|_| *signature == *signature)''',
     [TAKEN_FIRST]),
    # ── Places and bounds ──
    ("L25 the filings' bound is one more", LISTS,
     '''            SHARED_MAX_CHANNELS,
            false,''',
     '''            SHARED_MAX_CHANNELS + 1,
            false,''',
     [BOUND, PLACE]),
    ("L26 a drop past 64 is left out, not freed", LISTS,
     '''            SHARED_MAX_DROPPED,
            true,''',
     '''            SHARED_MAX_DROPPED,
            false,''',
     [BOUND]),
    ("L27 the drops' bound is one more", LISTS,
     '''            SHARED_MAX_DROPPED,
            true,''',
     '''            SHARED_MAX_DROPPED + 1,
            true,''',
     [BOUND]),
    ("L28 the subscriptions' bound is one more", LISTS,
     '''            SHARED_MAX_SUBSCRIPTIONS,
            false,''',
     '''            SHARED_MAX_SUBSCRIPTIONS + 1,
            false,''',
     [BOUND]),
    ("L29 the labels' bound is one more", LISTS,
     '''            SHARED_MAX_LABELS,
            false,''',
     '''            SHARED_MAX_LABELS + 1,
            false,''',
     [BOUND]),
    ("L30 past a bound the undone items do not come first", LISTS,
     '''                !act.undone(),''',
     '''                act.undone() && false,''',
     [BOUND]),
    ("L32 past a bound the oldest come first", LISTS,
     '''                Reverse(Order::of_act(act, makers)),''',
     '''                Order::of_act(act, makers),''',
     [BOUND]),
    ("L33 past a bound nothing is left out", LISTS,
     '''.extend(left.into_iter().take(most).cloned());''',
     '''.extend(left.into_iter().take(0).cloned());''',
     [IN_FORCE]),
    ("L34 a move leaves the old channel filed", LISTS,
     '''                filing.and_then(|filing| Ok(vec![AnyAct::Filing(filing), AnyAct::Drop(drop?)]))''',
     '''                filing.and_then(|filing| Ok(vec![AnyAct::Filing(filing)]).and_then(|v| drop.map(|_| v)))''',
     [PLACE]),
    # ── What an act is refused for ──
    ("L43 what cannot be written is an error, not a refusal", LISTS,
     '''            Err(e) => return Ok(Done::Refused(Refused::NotWritten(e))),''',
     '''            Err(e) => return Err(PersonError::Held(e.to_string())),''',
     [REFUSED]),
    # ── When a list is written ──
    ("L44 an act is not written at once", LISTS,
     '''        write_list(conn, identity, &standing, &mut lists, fetched, now)?;
        lists.save(conn)?;
        Ok(Done::Made(made))''',
     '''        let _ = fetched;
        lists.save(conn)?;
        Ok(Done::Made(made))''',
     [WRITES, MAKER]),
    ("L45 an act is written with no fetched time", LISTS,
     '''            .map_or(lists.list.fetched, |at| u64::try_from(at).unwrap_or(0));''',
     '''            .map_or(lists.list.fetched, |_| 0);''',
     [WRITES]),
    ("L46 a whole fetch keeps no time", LISTS,
     '''        lists.fetched_at = Some(now);
        take_lists''',
     '''        take_lists''',
     [WRITES]),
    ("L47 a list is not written where what it took changed it", LISTS,
     '''        let wrote = changed || due;''',
     '''        let wrote = due && changed | true;''',
     [WRITES, MAKER]),
    ("L48 a list is written again a second after its 30 days", LISTS,
     '''now - written >= WRITTEN_AGAIN_SECS''',
     '''now - written > WRITTEN_AGAIN_SECS''',
     [WRITES]),
    ("L49 a list whose fetched time is ahead of the clock is not written again", LISTS,
     ''' || before.fetched > fetched''',
     ''' || before.fetched > fetched && false''',
     [WRITES]),
    ("L50 a whole fetch writes the fetched time it wrote before", LISTS,
     '''        let fetched = u64::try_from(now).unwrap_or(0);
        let due''',
     '''        let fetched = before.fetched;
        let due''',
     [WRITES]),
    # ── Fresh ──
    ("L51 freshness goes by the fetched time alone", LISTS,
     '''    now - first_held < KEPT_SECS && now - fetched < KEPT_SECS''',
     '''    first_held == first_held && now - fetched < KEPT_SECS''',
     [FIRST_HELD]),
    ("L52 freshness goes by the first holding alone", LISTS,
     '''    now - first_held < KEPT_SECS && now - fetched < KEPT_SECS''',
     '''    now - first_held < KEPT_SECS && fetched == fetched''',
     [AWAY, FRESH]),
    ("L53 a list is fresh a second longer", LISTS,
     '''    now - first_held < KEPT_SECS && now - fetched < KEPT_SECS''',
     '''    now - first_held <= KEPT_SECS && now - fetched <= KEPT_SECS''',
     [FIRST_HELD]),
    ("L54 a list is taken fresh or not", LISTS,
     '''    let fresh: Vec<&Read> = others.iter().filter(|read| read.is_fresh(now)).collect();
    let mut candidates''',
     '''    let fresh: Vec<&Read> = others.iter().collect();
    let mut candidates''',
     [AWAY, FRESH]),
    ("L55 the device's own list is no candidate", LISTS,
     '''    let mut candidates = lists.held();''',
     '''    let mut candidates: Vec<AnyAct> = Vec::new();''',
     [WRITES]),
    ("L56 the others' lists are no candidates", LISTS,
     '''        candidates.extend(acts_of(&read.list));''',
     '''        let _ = read;''',
     [MAKER]),
    ("L57 a list is first held when the device was set up", LISTS,
     '''                first_held: held.stored_at,''',
     '''                first_held: held.stored_at & 0,''',
     [MAKER]),
    ("L58 the device's own list is read as another's", LISTS,
     '''        if writer == *own {
            continue;
        }''',
     '''        let _ = own;''',
     [FRESH]),
    ("L59 a list in a band above the statement's is read", LISTS,
     '''        if band(entry.rev) > standing.number() {''',
     '''        if band(entry.rev) > standing.number() && false {''',
     [OWN_ENTRY]),
    # ── Coming back ──
    ("L60 a device whose own list is fresh comes back", LISTS,
     '''        if lists.written_at.is_some() && !lists.own_is_fresh(now) {''',
     '''        if lists.written_at.is_some() {''',
     [OWN_FRESH]),
    ("L61 a device never comes back", LISTS,
     '''        if lists.written_at.is_some() && !lists.own_is_fresh(now) {''',
     '''        if lists.written_at.is_some() && false {''',
     [AWAY]),
    ("L62 coming back takes out what was not held at the previous fetch", LISTS,
     '''            .is_some_and(|(previous, first_held)| first_held <= previous);''',
     '''            .is_some_and(|_| true);''',
     [NO_RELAY]),
    ("L63 coming back takes out an item fetched before its time", LISTS,
     '''                .any(|read| read.list.fetched > act.time() && !read.carries(&act.key()))''',
     '''                .any(|read| !read.carries(&act.key()))''',
     [OWN_FRESH]),
    ("L64 coming back takes out what a fresh list carries", LISTS,
     '''                .any(|read| read.list.fetched > act.time() && !read.carries(&act.key()))''',
     '''                .any(|read| read.list.fetched > act.time())''',
     [OWN_FRESH]),
    ("L65 coming back compares lists that are not fresh", LISTS,
     '''    let fresh: Vec<&Read> = others.iter().filter(|read| read.is_fresh(now)).collect();
    let let_go''',
     '''    let fresh: Vec<&Read> = others.iter().collect();
    let let_go''',
     [FIRST_HELD]),
    # ── The dating ──
    ("L66 an act is dated at, not above, what it follows", LISTS,
     '''        .saturating_add(1)
        .min(SHARED_ACT_TIME_MAX);''',
     '''        .min(SHARED_ACT_TIME_MAX);''',
     [AHEAD, DATED]),
    ("L67 an act is not dated past the device's clock", LISTS,
     '''    let time = now
        .max(of_item)''',
     '''    let time = (now & 0)
        .max(of_item)''',
     [DATED]),
    ("L68 the item's own newest time is left out", LISTS,
     '''        .max(of_item)
''',
     '''        .max(of_item & 0)
''',
     [DATED, REMOVED_LIFT]),
    ("L69 an act freed on the item is left out of its dating", LISTS,
     '''        .chain(freed.map(|freed| freed.time))''',
     '''        .chain(freed.map(|freed| freed.time & 0))''',
     [DATED]),
    ("L70 other acts are taken as far ahead as they say", LISTS,
     '''        .map(|time| time.min(ahead))''',
     '''        .map(|time| time.max(ahead & 0))''',
     [DATED, REMOVED_LIFT]),
    ("L72 the fetched times held are left out of the dating", LISTS,
     '''        .chain(std::iter::once(lists.list.fetched));''',
     '''        .chain(std::iter::once(lists.list.fetched))
        .filter(|_| false);''',
     [DATED]),
    ("L73 an act is dated past the bound", LISTS,
     '''        .saturating_add(1)
        .min(SHARED_ACT_TIME_MAX);''',
     '''        .saturating_add(1);''',
     [AT_BOUND, DATED]),
    ("L74 an act below the bound has a count", LISTS,
     '''        return (time, 0);''',
     '''        return (time, 1);''',
     [TWO_AT_BOUND, DATED]),
    ("L76 a freed act's count is left out", LISTS,
     '''                .filter(|freed| freed.time == SHARED_ACT_TIME_MAX)''',
     '''                .filter(|_| false)''',
     [DATED]),
    ("L77 a freed act's count below the bound is counted", LISTS,
     '''                .filter(|freed| freed.time == SHARED_ACT_TIME_MAX)''',
     '''                .filter(|_| true)''',
     [DATED]),
    ("L78 the count is not one above the highest", LISTS,
     '''count.saturating_add(1).min(SHARED_ACT_TIME_MAX)''',
     '''count.min(SHARED_ACT_TIME_MAX)''',
     [TWO_AT_BOUND, DATED]),
    ("L79 the count passes the bound", LISTS,
     '''count.saturating_add(1).min(SHARED_ACT_TIME_MAX)''',
     '''count.saturating_add(1)''',
     [DATED]),
    # ── What a device says of its lists ──
    ("L80 a filing not in force is a name filed", LISTS,
     '''.any(|(act, maker)| maker.in_force() && act.item.name == name))''',
     '''.any(|(act, _)| act.item.name == name))''',
     [VALID]),
    ("L81 a device names every list as ahead of its clock", LISTS,
     '''        .filter(|read| read.list.fetched > now)''',
     '''        .filter(|read| read.list.fetched >= now & 0)''',
     [FRESH]),
    # ── A recovery's read ──
    ("L82 a list in someone else's hands sets the newest time", LISTS,
     '''            .filter(|(_, answered, _)| hands_too || *answered != Answered::Hands)''',
     '''            .filter(|(_, answered, _)| hands_too || *answered == *answered)''',
     [RECOVERY]),
    ("L83 a fetched time ahead of the recovery's clock is taken as it says", LISTS,
     '''i64::try_from(list.fetched).unwrap_or(i64::MAX).min(now);''',
     '''i64::try_from(list.fetched).unwrap_or(i64::MAX);''',
     [RECOVERY]),
    ("L84 a recovery takes every list, fresh or not", LISTS,
     '''        .filter(|(_, _, list)| newest - at(list) < KEPT_SECS)''',
     '''        .filter(|(_, _, list)| newest >= at(list) - KEPT_SECS * 0 || true)''',
     [RECOVERY]),
    ("L85 a recovery of only lists in someone else's hands takes nothing", LISTS,
     '''newest_of(false).or_else(|| newest_of(true))''',
     '''newest_of(false).or_else(|| newest_of(false))''',
     [RECOVERY]),
    ("L86 a recovery reads another key's entry in a device's slot", LISTS,
     ''' && entry.author == *key)''',
     ''')''',
     [LISTS_IN]),
    ("L87 a recovery reads a device's oldest entry", LISTS,
     '''            .max_by_key(|entry| entry.rev);''',
     '''            .min_by_key(|entry| entry.rev);''',
     [LISTS_IN]),
    # ── Makers, places and undoes, since the review ──
    ("M01 an act of a key the person never had is taken", LISTS,
     '''        makers.maker(&act.maker()).is_some() && self.holds(act)''',
     '''        makers.maker(&act.maker()).is_some() | true && self.holds(act)''',
     [NEVER_HAD]),
    ("M02 a key a statement left out is a key never had", LISTS,
     '''        } else if self.left_out.contains(key) {''',
     '''        } else if self.left_out.contains(key) && false {''',
     [VALID]),
    ("M03 the keys a statement left out are not read", LISTS,
     '''            left_out: left_out.into_iter().map(|left| left.key).collect(),''',
     '''            left_out: left_out.into_iter().map(|left| left.key).take(0).collect(),''',
     [VALID]),
    ("M04 a removed key ranks with the makers that count past a bound", LISTS,
     '''            Some(Maker::Removed) => 1,''',
     '''            Some(Maker::Removed) => 0,''',
     [BEFORE_UNDOES, PLACE]),
    ("M05 past a bound the makers that count do not come first", LISTS,
     '''                makers.rank(&act.maker()),
                !act.undone(),''',
     '''                makers.rank(&act.maker()) & 0,
                !act.undone(),''',
     [PLACE, BEFORE_UNDOES]),
    ("M06 past a bound the undone items come before the makers that count", LISTS,
     '''                makers.rank(&act.maker()),
                !act.undone(),''',
     '''                !act.undone() as u8,
                makers.rank(&act.maker()),''',
     [BEFORE_UNDOES]),
    ("M07 whether the maker counts orders nothing", LISTS,
     '''            counts: makers.maker(&maker) == Some(Maker::Counts),''',
     '''            counts: makers.maker(&maker) == makers.maker(&maker),''',
     [AT_BOUND, TWO_AT_BOUND, ORDER]),
    ("M08 an act is taken whether or not it holds", LISTS,
     '''    let first = acts.find(|act| checked.holds(act))?;''',
     '''    let first = acts.next()?;''',
     [NOT_TAKEN]),
    ("M09 an act is taken whatever its signature, once checked", LISTS,
     '''            .or_insert_with(|| act.holds())''',
     '''                .or_insert_with(|| true)''',
     [NOT_TAKEN]),
    ("M10 an undo of what nobody did is taken", LISTS,
     '''            .filter(|act| !act.undone() || done.contains(&key) || held_items.contains(&key))''',
     '''            .filter(|_| true)''',
     [NOBODY, UNDO_NOTHING]),
    ("M11 what another list does admits no undo", LISTS,
     '''!act.undone() || done.contains(&key) || held_items.contains(&key)''',
     '''!act.undone() || done.is_empty() && false || held_items.contains(&key)''',
     [NOBODY]),
    ("M12 what the device holds or held admits no undo", LISTS,
     '''!act.undone() || done.contains(&key) || held_items.contains(&key)''',
     '''!act.undone() || done.contains(&key) || held_items.is_empty() && false''',
     [HELD_ITSELF]),
    ("M13 an act whose signature fails does an item", LISTS,
     '''                .any(|act| !act.undone() && checked.takes(act, makers))''',
     '''                .any(|act| !act.undone())''',
     [NOBODY]),
    ("M14 a removed key's acts lift every item", LISTS,
     '''        .filter(|act| makers.maker(&act.maker()) == Some(Maker::Counts))
        .map(AnyAct::time)''',
     '''        .map(AnyAct::time)''',
     [REMOVED_LIFT]),
    ("M15 the count at the bound counts the acts of any maker", LISTS,
     '''                && act.time() == SHARED_ACT_TIME_MAX
                && makers.maker(&act.maker()) == Some(Maker::Counts)''',
     '''                && act.time() == SHARED_ACT_TIME_MAX''',
     [AT_BOUND, DATED]),
    ("M16 an act the device would not take dates the next", LISTS,
     '''        .filter(|act| checked.takes(act, makers))
        .cloned()''',
     '''        .filter(|act| checked.takes(act, makers) || true)
        .cloned()''',
     [DATED]),
    ("M17 an act whose signature fails dates the next", LISTS,
     '''        .filter(|act| checked.takes(act, makers))
        .cloned()''',
     '''        .filter(|act| makers.maker(&act.maker()).is_some())
        .cloned()''',
     [DATED]),
    ("M18 a part is full one item later", LISTS,
     '''count() >= most && !placed(key)''',
     '''count() > most && !placed(key)''',
     [PLACE, REFUSED]),
    ("M19 an item held again takes a new place", LISTS,
     '''count() >= most && !placed(key)''',
     '''count() >= most''',
     [PLACE, REFUSED]),
    ("M20 an act not in force takes a place", LISTS,
     '''            .filter(|act| makers.maker(&act.maker()).is_some_and(Maker::in_force))''',
     '''            .filter(|act| makers.maker(&act.maker()).is_some())''',
     [IN_FORCE]),
    ("M21 a channel not filed is dropped", LISTS,
     '''            matches!(held_on(&key), Some(AnyAct::Filing(_)))''',
     '''            matches!(held_on(&key), Some(AnyAct::Filing(_)) | None)''',
     [REFUSED]),
    ("M22 a filing left out past a bound is not filed", LISTS,
     '''        let held = lists.held();''',
     '''        let held = acts_of(&lists.list);''',
     [IN_FORCE]),
    ("M23 a move to a channel filed is made", LISTS,
     '''                if placed(&key) {''',
     '''                if placed(&key) && false {''',
     [REFUSED]),
    ("M24 an unsubscription of nothing is made", LISTS,
     '''                if !subscription.subscribed && !subscribed {''',
     '''                if !subscription.subscribed && !subscribed && false {''',
     [REFUSED]),
    ("M25 an unsubscription of an unsubscription is made", LISTS,
     '''                    Some(AnyAct::Subscription(held)) if held.item.subscribed''',
     '''                    Some(AnyAct::Subscription(_))''',
     [REFUSED]),
    ("M26 a removed label of no label is made", LISTS,
     '''                if label.label.is_none() && !labelled {''',
     '''                if label.label.is_none() && !labelled && false {''',
     [REFUSED]),
    ("M27 a removed label of a removed label is made", LISTS,
     '''                    Some(AnyAct::Label(held)) if held.item.label.is_some()''',
     '''                    Some(AnyAct::Label(_))''',
     [REFUSED]),
    ("M28 a database that cannot be read is a fetch that did nothing", LISTS,
     '''            Err(e) => return Err(e),
        };
        let makers = Makers::of(conn, &standing)?;''',
     '''            Err(_) => return Ok(false),
        };
        let makers = Makers::of(conn, &standing)?;''',
     [DB_ERROR]),
    ("M29 a list behind the clock is named however long ago it was first held", LISTS,
     '''        .filter(|read| now - read.first_held < KEPT_SECS && !read.is_fresh(now))''',
     '''        .filter(|read| !read.is_fresh(now))''',
     [BEHIND]),
    ("M30 a fresh list is named as behind", LISTS,
     '''        .filter(|read| now - read.first_held < KEPT_SECS && !read.is_fresh(now))''',
     '''        .filter(|read| now - read.first_held < KEPT_SECS)''',
     [BEHIND]),
    ("M31 coming back keeps what it left out", LISTS,
     '''    let left_out: Vec<AnyAct> = acts_of(&lists.left_out)
        .into_iter()
        .filter(|act| !let_go(act))
        .collect();
    lists.list = list_of(list, lists.list.fetched);
    lists.left_out = list_of(left_out, 0);''',
     '''    lists.list = list_of(list, lists.list.fetched);''',
     [LEFT_BACK]),
    ("M32 a recovery takes no act of a device the person has", LISTS,
     '''                Some(Maker::InNoList) => left_out.push(key),''',
     '''                Some(Maker::InNoList) => {}''',
     [RECOVERY]),
    # ── An act of a key the device does not know, since the second review ──
    ("H01 an act of a key the device does not know hides nothing", LISTS,
     '''    let first = acts.find(|act| checked.holds(act))?;''',
     '''    let first = acts.find(|act| checked.takes(act, makers))?;''',
     [SETTLED, NEVER_HAD, HIDES_AT_RECOVERY]),
    ("H02 the act that hides an item is taken", LISTS,
     '''    if makers.maker(&first.maker()).is_some() {''',
     '''    if true {''',
     [NEVER_HAD]),
    ("H03 the act held hidden may be one the device would not take", LISTS,
     '''    Some(Newest::Hidden(acts.find(|act| checked.takes(act, makers))))''',
     '''    Some(Newest::Hidden(acts.find(|act| checked.holds(act))))''',
     [NEVER_HAD]),
    ("H04 nothing is held hidden", LISTS,
     '''    Some(Newest::Hidden(acts.find(|act| checked.takes(act, makers))))''',
     '''    Some(Newest::Hidden(None))''',
     [NEVER_HAD]),
    ("H05 what is held hidden is in force", LISTS,
     '''            Some(Newest::Hidden(Some(act))) => hidden.push(act),''',
     '''            Some(Newest::Hidden(Some(act))) => chosen.push(act),''',
     [NEVER_HAD]),
    ("H06 what is held hidden is not kept within a bound", LISTS,
     '''        let mut left: Vec<&AnyAct> = hidden.iter().filter(|act| of_part(act)).collect();''',
     '''        let mut left: Vec<&AnyAct> = Vec::new();''',
     [NEVER_HAD, HIDES_AT_RECOVERY]),
    ("H07 an act lets go of what was held hidden", LISTS,
     '''        let bounded = within_bounds(held, left_out, &makers);''',
     '''        let bounded = within_bounds(held, Vec::new(), &makers);''',
     [NEVER_HAD]),
    ("H08 a recovery lets go of what is held hidden", LISTS,
     '''    let bounded = within_bounds(chosen, hidden, &makers);
    (list_of(bounded.list, 0), list_of(bounded.left_out, 0))''',
     '''    let bounded = within_bounds(chosen, Vec::new(), &makers);
    (list_of(bounded.list, 0), list_of(bounded.left_out, 0))''',
     [HIDES_AT_RECOVERY]),
    ("H09 what is held hidden is first held when it comes back", LISTS,
     '''    for act in &hidden {
        let at = lists.first_held_of(act).unwrap_or(now);
        first_held.insert(act.key(), (act.signature(), at));
    }''',
     '''''',
     [NEVER_HAD]),
    ("H10 an act of a key the device does not know dates nothing", LISTS,
     '''        .filter(|act| act.key() == *key && checked.holds(act))''',
     '''        .filter(|act| act.key() == *key && checked.takes(act, makers))''',
     [DATED]),
    ("H11 an act of a key the device does not know dates every item", LISTS,
     '''        .filter(|act| act.key() == *key && checked.holds(act))''',
     '''        .filter(|act| checked.holds(act))''',
     [DATED]),
    ("H12 an act that does not hold dates its item", LISTS,
     '''        .filter(|act| act.key() == *key && checked.holds(act))''',
     '''        .filter(|act| act.key() == *key)''',
     [DATED]),
    ("U01 an unsubscription needs a place", LISTS,
     '''if subscription.subscribed && full(''',
     '''if full(''',
     [UNDO_NO_PLACE]),
    ("U02 a removed label needs a place", LISTS,
     '''if label.label.is_some() && full(''',
     '''if full(''',
     [UNDO_NO_PLACE]),
    ("U03 a subscription needs no place", LISTS,
     '''if subscription.subscribed && full(''',
     '''if !subscription.subscribed && full(''',
     [UNDO_NO_PLACE]),
    ("U04 a label needs no place", LISTS,
     '''if label.label.is_some() && full(''',
     '''if label.label.is_none() && full(''',
     [UNDO_NO_PLACE]),
    # ── An act's bytes ──
    ("A01 an act's bytes leave out its time, count, maker and signature", ACTS,
     '''        self.write(&mut out, &|_| true)?;
        Ok(out)''',
     '''        self.item.write(&mut out, &|_| true)?;
        Ok(out)''',
     [WRITTEN]),
    # ── sync map ──
    ("Y01 sync map maps a name a shared channel is filed under", SYNC,
     '''        if filed {''',
     '''        if filed && false {''',
     [MAP]),
    ("Y02 sync map asks of another name", SYNC,
     '''crate::lists::is_filed_under(db, &mapping.name)''',
     '''crate::lists::is_filed_under(db, &mapping.folder)''',
     [MAP]),
    # ── A device that leaves its person ──
    ("F01 a device that leaves keeps its lists", LEAVING,
     '''        cordelia_storage::shared_lists::forget_all(conn)?;''',
     '''        let _ = cordelia_storage::shared_lists::forget_all;''',
     [FORGETS]),
    # ── Step 20 ──
    ("S01 the schema is still at step 19", SCHEMA,
     '''pub const SCHEMA_VERSION: u32 = 20;''',
     '''pub const SCHEMA_VERSION: u32 = 19;''',
     [STEP]),
    ("S02 step 20 is not run", SCHEMA,
     '''        migrate_in_one(conn, MIGRATION_V20, 20)?;''',
     '''        let _ = MIGRATION_V20;''',
     [STEP, FROM_ANY]),
    ("S03 a list may be longer than one at every bound", SCHEMA,
     '''AND length(list) >= 13 AND length(list) <= 41341),''',
     '''AND length(list) >= 13 AND length(list) <= 41342),''',
     [STEP_BOUNDS]),
    ("S04 a freed act's time may pass the bound", SCHEMA,
     '''AND time >= 0 AND time <= 1099511627776),''',
     '''AND time >= 0 AND time <= 1099511627777),''',
     [STEP, STEP_BOUNDS]),
    ("S05 a freed act's item may be longer than an ID and a name", SCHEMA,
     '''    item      BLOB NOT NULL CHECK(typeof(item) = 'blob'
                                  AND length(item) >= 32 AND length(item) <= 232),''',
     '''    item      BLOB NOT NULL CHECK(typeof(item) = 'blob'
                                  AND length(item) >= 32 AND length(item) <= 233),''',
     [STEP_BOUNDS]),
    ("S06 two acts freed on one item are kept", SCHEMA,
     '''    freed_at  INTEGER NOT NULL CHECK(typeof(freed_at) = 'integer'),
    PRIMARY KEY (part, item)''',
     '''    freed_at  INTEGER NOT NULL CHECK(typeof(freed_at) = 'integer')''',
     [STEP, BY_ITEM]),
    ("S07 a first holding takes a part there is not", SCHEMA,
     '''    part        INTEGER NOT NULL CHECK(part IN (1, 2, 3)),''',
     '''    part        INTEGER NOT NULL CHECK(part IN (0, 1, 2, 3, 4)),''',
     [STEP]),
    ("S08 a second row of the list is kept", SCHEMA,
     '''    one         INTEGER PRIMARY KEY CHECK(one = 1),''',
     '''    one         INTEGER PRIMARY KEY CHECK(one >= 1),''',
     [STEP]),
    ("S09 a list's value may be a text", SCHEMA,
     '''    list        BLOB NOT NULL CHECK(typeof(list) = 'blob'
''',
     '''    list        BLOB NOT NULL CHECK(1
''',
     [STEP]),
    # ── What a device keeps beside its list ──
    ("T01 a device that forgets keeps its freed acts", STORE,
     '''        "shared_list_freed",
    ] {''',
     '''    ] {''',
     [BY_ITEM]),
    ("T02 the rows of first holding are added to, not replaced", STORE,
     '''    conn.execute("DELETE FROM shared_list_first_held", [])''',
     '''    conn.execute("SELECT 1", [])''',
     [BY_ITEM]),
    ("T03 a later freed act keeps the earlier one's time", STORE,
     '''             time = excluded.time, count = excluded.count, maker = excluded.maker,''',
     '''             count = excluded.count, maker = excluded.maker,''',
     [BY_ITEM]),
    ("T04 what is kept of the list is not replaced", STORE,
     '''             list = excluded.list, left_out = excluded.left_out,''',
     '''             left_out = excluded.left_out,''',
     [KEPT]),
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
