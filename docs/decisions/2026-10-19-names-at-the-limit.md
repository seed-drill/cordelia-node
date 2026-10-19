# Decision: a warning before the personal channel fills a relay's room

**Date**: 2026-10-19
**Status**: Proposed. Not built.
**Cited as**: code comments will cite this record as "decision 2026-10-19", and its rules as "§2, rule 3". The numbers do not change.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md), and **the record of 2026-10-17** is [`2026-10-17-recovery-and-carrying.md`](2026-10-17-recovery-and-carrying.md).
- **A word** is an entry that a device writes in the personal channel under `name/` and a name: a text where it syncs the name, a delete where it has stopped (the record of 2026-10-04, §2.2 and §16).
- **The cap** is what one channel may hold at a relay, `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, 16 MiB (16,777,216 bytes), counted as entries are counted (`entry_cost`: the content and 1,024 more).
- **The channel's total** is the sum of `entry_cost` over every entry that this device's store holds of the personal channel of the statement it has applied: every author's, deletes included, its own that wait to be sent included.
- **Alpha.12** is the release 0.2.0-alpha.12, and **this version** is the version of the node that first carries what is below.
- Examples say laptop and desktop.

---

## 0. What this is

The personal channel can outgrow what a relay holds of one channel. Each device writes one word for each name it syncs, and a relay counts each word at 1,280 bytes. 64 devices with 256 names each write 20 MiB against a cap of 16 MiB, and the relay refuses the last quarter. Nothing bounds the names.

The exposure is small: the channel fills near 50 devices at 256 names each, or 4 devices at 3,274 names each. Each refusal added to the paths that write words (a map, the sync cycle, joining, a recovery, a statement) brought faults of its own (§8). So this record refuses nothing. It changes three things:

1. **A warning.** The status turns amber where the channel's total passes a line 4 MiB below the cap. The words say what fills it and what helps.
2. **A true line for a refusal.** `cordelia devices` no longer says that a refused entry was for a new channel at a full relay.
3. **A stated limit.** Nothing stops a new name. Past the cap the relay refuses what grows the channel, and the record says what a person then sees and can do.

Nothing on the wire changes, and no relay changes.

## 1. What the code does today

**A word is one entry for each device and each name it lists.** Its slot is the HMAC of `name/` and the name (`names::word_name`, `crates/cordelia-api/src/names.rs:77`). The slot holds no key: every device that syncs a name writes in the same slot, each as its own author. Several folders mapped to one name on one device are one word.

**Where a word is written.** Every new word goes through `names::say` (`names.rs:148`):

- each sync cycle, for every mapped folder (`name_channel`, `crates/cordelia-sync/src/claude.rs:897`);
- a map: the route stores the mapping (`sync.rs:1023`), then `names_follow` calls `hold_mapped` (`sync.rs:507`);
- when a device comes to follow a phrase (`leaving.rs:337`) or is accepted (`adding.rs:714`), through `hold_mapped`, in the transaction that gives it the secret, before it has read the channel;
- a carry, and a recovery (`hold_for_a_carry`, `recover.rs:1094`).

At a statement a device carries its own words, deletes included, into the new channel by another path (`Carry::channel`, `person.rs:1541`), each stored at the time of the carry.

**A word is always counted at 1,280 bytes.** It says the name's length (2 bytes), `name/` and a name of at most 200 bytes (`sync::valid_sync_name`, `crates/cordelia-api/src/sync.rs:220`), the value's kind (1), an empty text's length (2) and an empty chain (2): at most 212 bytes, 240 with the nonce and the tag (`protocol.rs:330`). The content is padded to a power of two from 256 (`crates/cordelia-crypto/src/entry.rs:615`, `protocol.rs:950`), so every word, and every delete of one, is 256 bytes, counted at 256 + 1,024 (`protocol.rs:341`, `entry_cost` at 347).

**The channel grows with names, not with changes.** A relay keeps the newest revision for each author in each slot, and a write that makes a channel hold no more is always taken (`crates/cordelia-storage/src/relay.rs:548` to `579`). A delete keeps its size. A relay sweeps a slot only where every entry in it is a delete it has held 90 days, and a device sweeps the personal channel the same way. So a stopped name stays counted while any device syncs it, and for 90 days after. A statement re-stores each device's own deletes at the time of the carry, so their 90 days start again.

**What else is written there, each as a relay counts it:**

| Entry | Content | Counted | How many |
|---|---|---|---|
| `name/<name>` | 256 | 1,280 | One for each name each device lists, and each it stopped while the slot stands |
| `applied/<its key>` (`person.rs:755`) | 256 | 1,280 | One for each device, under each statement |
| `left/<its key>` (`leaving.rs:101`) | 256 | 1,280 | One for each device that left, at most |
| `added/<key>` (`person.rs:790`) | 512 | 1,536 | One for each adder and key it added, under the statement; not carried to the next |

Messages are in a channel of their own (asserted within the cap at `protocol.rs:2052`), and the change entry is in the phrase's channel. So at D devices that each list N names:

D × N × 1,280 + D × 1,280 + (D − 1) × 1,536 ≤ 16,777,216

**The limits at which the personal channel reaches the cap, and the warning:**

| Devices | Most names each that fit | Names each at the warning |
|---|---|---|
| 1 | 13,106 | 9,829 |
| 4 | 3,274 | 2,455 |
| 8 | 1,636 | 1,226 |
| 16 | 817 | 612 |
| 32 | 407 | 305 |
| 50 | 259 | 194 |
| 64 | 202 | 151 |

A throwaway test against the relay's own store took 13,107 of the 16,448 entries that 64 devices write (each one's `applied/` word first, then 256 words each), and refused from the 51st device's 244th word on. A delete over a word it held was still taken.

**Nothing bounds the names.** The record of 2026-10-04 bounds devices (64) and removed keys (256). Its request count is "sized for a device with 256 names" (§16), which is a sizing, not a bound. A recovery carries 1,024 names at most (`RECOVERY_MAX_NAMES`).

**What happens today when a relay refuses an entry of the personal channel for room.**

- The wire has one answer, `NoRoom`, for a relay that is full and for a channel at its cap (`crates/cordelia-network/src/messages.rs:796`).
- The device keeps the entry, offers it again after a wait that doubles up to ten minutes, and goes on past it (`at_relays.rs:1150`; `device_entries.rs:2315` to `2340`).
- On a device that syncs a folder the status is amber, "memory: a relay has no room", for as long as it offers the entry again (`indicator.rs:479`, `NO_ROOM_STANDS_SECS`).
- `cordelia devices` says "<relay> had no room for a new channel at <time> (it is full)" (`look.rs:1388`). For the personal channel both halves are wrong: the channel is not new, and the relay need not be full.

## 2. The rules

1. **Each sync cycle sums the channel's total once,** at its end, and keeps it in the cycle's report (`CycleReport`): the total, the part that is words, and the author with the most bytes that are not words, with that author's bytes. It is one sum over the personal channel's rows, by channel. A second review measured such a sum at 20 to 30 ms, warm, over 16,448 rows beside 200,000 others. `/api/v1/sync/status` returns the report as it does today, and `cordelia status` reads it there. Nothing is summed on a status call, so the status keeps its time.
2. **The status turns amber where the total passes the line,** `PERSONAL_CHANNEL_WARN_BYTES`, 12 MiB, on a device that syncs a folder, as the other memory lines do. It stays amber for as long as the last report's total is past the line.
3. **What the warning says depends on what fills the channel.**
   - Where words are half the total or more:
     > memory: your devices sync nearly as many names as a relay can hold for you. Stop syncing names you no longer need, on every device that syncs them. Their room comes back slowly, at least 90 days after the last device stops.
   - Otherwise, where one device signed more than half of what is not words:
     > memory: the list your devices share at a relay is nearly full, mostly with entries from <label> (<first four words of its fingerprint>). If that device is not yours, or you no longer use it, remove it: cordelia remove-device.
   - Otherwise:
     > memory: the list your devices share at a relay is nearly full. Run cordelia devices to see what is in it.
4. **`cordelia devices` says what a relay refused for room as either:**
   > <relay> had no room for what you sent at <time>: the relay is full, or your list there is.

   A refusal of the change entry, and a refusal for the address's allowance, are said as today.
5. **Nothing refuses a write.** A map, the sync cycle, joining, a carry, a recovery and a statement write as they do today.

**Why 12 MiB.** The line is the cap less 4 MiB (`PERSONAL_CHANNEL_HEADROOM_BYTES`). The 4 MiB holds what can arrive at once, before a person can act on a warning:

- the entries that are written whatever the total: 64 `applied/` words and 64 `left/` words (163,840 bytes), and 320 records of an addition (491,520 bytes); 640 KiB in all. 320 is what a reader counts and keeps (`MAX_COUNTED_DEVICES` and `MAX_NOT_COUNTED_RECORDS`), not a proved bound;
- a recovery's names on the new machine: 1,024 words (`RECOVERY_MAX_NAMES`), 1.25 MiB;
- a device that joins with as many folders mapped, writing its words before it has read the channel: another 1.25 MiB.

That is 3,276,800 bytes. Rounded up to 4 MiB, a quarter of the cap, it leaves 917,504 bytes more, 716 words, for names mapped after the warning. Any lower line would warn people who are far from the cap: at 4 devices the warning comes at 2,455 names each.

**What it costs.** One sum at the end of each sync cycle, three fields in its report, one status line in three forms, and one changed line of `cordelia devices`. Two constants. No row, no stream, no check on a write.

## 3. The limit, stated

**Nothing refuses a new name.** A device writes every word as today. Where the channel reaches the cap at a relay, the relay refuses each entry that would grow it: a new word, a device's first `applied/` word under a statement, a `left/` word, a record of an addition. It takes each rewrite that is no larger. What follows:

- The device that sent the entry keeps it and offers it again. Its status is amber: "memory: a relay has no room". `cordelia devices` says so in the words of rule 4.
- Every device past the line also shows the warning of rule 3.
- Other devices that read at that relay do not see what was refused: a name is not listed there, a device's leave is not seen, and a device added since counts on no device that reads there (the record of 2026-10-17, §7). A recovery that reads there does not find a name whose every word was refused.

**What a person can do then.**

- **Stop syncing names they no longer need, on every device that syncs them.** Each such name's room comes back when every device's delete of it has been held 90 days. That is slow, and it is at least 90 days.
- **Remove a device they no longer use** (`cordelia remove-device`, with the phrase). The removed device's words and every record of an addition are not carried into the new channel, so the new channel starts smaller. But each remaining device carries its own deletes, re-stored at the time of the carry, so their 90 days start again.
- **Set up a relay of their own** with a larger cap. The cap is a relay's, not the protocol's.

**What a warning cannot see.** The total is what this device's store holds. A device that has just joined has read nothing yet, and two devices out of touch each see only their own part. A key that holds the secret and does not count can write at a relay, and its entries are in no store (the record of 2026-10-04, §4.4). And a device of alpha.12 shows no warning, though a device of this version counts alpha.12's entries in its total.

## 4. Set aside

- **A bound on the names each device lists,** the first draft of this record. A stopped name's delete stays while any device syncs that name, so the bound could not be got back; a recovery carries every device's names onto one machine, and would have been cut; a person with four devices would have been held at 192 names each where 3,274 fit.
- **A line on the total that refuses a new word,** the second draft. It needed a check on every path that writes a word, and each path brought a fault: a map stores the mapping before the word is written; the sync cycle would turn a refusal into an error on every cycle; a joining device writes before it has read; a recovery's statement would abort after the phrase signed. Each can be mended, at a cost in code and tests that a channel which fills only near 50 devices does not repay.
- **A larger room at a relay.** A relay cannot tell the personal channel from another channel of its kind, so every channel's room would go up, at every relay; a recovery would read for 1,111 seconds rather than 615 (`RECOVERY_READ_ON_MAX_SECS` is derived from the cap). And names stay unbounded.
- **A smaller word.** A word is in the smallest size class already, and the 1,024 that every entry is counted with beyond its content is 16 MiB by itself at 64 × 256.
- **A word that holds several names,** one entry for each device. It is the better form if names one day grow, but a device of alpha.12 does not read it.

## 5. On the wire, and beside alpha.12

**Nothing on the wire changes.** No entry, stream, answer or statement changes form, and no relay changes. A relay of alpha.12 serves a device of this version, and the reverse.

**A person whose devices run alpha.12 and this version at once:** each writes as today. A device of this version shows the warning from what its store holds, alpha.12's entries included. A device of alpha.12 shows none, and says of a refusal for room what it says today.

## 6. The constants

- `PERSONAL_CHANNEL_HEADROOM_BYTES: u64 = 4 MiB`. Asserted in `protocol.rs` to be no less than `2 × MAX_COUNTED_DEVICES × entry_cost(MIN_ENTRY_CONTENT_BYTES) + (MAX_COUNTED_DEVICES + MAX_NOT_COUNTED_RECORDS) × entry_cost(2 × MIN_ENTRY_CONTENT_BYTES) + 2 × RECOVERY_MAX_NAMES × entry_cost(MIN_ENTRY_CONTENT_BYTES)`, which is 3,276,800; and that the longest word, a text or a delete, is a content of `MIN_ENTRY_CONTENT_BYTES`.
- `PERSONAL_CHANNEL_WARN_BYTES: u64 = MAX_ENTRY_CHANNEL_BYTES_AT_RELAY − PERSONAL_CHANNEL_HEADROOM_BYTES`, that is 12 MiB.

For `parameter-rationale.md` §12.10: "**PERSONAL_CHANNEL_WARN_BYTES = 12 MiB.** The status turns amber where the personal channel, as this device's store holds it, passes this (decision 2026-10-19). A relay holds 16 MiB of one channel, and refuses what would grow it past that. The 4 MiB below the cap (`PERSONAL_CHANNEL_HEADROOM_BYTES`) holds what can arrive before a person acts on the warning: the entries that are written whatever the total (640 KiB), a recovery's 1,024 names, and a device that joins with as many folders mapped (1.25 MiB each), with 716 words more. Nothing is refused at the line. What it costs: one sum at the end of each sync cycle."

## 7. Tests

Each fails on an assertion with its rule taken out. Every total is a multiple of 256, since every entry is counted at 1,024 and a power of two from 256.

- `crates/cordelia-api/src/names.rs`: `the_channels_total_counts_every_author_and_every_delete`. A store holds this device's two words and its delete of a third, another device's word, and a record of an addition: the total is 4 × 1,280 + 1,536 = 6,656 bytes, words 5,120, and the author with the most bytes that are not words is the record's signer, at 1,536. Rule 1.
- `crates/cordelia-sync/src/claude.rs`: `a_cycles_report_carries_the_channels_total`. After a cycle the report holds the total of the store; a word written after the cycle does not change the status's total until the next cycle. Rule 1.
- `crates/cordelia-node/src/indicator.rs`: `the_status_is_amber_past_the_line`. Amber at 12,583,168 bytes (the line and 256: the first total past it that a store can hold), and none at 12,582,912 (the line). Rule 2.
- `indicator.rs`: `the_warning_says_what_fills_the_channel`. Words at half the total give the first form; words below half, with one author holding three quarters of the rest, give the second form with that device's label and fingerprint words; with no such author, the third. Rule 3.
- `crates/cordelia-api/src/look.rs`: `a_refusal_for_room_is_said_as_either`, and `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_relays_refusal_for_room_is_said_as_either`. A device and a relay run as real processes, the relay with a `max_storage_bytes` that one entry fills; the relay refuses for room, and `cordelia devices` shows the words of rule 4 and not "a new channel". Rule 4.
- `crates/cordelia-storage/src/relay.rs`: `the_headroom_holds_what_can_arrive_at_once`. A channel holding 12 MiB of words takes 64 `applied/` words, 64 `left/` words, 320 records of 512 bytes, 2,048 more words and then 716 words, and refuses the 717th. It holds the constants of §6 to the relay's own count.
- `crates/cordelia-api/src/names.rs`: `a_map_past_the_line_is_written`. With the store past the line, `hold_mapped` writes a word for each mapped folder. Rule 5.

## 8. What other records would say

The change would alter these sentences, and no record is changed by this one:

- The record of 2026-10-04, §2.2: "the names that exist and what each device syncs (`name/<the name>`)" gains "and nothing bounds them: a device warns before the channel fills a relay's room (decision 2026-10-19)".
- The record of 2026-10-04, §4.1, the bounds: a line that names are not bounded, and that the personal channel fits a relay's room up to the table of decision 2026-10-19 §1.
- The record of 2026-10-04, §16: "sized for a device with 256 names" gains "a sizing, not a bound: a device may sync more".
- The record of 2026-10-17, §7: "On each such device `cordelia devices` names the relay and says that it is full (`look::relays`)" becomes the words of rule 4.
- `parameter-rationale.md` §12.8: "It is sized for a device with 256 names" gains the same; §12.10: the two constants; §12.7 (`MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`): the line is derived from it.
- `CLAUDE.md`, the table of constants: one line for the two.

## 9. The two reviews, and where each finding stands

**The first review** (of the bound for each device, `bade123`):

| Finding | Severity | Where it stands |
|---|---|---|
| 1. The bound cut a recovery to 192 names | High | No longer applies: nothing is bounded, and a recovery carries 1,024 names as today. The headroom holds them (§2). |
| 2. A stopped name can count for ever; the line promised a date | High | Settled in the words. §1 and §3 say a stopped name counts while any device syncs it, and 90 days after; the warning says "at least 90 days" and promises no date. |
| 3. The relay test asserted a refusal at 193 | Medium | Settled. The relay test of §7 takes 716 words past the headroom's parts and refuses the 717th, from the record's own sum. |
| 4. No "not running" branch; `hold_mapped` unbounded | Medium | No longer applies: no write path is checked. §1 lists every path that writes a word. |
| 5. The sweep's gap was understated | Medium | No longer applies as a bound. A store that holds less than a relay is said in §3, "What a warning cannot see". |
| 6. A device kept over the bound for ever; what fails at the cap unsaid | Medium | Settled. §3 says what a relay refuses at the cap and what each device shows. |
| 7. The words a person reads | Low | Settled. Rules 3 and 4 say "you", in short sentences, and promise nothing that is not so. |
| 8. Tests that pass with the rule taken out | Low | Settled. Each test of §7 names its rule and the sizes it asserts. |
| 9. More than 64 authors; 320 records not proved; the total not weighed | Low | The total is what the warning reads. Authors that do not count are in §3; 320 is said to be a sizing. |

**The second review** (of the line that refused a new word, `6a796c6`):

| Finding | Severity | Where it stands |
|---|---|---|
| 1. A map stores the mapping before `say` runs, and swallows its error | High | No longer applies: nothing refuses. §1 now gives the map's path as it is. |
| 2. The sync cycle's `name_channel` was missing, and a refusal there is an error each cycle | High | No longer applies: nothing refuses. §1 names `name_channel`; the cycle is where the total is summed (rule 1). |
| 3. A joining device writes before it has read, and the 307 words did not bound it | Medium | Settled. The headroom holds a joining device with 1,024 folders mapped; past that the relay refuses, as §3 says. |
| 4. A recovery breaks "the new channel holds no more than the old" | Medium | No longer applies: that sentence is gone. The headroom holds a recovery's 1,024 words. |
| 5. A statement restarts the 90 days of deletes | Medium | Settled. §1 and §3 say so; the words promise no date, and say what a removal does to the 90 days. |
| 6. A store total of the line less 1,279 cannot exist | Low | Settled. §7 says every total is a multiple of 256, and asserts totals a store can hold. |
| 7. Tests that cannot fail; exempt entries and rule 5 untested | Low | Settled. With nothing refused, no entry is exempt; §7 tests that a map past the line is written, and each test names its rule. |
| 8. The words blamed names when other entries fill the channel | Low | Settled. Rule 3 has three forms, and names a device only where it signed most of what is not words. |
| 9. A refusal would abort a recovery's statement | Low | No longer applies: nothing refuses. |
| 10. Where the sum is computed, and its cost | Low | Settled. Rule 1: once per sync cycle, kept in the report, read by the status from `/api/v1/sync/status`; never summed on a status call. |

The second review also noted, as not of this record, that a mapped folder whose name is not in its one spelling fails in `name_channel` on every cycle and so stops `forget_other_folders` (`claude.rs:710`, `791`). This record does not touch it.
