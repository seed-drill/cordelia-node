# Decision: a warning before the personal channel fills a relay's room

**Date**: 2026-10-19
**Status**: Built.
**Cited as**: code comments will cite this record as "decision 2026-10-19", and its rules as "§2, rule 3". The numbers do not change.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md), and **the record of 2026-10-17** is [`2026-10-17-recovery-and-carrying.md`](2026-10-17-recovery-and-carrying.md).
- **A word** is an entry of the personal channel whose name is `name/` and then a name that this version would itself map (`names::is_a_name`): a text where a device syncs the name, a delete where it has stopped (the record of 2026-10-04, §2.2 and §16). Anything else in the channel is **not a word**, an entry under `name/` that is no name among it.
- **The cap** is what one channel may hold at a relay, `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, 16 MiB (16,777,216 bytes), counted as entries are counted (`entry_cost`: the content and 1,024 more).
- **The channel's total** is the sum of `entry_cost` over every entry that this device's store holds of the personal channel of the statement it has applied: every author's, deletes included, its own that wait to be sent included.
- **What your devices keep at a relay** is how the words a person reads name the personal channel: the names each device syncs, and which devices there are.
- **Alpha.12** is the release 0.2.0-alpha.12, and **this version** is the version of the node that first carries what is below.
- **#170** is the change of cordelia-node #170 (merged): a sync cycle reads the personal channel once for each change.
- Examples say laptop and desktop.

---

## 0. What this is

The personal channel can outgrow what a relay holds of one channel. Each device writes one word for each name it syncs, and a relay counts each word at 1,280 bytes. 64 devices with 256 names each write 20 MiB against a cap of 16 MiB, and the relay refuses the last quarter. Nothing bounds the names.

The exposure is small: the channel fills near 50 devices at 256 names each, or 4 devices at 3,274 names each. Each refusal added to the paths that write words (a map, the sync cycle, joining, a recovery, a statement) brought faults of its own. So this record refuses nothing. It changes three things:

1. **A warning.** The status turns amber where the channel's total passes a line 4 MiB below the cap. The total is taken in the read of the personal channel that each sync cycle already makes. The words say what fills it and what helps.
2. **A true line for a refusal.** `cordelia devices` no longer says that a refused entry was for a new channel at a full relay, and says which of your channels it was.
3. **A stated limit.** Nothing stops a new name. Past the cap the relay refuses what grows the channel, and the record says what a person then sees and can do.

Nothing on the wire changes, and no relay changes.

## 1. What the code does today

**A word is one entry for each device and each name it lists.** Its slot is the HMAC of `name/` and the name (`names::word_name`, `crates/cordelia-api/src/names.rs:77`). The slot holds no key: every device that syncs a name writes in the same slot, each as its own author. Several folders mapped to one name on one device are one word.

**Where a word is written.** Every new word goes through `names::say` (`names.rs:148`):

- each sync cycle, for every mapped folder (`name_channel`, `crates/cordelia-sync/src/claude.rs:897`);
- a map: the route stores the mapping, then `names_follow` (`crates/cordelia-api/src/sync.rs:1029` and `1030`) calls `hold_mapped` (`sync.rs:513`);
- when a device comes to follow a phrase (`leaving.rs:337`) or is accepted (`adding.rs:714`), through `hold_mapped`, in the transaction that gives it the secret, before it has read the channel;
- a carry, and a recovery (`hold_for_a_carry`, `recover.rs:1094`).

At a statement a device carries its own words, deletes included, into the new channel by another path (`Carry::channel`, `person.rs:1541`), each stored at the time of the carry.

**A word is always counted at 1,280 bytes.** It says the name's length (2 bytes), `name/` and a name of at most 200 bytes (`sync::valid_sync_name`, `sync.rs:220`), the value's kind (1), an empty text's length (2) and an empty chain (2): at most 212 bytes, 240 with the nonce and the tag (`protocol.rs:330`). The content is padded to a power of two from 256 (`crates/cordelia-crypto/src/entry.rs:615`, `protocol.rs:950`), so every word, and every delete of one, is 256 bytes, counted at 256 + 1,024 (`protocol.rs:341`, `entry_cost` at 347). Every total is so a multiple of 256.

**The channel grows with names, not with changes.** A relay keeps the newest revision for each author in each slot, and a write that makes a channel hold no more is always taken (`crates/cordelia-storage/src/relay.rs:548` to `596`). A delete keeps its size. A relay sweeps a slot only where every entry in it is a delete it has held 90 days, and a device sweeps the personal channel the same way. So a stopped name stays counted while any device syncs it, and for 90 days after. A statement re-stores each device's own deletes at the time of the carry, so their 90 days start again.

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

| Devices | Most names each that fit | Names each at which the warning shows |
|---|---|---|
| 1 | 13,106 | 9,830 |
| 4 | 3,274 | 2,456 |
| 8 | 1,636 | 1,227 |
| 16 | 817 | 613 |
| 32 | 407 | 306 |
| 50 | 259 | 195 |
| 64 | 202 | 152 |

A throwaway test against the relay's own store took 13,107 of the 16,448 entries that 64 devices write (each one's `applied/` word first, then 256 words each), and refused from the 51st device's 244th word on. A delete over a word it held was still taken.

**Nothing bounds the names.** The record of 2026-10-04 bounds devices (64) and removed keys (256). Its request count is "sized for a device with 256 names" (§16), which is a sizing, not a bound. A recovery carries 1,024 names at most (`RECOVERY_MAX_NAMES`).

**How a cycle reads the personal channel, since #170.** `exchange_names` (`claude.rs:993` to `997`) first checks and opens, with the database's lock let go, each entry stored since the last read (`names::read_ahead`, `names.rs:411`). Under the lock it then reads the channel's rows once (`names::said_and_listed`, `names.rs:473`, through `words_kept`, `names.rs:357`), reusing what was found of each row that is stored as it was, to the byte. What is kept of a text is its name; a delete is checked and not opened (`names::find`, `names.rs:260`).

**What it costs, measured.** #170's timed tests (`claude/tests/personal_reads.rs`) run as merged at 4 devices of 2,460 names, 9,844 entries. They are ignored, and run only by hand in release; nothing in CI holds a time. To measure at the cap's size, `NAMES_EACH` was set by hand to 4,112, which gives 16,452 entries, and both tests were run in release on a machine of 4 cores, before any sum was added:

| Run | A cycle with nothing changed holds the lock | The longest wait for the lock | The slowest sync status | The first cycle |
|---|---|---|---|---|
| This record's, 1 run | 62 ms | 56 and 61 ms | 25 ms | 4.9 s |
| The fourth review's, 3 runs | 53 to 64 ms | 94 to 154 ms (5 of 6 over 100 ms) | 70 to 121 ms | 3.1 to 3.9 s |

So at the cap's size the sync status answers well within the second that `cordelia status` waits (`main.rs:1670`). But the lock can be waited for longer than the 100 ms that `msg summary` tries it (`AGENT_MESSAGE_SUMMARY_WAIT_MS`), and #170's own assertion of that fails there. The waits seem to span two holds in a row: `read_ahead` loads the rows under the lock, and `said_and_listed` loads them again (not confirmed). At 9,844 entries, as merged, the review measured waits of 70 and 79 ms on the same machine. The first cycle after a start checks and opens every entry with the lock let go.

**What happens today when a relay refuses an entry of a channel of your own for room.**

- The wire has one answer, `NoRoom`, for a relay that is full and for a channel at its cap (`crates/cordelia-network/src/messages.rs:796`).
- The device keeps the entry, offers it again after a wait that doubles up to ten minutes, and goes on past it (`at_relays.rs:1150`; `device_entries.rs:2314`). This holds for the personal channel and for a name's channel alike; the messages channel is said apart.
- On a device that syncs a folder the status is amber, "memory: a relay has no room", for as long as it offers the entry again (`indicator.rs:480`, `NO_ROOM_STANDS_SECS`).
- `cordelia devices` says "<relay> had no room for a new channel at <time> (it is full)" (`look.rs:1388`). For a channel the relay already holds both halves are wrong: the channel is not new, and the relay need not be full.

## 2. The rules

1. **The total is taken in the pass that already reads the personal channel.** In `words_kept`, for each stored row: add `entry_cost` of its content's length, which is a column of the row and needs no key; and tell a word from what is not one.
   - **A text** is a word where the name that #170 keeps for it is `name/` and a name that `is_a_name` accepts.
   - **A delete** is not opened. It is not a word where its slot is that of `applied/` or `left/` and its own author's key, or that of `added/` and any key the device counts or keeps a record of; every other delete is a word. That is two slot hashes for each key, worked out once for each statement and kept with what #170 keeps.
   - What is not a word is counted for its author.

   **The sum goes before the pass's filter** of who counts and which band (`of(&author) && in_a_band_of`): every entry the store holds is counted, as a relay holds it.

   Measured in a throwaway release test on the same 4 cores, over 16,384 stored entries, 4,096 of them deletes: reading the rows took 17.5 ms (the pass reads them already); adding their sizes took 0.09 ms; matching every delete against the slots of 64 keys took 1.1 ms, hashes included. So the sum adds about 1 ms to a hold of 53 to 64 ms. The status reads only the report, and stays within its second.
2. **The cycle keeps in its report** (`CycleReport`, `claude.rs:212`): the total; the bytes that are words; and for each key, its bytes of words and its bytes of what is not a word. `/api/v1/sync/status` returns the report as it does today. Nothing is summed on a status call. **A cycle that ends before it reads the personal channel** (the device stands in no statement it applied, or has no phrase) carries forward the total of the last cycle that read it, with that cycle's time, so a short cycle does not clear the warning.
3. **The status turns amber where the total passes the line,** `PERSONAL_CHANNEL_WARN_BYTES`, 12 MiB, for as long as the last report's total is past it. It is placed **first among the amber memory lines**, above every line the overflow itself can cause: "no relay", "not taken by a relay", "the node is another version", "a removal not yet applied by every device", "added, not yet cleared", "a device has left", "carried, not yet sent", "a relay does not hold the latest change", "a relay has no room", and "not yet listed by a device" or "not yet sent". So where the channel is past the line, the line a person sees names the cause. Like the other memory lines it shows on a device with sync on and a folder mapped.
4. **What the warning says depends on what fills the channel.** The first form that holds is said. In honest use only the third form can show: what is not a word comes to 640 KiB at most, less than a quarter of the line. The first, second and fourth are for a device that misbehaves or fails, and such a device can dodge the first two by writing entries that are words in form (§3). They name a device where they can; they do not promise to.
   - **Another device has signed more than half of what is not words, and more than a quarter of the total:**
     > memory: <label> (<first four words of its fingerprint>) has filled most of what your devices keep at a relay. If it is not yours, or you no longer use it, remove it: cordelia remove-device <its key>
   - **This device has:**
     > memory: this device has filled most of what your devices keep at a relay. If you no longer use it, remove it from another of your devices.
   - **Words are half the total or more:**
     > memory: you sync nearly as many names as a relay can keep for your devices. A name you add now may not reach your other devices. Stop syncing names you no longer need, on every device that syncs them: their room comes back slowly, at least 90 days later. Or remove a device you no longer use: its room comes back at once.
   - **Otherwise:**
     > memory: what your devices keep at a relay is nearly full. Run cordelia devices to see how much each device keeps there.
5. **`cordelia devices` shows what your devices keep at a relay,** from the last report, in MiB as every size in this record is: "Your devices keep 12.4 MiB of the 16 MiB a relay holds for them (names: 11.8 MiB)", and beside each device the MiB it signed. It shows them past the line only.
6. **`cordelia devices` says what a relay refused for room as what it is.** A device keeps, with the refusal, which channel was refused (the personal channel, a name's, or a pair channel), as it knows its own channels. It keeps one refusal for each relay, as today; where the personal channel and another are refused in one pass, the personal channel's is kept, and otherwise the latest:
   > <relay> had no room for what you sent at <time>: the relay is full, or what your devices keep there is.

   > <relay> had no room for what you sent at <time>: the relay is full, or your memory of <name> there is as large as a relay keeps.

   > <relay> had no room for what you sent at <time>: the relay is full, so no device can be added through it now.

   The last is for a pair channel, which carries a hand-over. A refusal of the change entry, and a refusal for the address's allowance, are said as today. **The let-go read also shows a refusal for room** ("It had no room for it, the last time …", `let_go.rs:453`): it reads the same refusal, so it can give the time of another channel's refusal at that relay. It is left as it is: it says when the relay last refused, which is so.
7. **Nothing refuses a write.** A map, the sync cycle, joining, a carry, a recovery and a statement write as they do today.

**Why 12 MiB.** One thing frees room at once: a removal, which leaves the removed device's words, every record of an addition and every `applied/` word behind in the old channel. Nothing else does in less than 90 days: a stopped name's room comes back 90 days after the last device stops, and a removal starts every other stopped name's 90 days again. So the 4 MiB between the line and the cap (`PERSONAL_CHANNEL_HEADROOM_BYTES`) is a budget: the room a person has after the warning, until a removal or until stopped names come back. It holds:

- the entries that are written whatever the total: 64 `applied/` words and 64 `left/` words (163,840 bytes), and 320 records of an addition (491,520 bytes); 640 KiB in all. 320 is what a reader counts and keeps (`MAX_COUNTED_DEVICES` and `MAX_NOT_COUNTED_RECORDS`), not a proved bound;
- a recovery's names on the new machine: 1,024 words (`RECOVERY_MAX_NAMES`), 1.25 MiB;
- a device that joins with as many folders mapped, writing its words before it has read the channel: another 1.25 MiB;
- 716 words more, for names added meanwhile.

That is the cap less the line, 4,194,304 bytes; the first three come to 3,276,800. A person who goes on adding names after the warning uses the last 716 words first, and is told, in the third form, that a name added now may not reach the other devices. A lower line would warn people who are far from the cap: at 4 devices the warning already shows at 2,456 names each.

**What it costs.** A sum and a slot match in a pass that exists (about 1 ms at the cap's size, under the lock), two slot hashes for each key at each statement, a few fields in the cycle's report, a status line in four forms, one line of `cordelia devices` and a size beside each device past the line, and the channel kept with a refusal for room. Two constants. No row, no stream, no check on a write.

## 3. The limit, stated

**Nothing refuses a new name.** A device writes every word as today. Where the channel reaches the cap at a relay, the relay refuses each entry that would grow it: a new word, a device's first `applied/` word under a statement, a `left/` word, a record of an addition. It takes each rewrite that is no larger.

**What each device then shows.**

- The device that sent the entry keeps it and offers it again. Where it syncs a folder, its status is amber, with the warning of rule 4 first, then "memory: a relay has no room"; `cordelia devices` says the words of rule 6.
- **A refused carried word stops everything after it.** Where a word that the device carried into the personal channel after a statement is refused, the device sends nothing it wrote after it in that channel to that relay, and offers it again from there (`at_relays::sent`, its documentation at `at_relays.rs:1100` to `1110`; the test `test_a_carried_word_that_a_relay_has_no_room_for_is_not_passed`). So its deletes of names it stops syncing, which the relay would take, its `left/` word and its new words wait too, and devices that read there go on seeing it list those names.
- Where a carried word was refused after a statement, the device never writes that it has sent what it carried (`at_relays::say_sent`, `at_relays.rs:697`). So, with no end: on that device, "keep this machine on: this device has not yet sent every relay what it carried" (`person_cmd.rs:2321`); on the others, that it "has applied change N, and is still sending what it held" (`person_cmd.rs:978`).
- Where a device's first `applied/` word was refused, the other devices say that it "has not applied change N yet" (`person_cmd.rs:988`), and the amber "memory: a removal not yet applied by every device" shows for 7 days.
- Other devices that read at that relay do not see what was refused: a name is not listed there, a device's leave is not seen, and a device added since counts on no device that reads there (the record of 2026-10-17, §7). A recovery that reads there does not find a name whose every word was refused.

**What a person can do then.**

- **Add no new names.** It helps at once.
- **Stop syncing names they no longer need, on every device that syncs them.** Each such name's room comes back when every device's delete of it has been held 90 days: at least 90 days, and longer where a statement is made meanwhile. It works only from devices that have sent the relay everything they carried: on a device whose carried word was refused, the deletes wait behind it, and never reach that relay.
- **Remove a device they no longer use** (`cordelia remove-device`, with the phrase). It frees room at once: the removed device's words, every record of an addition and every `applied/` word stay behind in the old channel. Each remaining device carries its own words and deletes, which starts their 90 days again. The new channel fits only where what the remaining devices carry fits; where it does not, the lines above show again, now about the carry.
- **Set up a relay of their own** with a larger cap. The cap is a relay's, not the protocol's.

**What a warning cannot see.**

- The total is what this device's store holds. A device that has just joined has read nothing yet, and two devices out of touch each see only their own part.
- A key that holds the secret and does not count can write at a relay, and its entries are in no store (the record of 2026-10-04, §4.4).
- A device that counts, in someone else's hands, can write entries that are words in form, and the warning then speaks of names. The sizes beside each device in `cordelia devices` (rule 5) show which device signed them.
- A delete under `added/` and a key the device neither counts nor keeps a record of is counted as a word: a device writes none.
- A device with sync off, or no folder mapped, shows no memory line: a recovered machine that maps nothing runs no cycle, and so takes no total.
- A device of alpha.12 shows no warning, though a device of this version counts alpha.12's entries in its total.

**`msg summary` between the line and the cap.** At those sizes the lock can be waited for longer than the 100 ms that `msg summary` tries it (§1). A summary that finds the lock busy prints nothing for that prompt: the message waits, and the next summary shows it. This record does not change that. A later improvement, not part of this record, would load the channel's rows once under the lock for each cycle, or take a fair lock.

## 4. Set aside

- **A bound on the names each device lists,** the first draft of this record. A stopped name's delete stays while any device syncs that name, so the bound could not be got back; a recovery carries every device's names onto one machine, and would have been cut; a person with four devices would have been held at 192 names each where 3,274 fit.
- **A line on the total that refuses a new word,** the second draft. It needed a check on every path that writes a word, and each path brought a fault: a map stores the mapping before the word is written; the sync cycle would turn a refusal into an error on every cycle; a joining device writes before it has read; a recovery's statement would abort after the phrase signed.
- **Opening every delete to tell a word,** in place of the slot rule. `find` already checks every delete; opening them too adds about 171 ms for 4,096 deletes, once for each start, with the lock let go. It is cheap, and exact; but for honest entries the slot rule is exact too (a device deletes only words and its own `left/` word), and opening constrains a device that misbehaves no more than texts in form do.
- **A larger room at a relay.** A relay cannot tell the personal channel from another channel of its kind, so every channel's room would go up, at every relay; a recovery would read for 1,111 seconds rather than 615 (`RECOVERY_READ_ON_MAX_SECS` is derived from the cap). And names stay unbounded.
- **A smaller word.** A word is in the smallest size class already, and the 1,024 that every entry is counted with beyond its content is 16 MiB by itself at 64 × 256.
- **A word that holds several names,** one entry for each device. It is the better form if names one day grow, but a device of alpha.12 does not read it.

## 5. On the wire, and beside alpha.12

**Nothing on the wire changes.** No entry, stream, answer or statement changes form, and no relay changes. A relay of alpha.12 serves a device of this version, and the reverse. Which channel a refusal was for is kept by the device that sent the entry, from what it sent.

**A person whose devices run alpha.12 and this version at once:** each writes as today. A device of this version shows the warning from what its store holds, alpha.12's entries included. A device of alpha.12 shows none, and says of a refusal for room what it says today.

## 6. The constants

- `PERSONAL_CHANNEL_HEADROOM_BYTES: u64 = 4 MiB`. Asserted in `protocol.rs` to be no less than `2 × MAX_COUNTED_DEVICES × entry_cost(MIN_ENTRY_CONTENT_BYTES) + (MAX_COUNTED_DEVICES + MAX_NOT_COUNTED_RECORDS) × entry_cost(2 × MIN_ENTRY_CONTENT_BYTES) + 2 × RECOVERY_MAX_NAMES × entry_cost(MIN_ENTRY_CONTENT_BYTES)`, which is 3,276,800; and that the longest word, a text or a delete, is a content of `MIN_ENTRY_CONTENT_BYTES`.
- `PERSONAL_CHANNEL_WARN_BYTES: u64 = MAX_ENTRY_CHANNEL_BYTES_AT_RELAY − PERSONAL_CHANNEL_HEADROOM_BYTES`, that is 12 MiB.

For `parameter-rationale.md` §12.10: "**PERSONAL_CHANNEL_WARN_BYTES = 12 MiB.** The status turns amber where the personal channel, as this device's store holds it, passes this (decision 2026-10-19). A relay holds 16 MiB of one channel, and refuses what would grow it past that. Nothing but a removal frees room in under 90 days, so the 4 MiB below the cap (`PERSONAL_CHANNEL_HEADROOM_BYTES`) is the budget left after the warning: the entries that are written whatever the total (640 KiB), a recovery's 1,024 names and a device that joins with as many folders mapped (1.25 MiB each), and 716 words for names added meanwhile. Nothing is refused at the line. What it costs: a sum in the read of the personal channel that each sync cycle makes, about 1 ms at the cap's size."

## 7. Tests

Each fails on an assertion with its rule taken out. No timed test is a rule's guard: #170's timed tests are ignored in CI, and §1 gives what they measured as a measurement.

- `crates/cordelia-api/src/names.rs`: `the_channels_total_counts_every_author_and_every_delete`. The store holds, in the personal channel of the statement applied:
  - this device's two words and its delete of a third;
  - another device's word, a record of an addition by that device, and `name/A Lab`, which is no name, by that device;
  - this device's `applied/` word, and a delete of its `left/` word;
  - a word by a key that no longer counts, and a word of this device's in a band that the pass's filter of bands leaves out;
  - a delete under `added/` and a key this device counts, and a delete by the other device under this device's `left/` slot.

  Beside them, an entry of a name's channel and one of the personal channel of a generation left. The total is 11 × 1,280 + 1,536 = 15,616 bytes; words are the four words, the two words outside the filter, and the delete under another key's `left/` slot, 7 × 1,280 = 8,960; what is not a word is the record, `name/A Lab`, the `applied/` word, the own `left/` delete and the `added/` delete. Taking out the channel's filter, putting the sum after the filter of who counts and which band, counting deletes as not words, or counting `name/A Lab` as a word each fails an assertion. Rules 1 and 2.
- `crates/cordelia-sync/src/claude.rs`: `a_cycles_report_carries_the_channels_total`. After a cycle the report holds the total of the store; a word written after the cycle does not change the status's total until the next cycle; and a cycle that ends before it reads the channel carries the last total forward. Rule 2.
- `crates/cordelia-node/src/indicator.rs`: `the_status_is_amber_past_the_line`. Amber at 12,583,168 bytes (the line and 256: the first total past it that a store can hold), and none at 12,582,912; none with sync off, and none with no folder mapped. Rule 3.
- `indicator.rs`: `the_warning_is_shown_before_every_other_amber_memory_line`. With the total past the line, each of the eleven lines that rule 3 names is made to hold in turn, and the line shown is the warning each time. Rule 3.
- `indicator.rs`: `the_warning_says_what_fills_the_channel`. Another device with half of what is not words and one entry more, and more than a quarter of the total, gives the first form; at exactly half of what is not words, or at exactly a quarter of the total, it does not. This device in its place gives the second. Words at exactly half the total give the third. Words below half, with two devices each at half of the rest, give the fourth. Rule 4.
- `crates/cordelia-api/src/look.rs`: `a_refusal_for_room_says_which_channel`. A refusal kept for the personal channel, for a name's channel and for a pair channel each gives its own words of rule 6; one for the change entry and one for the address's allowance give today's; where the personal channel and a name's are refused in one pass, the personal channel's is kept. Rule 6.
- `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_relays_refusal_for_room_is_said_as_what_it_is`. A device and a relay run as real processes, the relay with a `max_storage_bytes` that one entry fills. In one pass the relay refuses an entry of the personal channel, and `cordelia devices` shows the words of rule 6 for it; in a later pass, while the first waits to be offered again (so that pass does not offer it), it refuses an entry of a name's channel, and the words for that show. Neither says "a new channel". This tests a full relay; a channel at its cap is answered the same on the wire (`NoRoom`, §1), and 16 MiB is too large for a test of real processes, so the cap is tested in units only. Rule 6.
- `crates/cordelia-node/src/person_cmd.rs`: `devices_shows_what_each_device_keeps_past_the_line`, and none below it. Rule 5.
- `crates/cordelia-storage/src/relay.rs`: `the_headroom_holds_what_can_arrive`. A channel holding 9,831 words (12,583,680 bytes, the first count past the line) takes 64 `applied/` words, 64 `left/` words, 320 records of 512 bytes, 2,048 more words and then 716 words, and refuses the 717th. It holds the constants of §6 to the relay's own count.

Rule 7 adds no code to any path that writes, so it has no test of its own: the tests of those paths stand.

## 8. What other records would say

The change would alter these sentences, and no record is changed by this one:

- The record of 2026-10-04, §2.2: "the names that exist and what each device syncs (`name/<the name>`)" gains "and nothing bounds them: a device warns before the channel fills a relay's room (decision 2026-10-19)".
- The record of 2026-10-04, §4.1, the bounds: a line that names are not bounded, and that the personal channel fits a relay's room up to the table of decision 2026-10-19 §1.
- The record of 2026-10-04, §16: "sized for a device with 256 names" gains "a sizing, not a bound: a device may sync more".
- The record of 2026-10-17, §7: "On each such device `cordelia devices` names the relay and says that it is full (`look::relays`)" becomes the words of rule 6.
- `parameter-rationale.md` §12.8: "It is sized for a device with 256 names" gains the same; §12.10: the two constants; §12.7 (`MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`): the line is derived from it.
- `CLAUDE.md`, the table of constants: one line for the two.

## 9. The four reviews, and where each finding stands

The reviews of this record are in the pull requests that built it.
