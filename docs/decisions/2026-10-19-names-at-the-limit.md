# Decision: a line on the personal channel, below a relay's room

**Date**: 2026-10-19
**Status**: Proposed. Not built.
**Cited as**: code comments will cite this record as "decision 2026-10-19", and its rules as "§2, rule 3". The numbers do not change.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md), and **the record of 2026-10-17** is [`2026-10-17-recovery-and-carrying.md`](2026-10-17-recovery-and-carrying.md).
- **A word** is an entry that a device writes in the personal channel under `name/` and a name: a text where it syncs the name, a delete where it has stopped (the record of 2026-10-04, §2.2 and §16).
- **A new word** is a word in a slot where this device has no entry of its own yet. Writing in a slot where it has one, a text or a delete, is **a rewrite**.
- **The cap** is what one channel may hold at a relay, `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, 16 MiB (16,777,216 bytes), counted as entries are counted (`entry_cost`: the content and 1,024 more).
- **The channel's total, as this device reads it,** is the sum of `entry_cost` over every entry that this device's store holds of the personal channel of the statement it has applied: every author's, deletes included, its own that wait to be sent included.
- **Alpha.12** is the release 0.2.0-alpha.12, and **this version** is the version of the node that first carries what is below.
- Examples say laptop and desktop.

---

## 0. What this is

The personal channel can outgrow what a relay holds of one channel. Each device writes one word for each name it syncs, and a relay counts each word at 1,280 bytes. 64 devices with 256 names each write 20 MiB against a cap of 16 MiB, and the relay refuses the last quarter. Nothing bounds the names today.

The exposure is small: the channel overflows near 50 devices at 256 names each, or 4 devices at 3,274 names each. So this record makes the least change that makes the record true and never stops a person in ordinary use. **A device writes no new word where it would take the channel's total, as the device reads it, past a line 1 MiB below the cap** (15 MiB, some 12,000 words between all the person's devices). The mebibyte below the cap is kept for what must always fit. A rewrite is never refused. Nothing on the wire changes, and no relay changes.

## 1. What the code does today

**A word is one entry for each device and each name it lists.** Its slot is the HMAC of `name/` and the name (`names::word_name`, `crates/cordelia-api/src/names.rs:77`), and the slot holds no key: every device that syncs a name writes in the same slot, each as its own author. Several folders mapped to one name on one device are one word. Every new word goes through one function, `names::say` (`names.rs:148`). It is called by `sync_name` (a map, through `/api/v1/sync/map`, which needs the node running), by `hold_mapped` (when the device comes to follow a phrase, `leaving.rs:337`; is accepted, `adding.rs:714`; or turns sync on, `sync.rs:507`), by `held_after_its_folder`, and by `hold_for_a_carry` (a carry, and a recovery at `recover.rs:1094`). At a statement a device carries its own words into the new channel by another path (`person.rs:1541`, `is_its_word_to_carry`), deletes included.

**A word is always counted at 1,280 bytes.** It says the name's length (2 bytes), `name/` and a name of at most 200 bytes (`sync::valid_sync_name`, `crates/cordelia-api/src/sync.rs:220`), the value's kind (1), an empty text's length (2) and an empty chain (2): at most 212 bytes, 240 with the nonce and the tag (`protocol.rs:330`). The content is padded to a power of two from 256 (`crates/cordelia-crypto/src/entry.rs:615`, `protocol.rs:950`), so every word, and every delete of one, is 256 bytes, and counted at 256 + 1,024 (`protocol.rs:341`, `entry_cost` at 347).

**The channel grows with names, not with changes.** A relay keeps the newest revision for each author in each slot, and a write that makes a channel hold no more is always taken (`crates/cordelia-storage/src/relay.rs:548` to `579`). A delete stays at the same size. A relay sweeps a slot only where every entry in it is a delete it has held 90 days, and a device sweeps the personal channel the same way: so a device's delete of a name stays for as long as any other device syncs that name, and 90 days after.

**What else is written there, each as a relay counts it:**

| Entry | Content | Counted | How many |
|---|---|---|---|
| `name/<name>` | 256 | 1,280 | One for each name each device lists, and each it stopped while the slot stands |
| `applied/<its key>` (`person.rs:755`) | 256 | 1,280 | One for each device, under each statement |
| `left/<its key>` (`leaving.rs:101`) | 256 | 1,280 | One for each device that left, at most |
| `added/<key>` (`person.rs:790`) | 512 | 1,536 | One for each adder and key it added, under the statement; not carried to the next |

Messages are in a channel of their own (asserted within the cap at `protocol.rs:2052`), and the change entry is in the phrase's channel. So at D devices that each list N names:

D × N × 1,280 + D × 1,280 + (D − 1) × 1,536 ≤ 16,777,216

**The limits at which the personal channel reaches the cap:**

| Devices | Most names each that fit |
|---|---|
| 1 | 13,106 |
| 4 | 3,274 |
| 8 | 1,636 |
| 16 | 817 |
| 32 | 407 |
| 50 | 259 |
| 51 | 254 |
| 64 | 202 |

A throwaway test against the relay's own store took 13,107 of the 16,448 entries that 64 devices write (each one's `applied/` word and 256 words), and refused from the 51st device's 244th word on. A delete over a word it held was still taken.

**Nothing bounds the names.** The record of 2026-10-04 sizes a request count for "a device with 256 names" (§16), which is a sizing assumption. A recovery carries 1,024 names at most (`RECOVERY_MAX_NAMES`).

**What happens today when a relay refuses an entry of the personal channel for room.**

- The wire has one answer, `NoRoom`, for a relay that is full and a channel at its cap (`crates/cordelia-network/src/messages.rs:796`).
- The device keeps the entry, offers it again after a wait that doubles up to ten minutes, and goes on past it (`at_relays.rs:1150`; `device_entries.rs:2315` to `2340`).
- On a device that syncs a folder the status is amber, "memory: a relay has no room", for as long as it offers the entry again (`indicator.rs:479`, `NO_ROOM_STANDS_SECS`).
- `cordelia devices` says "<relay> had no room for a new channel at <time> (it is full)" (`look.rs:1388`). Here both halves are wrong: the channel is not new, and the relay is not full.
- `cordelia sync map` says nothing of it.
- At the cap a relay refuses every entry that makes the channel larger: a new word, a device's first `applied/` word under a statement, a `left/` word, a record of an addition. A rewrite no larger is taken. So other devices do not see the name, a device's leave, or a device added since: the added device counts on no other device that reads at that relay (the record of 2026-10-17, §7). A recovery does not find a name whose every word was refused.

## 2. The rules

1. **A device writes no new word that would take the channel's total, as it reads it, past the line** (`PERSONAL_NAMES_LINE_BYTES`, 15 MiB). The check is in `names::say`, so it holds for a map, for `hold_mapped`, for a carry and for a recovery.
2. **A rewrite is never refused,** whatever the total: a name stopped and synced again, and a delete over a word. It takes no more room at a relay.
3. **Nothing else a device writes in the personal channel is held to the line:** a word that it applied a statement, a word that it left, a record of an addition, and what it carries at a statement. These use the mebibyte kept below the cap. A statement's carry adds nothing that was not in the old channel: each device carries only its own entries, one for each slot it wrote, and records, `applied/` words and the removed devices' words are not carried. So the new channel holds no more than the old one did.
4. **`cordelia sync map` refuses a new name at the line, and maps nothing.** It says:
   > You can't sync another name. Your devices already list as many synced names as Cordelia can carry for you, counting names you stopped syncing lately. Nothing was mapped.
   > To make room, stop syncing names you no longer need, on every device that syncs them. Each one's room comes back 90 days after the last device stops syncing it. Removing a device you no longer use frees its names at once.
5. **`hold_mapped` lists folders in the order they were mapped, up to the line.** A folder past it stays mapped and is not synced. The status says so: "memory: <n> mapped folders are not synced: no room to list more names". `cordelia sync carry` refuses a name past the line with the words of rule 4, and a recovery names a name it could not list among the names it left.
6. **Near the line the status turns amber,** on every device that syncs a folder, from 14 MiB (`PERSONAL_NAMES_NEAR_BYTES`): "memory: you are close to the most names Cordelia can carry for you".
7. **What `cordelia devices` says of a refusal for room:** "<relay> had no room for what you sent at <time>: the relay is full, or your channel there is." A refusal of the change entry, and a refusal for the address's allowance, are said as today.

**Why it fits.** Below the line, the mebibyte to the cap holds everything that rule 3 lets through: 64 `applied/` and 64 `left/` words (163,840 bytes) and 320 records of an addition (491,520 bytes), 640 KiB in all. That leaves 384 KiB, 307 words, for what the line does not see (below). 320 records is not a proved bound: it is what a reader counts and keeps (`MAX_COUNTED_DEVICES` and `MAX_NOT_COUNTED_RECORDS`). A person who keeps to the commands adds at most 63 devices under one statement before `add-device` refuses, and 320 is five times that.

**What the line does not bound.** The relay's refusal is then the last guard, and the person sees what §1 says, with the line of rule 7.

- **Devices that map while apart.** Each reads the total from what it holds. Two devices out of touch can each map up to the line, and together pass it. The 307 words cover a little of that; past them the relay refuses.
- **A device's own deletes swept before a relay sweeps them.** A device counts a delete from when it stored it, and a relay from when it took it: later where the device was off, where a relay is new to the device or was down, or where a relay took the channel from another. In that gap the device counts less than the relay holds.
- **Authors that do not count.** A store holds only entries whose signer counts (the record of 2026-10-04, §4.4). A key that holds the secret and does not count (one the 64 kept out) can still write at a relay, and a device that counts, in someone else's hands, can fill the channel with records (the record of 2026-10-17, §7). This record bounds what a person's own devices write, and nothing else.
- **Alpha.12.** A device of alpha.12 holds to no line. A device of this version counts its words in the total, and refuses new words of its own past the line, but cannot stop it.

**What it costs.** A device sums the channel's entries before each new word: a sum over at most some 13,000 rows, once for each name a person maps. Two constants, one check, one status line, one refusal and one changed line of `cordelia devices`. A person who reaches the line waits 90 days for a stopped name's room, unless they remove a device.

## 3. Set aside

- **A bound on the names each device lists (192),** as the first draft of this record proposed. A slot's delete stays while any other device syncs the name, so a person who moves names from the laptop to the desktop never gets those places back on the laptop; the line promised a date it cannot know; a recovery that carries every device's names onto one machine would have been cut to 192; and a person with four devices would have been held to 192 names each when 3,000 fit. Its one strength, that it holds while devices are apart, buys little where the exposure is this small.
- **A larger room at a relay.** A relay cannot tell the personal channel from another channel of the kind, so every channel's room goes up, at every relay; a channel filled by a device in someone else's hands takes twice as much; a recovery reads for 1,111 seconds rather than 615 (`RECOVERY_READ_ON_MAX_SECS` is derived from the cap). And names stay unbounded.
- **A smaller word.** A word is in the smallest size class already, and the 1,024 that every entry is counted with beyond its content is 16 MiB by itself at 64 × 256. A smaller word needs a smaller count for every entry at every relay.
- **A word that holds several names,** one entry for each device. It is the better form if names one day grow, but it is a new kind of entry, which a device of alpha.12 does not read: it would neither prove those channels, nor show those names at a removal, nor carry them at a recovery made with its command.
- **Not carrying `name/` deletes at a statement,** so that a renewal frees stopped names. In a new channel no word and a delete say the same. It would be a way out at the line, but it changes the carry, and the line is reached by no ordinary use.

## 4. On the wire, and beside alpha.12

**Nothing on the wire changes.** No entry, stream, answer or statement changes form, and no relay changes. The line is a check that each device of this version makes on what it writes.

**A person whose devices run alpha.12 and this version at once:** each reads every word the other writes, as today. A device of this version counts alpha.12's words in its total and refuses new words of its own past the line. A device of alpha.12 maps as today. Where the channel reaches the cap at a relay, the relay refuses, and devices of this version say so with the line of rule 7. A recovery is as today on both.

## 5. The constants

- `PERSONAL_CHANNEL_KEPT_BYTES: u64 = 1 MiB`. Asserted in `protocol.rs`: no less than `2 × MAX_COUNTED_DEVICES × entry_cost(MIN_ENTRY_CONTENT_BYTES) + (MAX_COUNTED_DEVICES + MAX_NOT_COUNTED_RECORDS) × entry_cost(2 × MIN_ENTRY_CONTENT_BYTES)`, which is 655,360; and that the longest word, a text or a delete, is a content of `MIN_ENTRY_CONTENT_BYTES`.
- `PERSONAL_NAMES_LINE_BYTES: u64 = MAX_ENTRY_CHANNEL_BYTES_AT_RELAY − PERSONAL_CHANNEL_KEPT_BYTES`, that is 15 MiB.
- `PERSONAL_NAMES_NEAR_BYTES: u64 = PERSONAL_NAMES_LINE_BYTES − PERSONAL_CHANNEL_KEPT_BYTES`, that is 14 MiB.

For `parameter-rationale.md` §12.9: "**PERSONAL_NAMES_LINE_BYTES = 15 MiB.** A device writes no new word that a name is synced where it would take the personal channel's total, as its store reads it, past this (decision 2026-10-19). A word is counted at 1,280 bytes at a relay, whatever the name, and a relay holds 16 MiB of a channel: so some 12,000 words between all of a person's devices. The mebibyte below the cap (`PERSONAL_CHANNEL_KEPT_BYTES`) holds what is never refused: 64 words that a statement is applied, 64 that a device left, and 320 records of an addition, with 307 words over for what one device cannot see. `PERSONAL_NAMES_NEAR_BYTES`, a mebibyte lower, turns the status amber. What it costs: a person past the line maps no new name until a stopped name's room comes back, 90 days after no device syncs it, or a device is removed."

## 6. Tests

Each would fail on an assertion with its rule taken out.

- `crates/cordelia-api/src/names.rs`: `a_new_word_past_the_line_is_refused` (the store holds the line less 1,279 bytes of other devices' words: `say` of a new name is refused with the error of the line, and stores nothing; one byte more room and it is taken). Rule 1.
- `names.rs`: `a_rewrite_past_the_line_is_taken` (over the line, `unsay` of a word, and `say` again of a name this device has a delete for, are each taken). Rule 2.
- `names.rs`: `hold_mapped_lists_folders_in_order_up_to_the_line` (three folders mapped and room for two: the first two have words and the third has none, and is reported as not synced). Rule 5.
- `crates/cordelia-api/src/person.rs`: `a_statement_carries_no_more_than_the_channel_held` (three devices near the line, one removed: the two that stay each carry every word of their own, and the new personal channel's total is the old one's less the removed device's words, the records and the `applied/` words). Rule 3.
- `crates/cordelia-api/tests/commands_api.rs`: `map_at_the_line_maps_nothing_and_says_why` (the route refuses, the configuration is unchanged, and the answer holds the words of rule 4); and `a_carry_at_the_line_is_refused`. Rules 4 and 5.
- `crates/cordelia-node/src/indicator.rs`: `the_status_is_amber_near_the_line` (amber at `PERSONAL_NAMES_NEAR_BYTES`, none a byte below). Rule 6.
- `crates/cordelia-node/tests/device_entries_e2e.rs`: `a_refusal_for_room_is_said_as_either`. A device and a relay run as real processes, the relay with a small `max_storage_bytes`; the relay refuses for room, and `cordelia devices` shows the line of rule 7. Rule 7.
- `crates/cordelia-storage/src/relay.rs`: `the_room_kept_below_the_line_holds_what_is_never_refused`. A channel holding the line in words takes 64 `applied/` and 64 `left/` words and 320 records of 512 bytes, then 307 words, and refuses the 308th. It holds the constants of §5 to the relay's own count.

## 7. What other records would say

The change would alter these sentences, and no record is changed by this one:

- The record of 2026-10-04, §2.2: "the names that exist and what each device syncs (`name/<the name>`)" gains "up to the line of decision 2026-10-19".
- The record of 2026-10-04, §16: "a device's word that it syncs a name under `name/<the name>`, written when it maps the name and deleted when it unmaps it" gains "and no new word past the line of decision 2026-10-19"; "sized for a device with 256 names" stays.
- The record of 2026-10-04, §9 and §13: a recovery names a name it could not list among those it left.
- The record of 2026-10-17, §7: "On each such device `cordelia devices` names the relay and says that it is full (`look::relays`)" becomes the line of rule 7.
- `parameter-rationale.md` §12.9: the three constants. §12.7 (`MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`): the line is derived from it.
- `CLAUDE.md`, the table of constants: one line for the three.

## 8. The review of the first draft, and where each finding stands

| Finding | Severity | Where it stands |
|---|---|---|
| 1. The bound cut a person's recovery to 192 names | High | Does not apply. There is no bound for each device, and a recovery carries 1,024 names as today, into a new channel where they take 1.3 MB at most. A name it cannot list is named (rule 5). |
| 2. A stopped name can count for ever; the line promised a date and a way out that frees nothing | High | Settled in the rule. §1 says a delete stays while any device syncs the name and 90 days after. The words of rule 4 promise no date, and name the ways out that work: stopping a name on every device, and removing a device. The line is some 12,000 words, which no ordinary use reaches. |
| 3. The relay test asserted a refusal at 193, which a correct relay takes | Medium | Settled. The test of §6 asserts 307 words taken past what is kept, and the 308th refused, from the record's own sum. |
| 4. No "not running" branch exists, and `hold_mapped` was unbounded | Medium | Settled. The check is in `names::say`, which every path that writes a new word goes through (§1). `hold_mapped` goes in the order of mapping, and a folder past the line is said as mapped and not synced (rule 5). |
| 5. The gap between a device's sweep and a relay's was understated | Medium | Settled as a stated limit. §2 names every case of a late take, and that the 307 words are all that covers it; past them the relay refuses. |
| 6. Rule 5 kept an over-bound device over for ever; what fails at the cap was not said | Medium | Settled. No device keeps a grant over the line. §1 says what a relay refuses at the cap and what a person sees. A statement never grows the channel (rule 3). |
| 7. The words a person reads | Low | Settled. Rules 4 to 7 address "you", in short sentences, and promise nothing that is not so. |
| 8. Tests that pass with the rule taken out | Low | Settled. Each test of §6 names the rule it would fail without. |
| 9. More than 64 authors; 320 records not proved; the total was not weighed | Low | The total is the rule. Authors that do not count are a stated limit (§2). 320 is said to be a sizing, not a bound. |
