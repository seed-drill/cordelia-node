# Decision: the names a device may list in the personal channel

**Date**: 2026-10-19
**Status**: Proposed. Not built.
**Cited as**: code comments will cite this record as "decision 2026-10-19", and its rules as "§2, rule 3". The numbers do not change.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md), and **the record of 2026-10-17** is [`2026-10-17-recovery-and-carrying.md`](2026-10-17-recovery-and-carrying.md).
- **A word** is an entry that a device writes in the personal channel under `name/` and a name: a text where it syncs the name, a delete where it has stopped (the record of 2026-10-04, §2.2 and §16).
- **The cap** is what one channel may hold at a relay, `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, 16 MiB (16,777,216 bytes), counted as entries are counted (`entry_cost`).
- **Alpha.12** is the release 0.2.0-alpha.12, and **this version** is the version of the node that first carries what is below.
- Examples say laptop and desktop.

---

## 0. What this is

The personal channel does not fit at a relay at the limits that the record of 2026-10-04 sizes for. With 64 devices that each sync 256 names, the words alone are 16,384 entries of 1,280 bytes as a relay counts them: 20,971,520 bytes, a quarter over the cap. The relay takes the first 13,107 and refuses the rest. Nothing is wrong, and memory still syncs, but other devices and a recovery do not learn of the names, devices and changes whose entries were refused.

Nothing in the record or the code bounds the names a device syncs. This record bounds them: **a device lists at most 192 names in the personal channel** (`MAX_NAMES_PER_DEVICE`), counting each name it has stopped until its delete is swept. At 64 devices that is 15 MiB, and the other mebibyte is kept for every other entry of the channel. Nothing on the wire changes, and no relay changes.

## 1. What the code does today

**A word is one entry for each device and each name it lists.** Its slot is the HMAC of `name/` and the name (`names::word_name`, `crates/cordelia-api/src/names.rs:77`). A device writes a text there when it comes to sync the name or holds it by a carry, and a delete when it stops (`names::say`, `unsay`, `hold_for_a_carry`). Several folders mapped to one name are one word.

**A word is always counted at 1,280 bytes.** It says the name's length (2 bytes), `name/` and a name of at most 200 bytes (`sync::valid_sync_name`, `crates/cordelia-api/src/sync.rs:220`), the value's kind (1), an empty text's length (2) and an empty chain (2): at most 212 bytes, 240 with the nonce and the tag (`ITEM_SEAL_OVERHEAD_BYTES`, `protocol.rs:330`). The content is padded to a power of two from 256 (`entry::content_size`, `crates/cordelia-crypto/src/entry.rs:615`; `MIN_ENTRY_CONTENT_BYTES`, `protocol.rs:950`), so every word, and every delete of one, is 256 bytes. A relay counts each entry at its content and 1,024 more (`entry_cost`, `ENTRY_OVERHEAD_BYTES`, `protocol.rs:341` and `347`).

**The channel grows with names, not with changes.** A relay keeps the newest revision for each author in each slot (`relay::taken`, `crates/cordelia-storage/src/relay.rs:548` to `579`): a later word replaces the earlier one, and a write that makes the channel hold no more is always taken. But a delete stays for 90 days, at the same size, so a name a device stopped syncing is counted for 90 days after.

**What else a device writes there, each counted as a relay counts it:**

| Entry | Content | Counted | How many |
|---|---|---|---|
| `name/<name>` | 256 | 1,280 | One for each name each device lists, and each it stopped in the last 90 days |
| `applied/<its key>` (`person.rs:755`) | 256 | 1,280 | One for each device, under each statement |
| `left/<its key>` (`leaving.rs:101`) | 256 | 1,280 | One for each device that left, at most |
| `added/<key>` (`person.rs:790`) | 512 | 1,536 | One for each adder and key it added, under the statement; not carried to the next |

Messages are in a channel of their own ([`2026-10-09-messages-between-your-own-agents.md`](2026-10-09-messages-between-your-own-agents.md) §2.1, asserted within the cap at `protocol.rs:2052`), and the change entry is in the phrase's channel. Nothing else is written in the personal channel. So at D devices that each list N names, with each device's word that it applied and a record for each device added:

D × N × 1,280 + D × 1,280 + (D − 1) × 1,536 ≤ 16,777,216

**The limits at which the personal channel reaches the cap:**

| Devices | Most names each that fit |
|---|---|
| 1 | 13,106 |
| 4 | 3,274 |
| 8 | 1,636 |
| 12 | 1,090 |
| 16 | 817 |
| 32 | 407 |
| 50 | 259 |
| 51 | 254 |
| 64 | 202 |

At 256 names each, 50 devices fit and 51 do not. At 1,024 names each (what a recovery carries, `RECOVERY_MAX_NAMES`), 12 fit. A throwaway test against the relay's own store took 13,107 entries of the 16,448 that 64 devices write (each one's `applied/` word and 256 words), held 16,776,960 bytes, and refused from the 51st device's 244th word on. A delete over a word it held was still taken.

**Nothing bounds the names.** The record of 2026-10-04 bounds devices (64, `MAX_STATEMENT_DEVICES`), removed keys and statements. Of names it says only that a request count is "sized for a device with 256 names" (§16, line 960; `parameter-rationale.md` §12.8, `ENTRY_REQUESTS_PER_PEER_PER_MINUTE`), which is a sizing assumption, and that a relay keeps the proofs of 1,024 channels for one connection (§2.5). A recovery carries 1,024 names at most and names the rest (`RECOVERY_MAX_NAMES`, `recover.rs:1003`). `cordelia sync map` maps any name.

**What happens today when a relay refuses a word for room.**

- The relay answers `NoRoom`: the wire has one answer for a relay that is full and a channel at its cap (`messages.rs:796`).
- The device keeps the entry, offers it again after a wait that doubles up to ten minutes, and goes on past it to what follows (`at_relays.rs:1150` to `1170`; `device_entries.rs:2315` to `2340`).
- Its status is amber, "memory: a relay has no room", for 20 minutes after each refusal (`indicator.rs:479`, `NO_ROOM_STANDS_SECS`), so for as long as it offers the entry again; on the bar too, since the level is the same. The line shows only on a device that syncs a folder.
- `cordelia devices` says "<relay> had no room for a new channel at <time> (it is full)" (`look.rs:1388`). Both halves are wrong here: the channel is not new, and the relay is not full.
- `cordelia sync map` says nothing: it maps, and the word waits (`main.rs:4353`).
- On the other devices the name is not listed. They do not prove its channel each day; `remove-device` does not show it among the names only the removed device lists; and a device's `applied/` word or a record of an addition that is refused is not seen, so a device added then counts on no other device that reads at that relay (the record of 2026-10-17, §7).
- A recovery reads the channel to its end (the record of 2026-10-17, §3) and carries the names it finds. A name whose every word was refused at every relay is not among them, and is not named as left.
- After a removal every device carries its words into the new personal channel, and the same happens again there, to whichever devices send last.

## 2. The rules

1. **A device lists at most 192 names in the personal channel** (`MAX_NAMES_PER_DEVICE`). It counts its own entries under `name/` in the personal channel of the statement it has applied, texts and deletes alike, as its store holds them. A delete counts until the device sweeps it (the record of 2026-10-04, §2.3).
2. **A device writes no word for a new name at the bound.** Where it has a word for the name already, a text or a delete, it writes over it: that takes no more room, and is never refused. So a name stopped and mapped again costs nothing.
3. **`cordelia sync map` refuses a new name at the bound, before it maps anything,** and says: "This device lists 192 names in the personal channel, the most one device may: <n> it syncs, and <m> it stopped syncing, each counted for 90 days after (the first is freed on <date>). Nothing was mapped. Map this folder on another device, or unmap a name here." Where the node is not running, `map` maps, and the node holds to rule 2 at its next cycle: the folder is listed as mapped and not synced, its status says why, and `cordelia sync map` says the same of it.
4. **`cordelia sync carry` and a recovery hold to the same bound.** A carry of a name that this device does not list refuses at the bound, with the line of rule 3. A recovery carries at most what the bound leaves on the new machine (`RECOVERY_MAX_NAMES` becomes `MAX_NAMES_PER_DEVICE`), and names the names it leaves, as it names those beyond 1,024 today.
5. **A device that lists more than 192 when it takes this version keeps them all.** It writes no word for a new name until it is below the bound, and its status and `map` say so. Nothing is unmapped for it.
6. **What `cordelia devices` says of a refusal for room no longer says "a new channel" or "it is full".** It says "<relay> had no room for what this device sent, at <time>: the relay is full, or a channel of this device's own is at its cap there". (The wire cannot tell the two apart, and this record changes no wire.) A refusal of the change entry, and a refusal for the address's allowance, are said as today.

**Why it fits.** 64 devices × 192 names × 1,280 is 15,728,640 bytes, 15 MiB. The mebibyte left holds every other entry that devices that keep to the rules write under one statement: 64 words that a statement is applied and 64 that a device left (163,840 bytes), and 320 records of an addition, which is what a reader counts and keeps (`MAX_COUNTED_DEVICES` and `MAX_NOT_COUNTED_RECORDS`; 491,520 bytes). That leaves 393,216 bytes, 307 words, for rule 1's one gap (below).

**Its limits.**

- A device counts a delete from when it stored it, and a relay from when it took it. A device that stopped names while it was off sweeps those deletes before the relay does, and can map as many new names in that gap. The 307 words of room cover one device that does so with all its names, not many at once.
- A device that counts, in someone else's hands, can still fill the channel at a relay with records (the record of 2026-10-17, §7). This record bounds what devices that keep to the rules write, and nothing else.
- The bound is per device, and so is low for a person with few devices: one laptop alone could list 13,000 names. A bound that grew as devices were fewer would change when a device is added, and could not take back what was listed.
- A device of alpha.12 beside a device of this version lists as many names as today. The channel fits only once every device of the person's runs this version.

## 3. Set aside

- **A larger room for the personal channel at a relay.** A relay cannot tell the personal channel from any other channel of this kind, by design (the record of 2026-10-04, §2.4 item 4), so the room is raised for every channel: 32 MiB, to hold 64 × 256 words. Every relay changes, one channel may take twice as much of a relay, a channel filled by a device in someone else's hands takes twice as much, and a recovery reads twice as long (`RECOVERY_READ_ON_MAX_SECS` is derived from the cap: 615 seconds becomes 1,111). And names stay unbounded, so it moves the line and still needs a bound.
- **A smaller word.** A word is in the smallest size class already, and the 1,024 that every entry is counted with beyond its content is 64 × 256 × 1,024 = 16 MiB by itself. A smaller word needs a smaller count for every entry at every relay, and that count is what makes a limit on bytes mean something for small entries (`parameter-rationale.md` §4).
- **A word that holds several names:** one entry for each device, `names/<its key>`, listing every name it syncs. 256 names of 200 bytes fit one entry of 64 KB, so 64 devices take 4.3 MB, and no delete is kept for each name stopped. It is the better form, and the next step if 192 is found tight. Its costs: a new kind of entry in the personal channel, which every device and every recovery must read beside `name/` for as long as a left generation's personal channel can hold `name/` (90 days); a device of alpha.12 does not read it, and so neither proves those channels, nor shows those names at a removal, nor carries them at a recovery made with its command; each map and unmap writes up to 64 KB again. And it still needs a bound, on what fits in one entry.
- **Each of these needs a bound on names,** since nothing else bounds them. The bound alone is the least change.
- **192 rather than 256.** 256 names at 64 devices is 20 MiB, over the cap with nothing else. 192 is the most that fits with a mebibyte kept for the rest. The request count stays sized for 256 names (§16), which is now above what a device lists.

## 4. On the wire, and beside alpha.12

**Nothing on the wire changes.** No entry, stream, answer or statement changes form, and no relay changes. A word is as before. The bound is a check that each device makes on what it writes.

**A person whose devices run alpha.12 and this version at once:** each device of this version lists at most 192 names, and each of alpha.12 any number. Each reads every word the other writes, as today. Where an alpha.12 device takes the channel to the cap, the relay refuses as today, and the devices of this version say so with the line of rule 6. A recovery made with this version carries at most 192 names onto the new machine, whichever version wrote them, and names the rest.

## 5. The constant

`MAX_NAMES_PER_DEVICE: usize = (MAX_ENTRY_CHANNEL_BYTES_AT_RELAY − NAMES_ROOM_KEPT_BYTES) / (MAX_COUNTED_DEVICES × entry_cost(MIN_ENTRY_CONTENT_BYTES))`, with `NAMES_ROOM_KEPT_BYTES = 1 MiB`: (16,777,216 − 1,048,576) / (64 × 1,280) = 192. Asserted in `protocol.rs`: that the longest word, a text or a delete, is a content of `MIN_ENTRY_CONTENT_BYTES`; and that 64 devices' words at the bound, with 64 `applied/` and 64 `left/` words and `MAX_COUNTED_DEVICES + MAX_NOT_COUNTED_RECORDS` records of the largest size, are within the cap.

For `parameter-rationale.md` §12.9: "**MAX_NAMES_PER_DEVICE = 192.** The most names a device lists in the personal channel, counting each name it stopped until its delete is swept (decision 2026-10-19). A word is counted at 1,280 bytes at a relay, whatever the name; 64 devices at the bound take 15 MiB of the 16 MiB a channel may hold, and the mebibyte left holds every word that a statement is applied, every word that a device left, and every record of an addition that a reader keeps. Without it, 64 devices with 256 names each write 20 MiB, and a relay refuses the last quarter. What it costs: a person who syncs more than 192 names on one device syncs the rest on another."

`RECOVERY_MAX_NAMES` becomes `MAX_NAMES_PER_DEVICE`, and its line in §12.9 says so: "the names a recovery carries become the names the new machine lists".

## 6. Tests

- `crates/cordelia-core/src/protocol.rs`: `test_the_personal_channel_fits_at_every_bound_decision_2026_10_19`, the two assertions of §5 and the value 192. Rule 1.
- `crates/cordelia-storage/src/relay.rs`: `a_personal_channel_at_every_bound_is_taken_whole`. A relay at the cap's default takes 64 devices' 192 words each, with the longest name, their `applied/` and `left/` words, and 320 records of the largest size, and refuses none. With 193 words each it refuses. Rule 1.
- `crates/cordelia-api/src/names.rs`: `a_device_writes_no_word_for_a_new_name_at_the_bound` (the 193rd is refused, a name it has a delete for is written over, a delete counts, and one swept frees a place), and `a_device_over_the_bound_keeps_its_names`. Rules 1, 2 and 5.
- `crates/cordelia-node/tests/person_e2e.rs`: `map_says_the_bound_and_maps_nothing`. A device as a real process with 192 names listed, 4 of them stopped, refuses a 193rd folder with the line of rule 3, and its configuration is unchanged; mapping one of the stopped names again is taken. Rule 3.
- `crates/cordelia-node/tests/carry_e2e.rs`: `a_carry_at_the_bound_is_refused`, and `crates/cordelia-node/tests/recover_e2e.rs`: `a_recovery_carries_the_names_the_bound_leaves`. Rule 4.
- `crates/cordelia-api/src/look.rs`: `a_refusal_for_room_is_said_as_either`. Rule 6.

## 7. What other records would say

The change would alter these sentences, and no record is changed by this one:

- The record of 2026-10-04, §2.2: "the names that exist and what each device syncs (`name/<the name>`)" gains "at most 192 for each device (decision 2026-10-19)".
- The record of 2026-10-04, §2.5: "(A relay remembers the proofs of 1,024 channels for one connection, and looks at none beyond them: a person with more names than that is past what this keeps alive.)" gains that a device lists at most 192 names.
- The record of 2026-10-04, §9: "The new machine carries at most 1,024" becomes "at most 192 (decision 2026-10-19)"; and §13: "at most 1,024 are carried, in their order" likewise.
- The record of 2026-10-04, §16: "a device's word that it syncs a name under `name/<the name>`, written when it maps the name and deleted when it unmaps it" gains "and never for a new name beyond 192 (decision 2026-10-19)"; and "sized for a device with 256 names" stays, as a sizing above the bound.
- The record of 2026-10-17, §7: "On each such device `cordelia devices` names the relay and says that it is full (`look::relays`)" becomes the line of rule 6.
- `parameter-rationale.md` §12.7 (`MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`), §12.9 (`RECOVERY_MAX_NAMES`, and the new constant) and §12.6 (the names in the personal channel).
- `CLAUDE.md`, the table of constants: one line for `MAX_NAMES_PER_DEVICE`, and `RECOVERY_MAX_NAMES` as derived.
