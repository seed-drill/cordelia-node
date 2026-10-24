# Decision: a removal fails safe

**Date**: 2026-10-24
**Status**: Proposed. Not built. Where it is built, it amends the records that section 5 names, sentence by sentence.
**Cited as**: "decision 2026-10-24 rule 7", "decision 2026-10-24 §8". The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md). **The record of 2026-10-19** is [`2026-10-19-a-relay-out-of-reach.md`](2026-10-19-a-relay-out-of-reach.md). **The record of relays** is [`2026-10-17-a-devices-relays-and-connections.md`](2026-10-17-a-devices-relays-and-connections.md). **The messages record** is [`2026-10-09-messages-between-your-own-agents.md`](2026-10-09-messages-between-your-own-agents.md). **The shared record** is `2026-10-10-a-shared-channel-for-messages.md`, on the branch `docs/shared-converge`: settled, and not built.
- **This version** is the first that carries what is below. **The version before** is 0.2.0-alpha.16.
- **A change** is a statement and its change entry (the record of 2026-10-04, 4.1 and 4.6). **Change n** is a change whose statement is numbered n. Two changes can have one number.
- **Made after.** A change is made after each change on its chain. **Made apart:** neither is on the other's chain (the record of 2026-10-04, 4.5).
- **A head,** on a device or at a relay, is a change that it keeps and that no other change it keeps was made after.
- **Its removed keys.** The keys that a device knows to be removed: every key that any change it has seen and checked lists as removed, on any branch. They only grow.
- **Who holds a secret.** A change's secret is held by each device that the change lists, and by each key that a record of an addition under that change adds: the hand-over gives it the secret (the record of 2026-10-04, section 6). A shared channel's seed is held by every device of the person's while the person holds the channel (the shared record, property 19), and by each key that an anew record seals it to.
- **Clear.** A secret is clear on a device where none of its removed keys holds it, as far as the device knows. A change is clear where its secret is.
- **To seal** is to write an entry under a secret, or to hand a secret on: in a hand-over, or in an anew record. **To send** is to push what was sealed to a relay.
- **The change a device follows** is the one it has applied and seals under. Every other head it keeps is **set aside**.
- **Closed:** a device that follows no clear change. It replaces "in a fork".
- **Lineage:** the part of a change entry that a relay can read (rule 13).
- Examples say laptop, desktop, tablet and phone, and relay A and relay B. For shared channels they say Alice and Bob for two people, as the shared record does.

---

## 0. What this is

**The ruling** (the project owner, 24 October): "if you remove a device it should no longer be able to access any new information from that point, no failure modes that get around that, everything else is niceties." So a removal must fail safe by how it is built, and not by a warning.

**The fault.** An independent review found it, and a throwaway test with real processes showed it.

- A person has three devices, a laptop, a desktop and a tablet, and two relays. The laptop and the tablet reach only relay A. The desktop reaches only relay B. All three are on change 2.
- The desktop removes the tablet, through relay B. That is change 3, made on the desktop.
- The laptop cannot read relay B. It runs `cordelia renew`, and makes a change 3 of its own, which still lists the tablet.
- The tablet applies the laptop's change 3, and holds its new secret.
- When the two sides meet, each device that sees both is in a fork. `cordelia settle` makes change 4, with the tablet removed, and the tablet then reads that it was removed.
- **Until `settle`,** the tablet holds the secret of one branch, and reads what is written under it. And the removal no longer spreads by itself.

**Why, in the code of the version before.**

1. **A relay keeps one change entry.** Shown a change entry at the number of the one it holds, or below it, a relay answers with the one it holds, and stores nothing (`relay::shown` and `would_take`, `cordelia-storage/src/relay.rs`, lines 969 to 1008). Relay A holds the laptop's change 3. It never takes the desktop's, from a device or from a relay it works with. A device that reaches only relay A is never told of the removal.
2. **A device that sees both stops, and spreads nothing.** It keeps both entries, and goes on showing each relay the one it had applied (the record of 2026-10-04, 4.5; `person::shown` and `judged`, `cordelia-api/src/person.rs`, lines 924 to 1058). The tablet, shown the desktop's change, is in a fork: it is not told that it was removed.
3. **The record of 2026-10-04 says so itself** (4.5, "Which devices see a fork"): the devices of the branch that the relays hold "may never be shown the other, and go on". Each of them seals under a secret that the tablet holds, for as long as that lasts. With two relays that pass entries to each other, and no device that reaches both, it lasts for good.

What the version before gets right: a device that has seen both seals nothing. What it gets wrong: a removal can stop at a relay, and a removal takes effect on such a device only by stopping it.

**What this record does.**

1. A device keeps every head it is shown, and every key that any of them removes. It seals only under a clear secret, and takes nothing that a removed key sends. What a removed key wrote in a branch made apart from its removal is never carried on (rules 1 to 7).
2. A device that follows a change which is not clear moves, with no phrase, to a clear change that lists it. Where there is none, it is closed: it seals nothing until a person joins the two with the phrase (rules 8 to 12).
3. Each change entry says its lineage in the clear. A relay keeps every head by it, and hands each to every connection before it says that it holds the entry shown (rules 13 to 19).
4. Every change made from here lists as removed every key that its device knows to be removed (rules 20 to 22).
5. A removal makes each shared channel anew, for when shared channels are built (rules 23 to 26).
6. The window that physics leaves is stated, with its bound (section 8).

## 1. The properties

Each is a promise to a person, and each has tests (section 7). Where a property has a limit, the limit is stated with it.

1. **No change on any branch lets a removed device open what is sealed after the sealing device knew of the removal.** That holds for a renewal, an addition, a removal, a settlement and a recovery. Every secret made after a removal is new and random. None is derived from a secret that a removed device holds.
2. **A removal takes effect on a device as soon as that device reads it, with no person's act,** even where the device also holds a change made apart that lists the removed device. `cordelia settle` may still join the two histories. It is never what makes a removal work.
3. **It fails closed.** A device that holds no secret clear of every key it knows to be removed (for example, each side removed a different device) seals nothing new. It keeps new content on the device, and asks for `cordelia settle`.
4. **Shared channels too.** Removing a device cuts it off from new content in every shared channel that the person holds. A seed does not change at a statement, so a removed device would go on reading it. Making each channel anew at the removal is what cuts it off (rules 23 to 26). **Its limit:** what another person writes there is cut off once that person's device has read the offer, and stays cut off unless that person says, at a terminal, to go on in the old channel.
5. **Nothing sent after a removal is applied.** This is the project owner's own ruling (24 October: "agreed, nothing sent after removal is applied"). What a removed device seals or sends after its removal is never taken by a device that knows of the removal: no version of a file, and no message between the person's agents. A stolen device does not send, as one of the person's agents, to a device that knows. **Its limit** is the window of property 6: what a device took before it knew. Of that, what the removed device wrote in a branch made apart from its removal is never carried on, and goes from the folders (rule 7). What it wrote in a generation that its removal was made after is carried as the record of 2026-10-04 has it (its property 2), because no device can tell it from what was written before the removal (section 12 asks the person).
6. **The one limit that physics sets.** Until a device has read the removal, it can seal under a secret that the removed device holds: while it is off, or cut off from every relay that holds the removal. Section 8 states it as a window with its bound, and says what narrows it.

## 2. The rules

### What a device knows of removals

**Rule 1. A device keeps every head it is shown.** It keeps the change it follows, and up to seven heads set aside: eight in all (`MAX_CHANGE_HEADS`). A head set aside goes when the device applies a change that was made after it, or keeps one set aside that was. A change is kept only where the phrase that the device follows signed it, it is well formed, and its lineage matches its statement (rule 13), or it has none (it was made on the version before).

- Where a ninth would be kept, the device is closed. Only a phrase that makes nine branches at once reaches that.
- **Where:** the rows of `person_change_entries` (`latest` and `apart` become the change followed and the heads), in a step of the schema; `person::shown` (`person.rs` 924).

**Rule 2. A device keeps its removed keys.** Every key that any change it has seen lists as removed is kept, whether the device follows that change, sets it aside, or finds it behind, with the first change that removed it on each branch (rule 7 asks it). A key is never taken out. At most 2,048 (`MAX_KNOWN_REMOVED`, eight heads of 256 each).

- **Where:** a table beside `person_change_entries`. `Counting` (`person.rs` 243) takes them as its removed keys, in place of those of the statement applied alone (`Counting::of`, line 262; `publish::Standing::of`, `publish.rs` 407).

**Rule 3. Who holds a secret, as a device knows it.** A change's secret is held by the devices it lists, and by each key that a record of an addition under it adds, of the records this device has seen. A shared channel's seed is held as the words above say. A secret is clear where none of the device's removed keys is among them.

- A record that this device has not seen is one more thing it has not read: section 8 counts it in the window.
- **Where:** one function beside `Counting`, which every rule below asks.

### What a device seals under

**Rule 4. A device seals only under a clear secret.** That is every entry it writes in a channel of its own, every hand-over, and (when shared channels are built) every message and anew record in a shared channel.

- **The store enforces it.** Every path that seals reaches the secret through one of two functions: `person::applied_secret` (`person.rs` 1792), and `publish::Standing::to_write` (`publish.rs` 422), which already refuses a device that does not stand applied. Both refuse a secret that is not clear. So a fault elsewhere cannot seal under a secret that a removed key holds. The paths are publishing (`publish.rs` 410), the one door (`take.rs` 203), a hand-over (`adding.rs` 1251), a device's word that it left (`leaving.rs` 224), a name's word (`person.rs` 768) and a message (`sender.rs`, `Ring::of`, through `Standing::to_write`).
- A device that leaves its phrase while it is closed (`cordelia phrase`, `cordelia init --new-key`) leaves without its word that it left: that word would be sealed under a secret that a removed key holds.

**Rule 5. From the moment a device reads a removal that makes the secret it follows not clear, it sends nothing more under that secret,** on any connection. What waits to be sent under it is taken out of what waits, and stays in the device's store.

- It is today's rule for a change that a device can apply (the record of 2026-10-04, 4.2: "From the moment a device is answered with a change that it can apply, it sends nothing in an old channel"), made to hold for a removal on any branch.
- **Where:** the same moment as today's (`device_entries::answered_with`, `device_entries.rs` 1830), and the rule that a request is sent only under the change entry it was built under (the record of 2026-10-04, §16), which now ends a pass where the device's removed keys grow, as where the kept entry changes.

**Rule 6. A device takes nothing that one of its removed keys signed,** from any channel, in any generation, from the moment it knows. A record of an addition for such a key counts for nothing. `cordelia add-device` refuses such a key. It is what makes property 5 true, the owner's ruling, for a device that knows.

- **Messages between the person's agents.** A message is shown only while its signer counts (the messages record, property 1). So from the moment a device knows of a removal, on any branch, `cordelia msg summary`, `msg read` and every hook show nothing that the removed key signed, and a reply to it is refused. What the device held of such a key's messages before it knew is shown by `cordelia msg log` alone, as the messages record has it for a removal today.
- An act in a person's list of shared channels is the shared record's (3.4, 3.5): an act of a removed key's that arrives as a copy is taken and named, with what undoes it. That record decided so, and this one does not change it.
- **Where:** `Counting::counts` and `Counting::judge` read the removed keys (rule 2). `adding.rs` 161 and 234 ask `statement.removes` today; they ask the removed keys.

**Rule 7. What a device sealed, and took, under a change before it learned that the change is not clear.**

- **What it sent is at the relays,** and the removed device can read it there. Nothing undoes that. It is the window of section 8.
- **What it holds,** sent or not, it carries into the change it moves to (rule 9), as at any change (the record of 2026-10-04, 7.3). While it is closed, it keeps it in its store, and carries it at the settlement.
- **What waited to be sent is never sent under the old secret** (rule 5).
- **What it took from the removed key in that time, in a branch made apart from the removal, is never carried on.** At any carry (a move, an apply, a settlement), a version that a removed key signed, in a generation made apart from a change that removed that key, is not carried. In its slot the device carries instead the newest version that a key which counts signed. A folder whose file holds the removed key's text goes back to that version, as `cordelia restore` puts a version back, and the removed key's text is kept in local history alone: not beside the file, where an agent would read it, and not in any channel. In the fault, that is everything the tablet wrote under the laptop's change 3: the laptop took it before it knew, and none of it reaches the desktop's change.
  - **Why a generation made apart.** A removal is made over the history on its chain. A generation made apart from it is history the removal never saw, so what the removed key wrote there came after the person removed it. A generation that the removal was made after is history it saw: what the removed key wrote there before the removal and what it wrote after look the same, and are carried as the record of 2026-10-04 has it (its property 2), with that key in the first link, so that every other device keeps its own text beside it. That is property 5's limit.
  - A version that a device of the person's wrote over the removed key's text is that device's own, and is carried, as an agent's work on a remaining device is today (the record of 2026-10-04, 7.4). Its chain names the removed key, so every device that knows keeps its own text beside it.
  - The device knows which change removed each removed key: rule 2 keeps it with the key.
- From the moment the device knows, it takes nothing more of that key's (rule 6).
- **Where:** `Carry::channel` (`person.rs` 1833), whose `counts` leaves out such a key in such a generation; and the record of each folder moved at the carry (`move_records`, `person.rs` 1682), which names the version carried, with the file put back as `cordelia restore` puts it back (`cordelia-sync`, the record of 2026-09-30, 4.5b).

### Which change a device follows

**Rule 8. One function decides,** each time a device is shown a change that it does not keep, and at its first start on this version (rule 12). In this order:

1. A change that is the one followed, a head kept, or behind one of them: nothing is done, as today.
2. Otherwise the device checks it (the signature, the form, the lineage), adds its removed keys (rule 2), and drops each change set aside that it was made after.
3. **A change that lists this device's key as removed stops the device, as removed,** whether it was made after the change followed or apart from it. (Today a change made apart is a fork, even where it removes this device.)
4. A change made after the one followed, that lists this device and is clear: the device applies it, as today. Where its secret does not open, the device stops, as today (4.5).
5. A change made after the one followed that lists this device in neither list stops it, as in no list, as today (the record of 2026-10-04, 4.3), whether or not it is clear.
6. Anything else is kept as a head set aside. Where the change followed is still clear, nothing more is done: the device goes on (rule 11).
7. Where the change followed is not clear, the device moves (rule 9) to the best change it keeps that is clear, lists it, and whose secret opens for it: the one with the highest number, and of two at one number, the one whose hash is lower.
8. Where there is none, the device is closed (rule 10).

- A device that was removed, is in no list, or could not open a change takes no change, as today: the way on is a person's.
- **Where:** `person::shown` and `judged` (`person.rs` 924 to 1058) and `statement::judge` (`statement.rs` 667). `judge` keeps rules 1, 2, 5 and 6 of 4.2 for a change made after the one followed. `judged` gains the test of rule 3, the move and the closing.

**Rule 9. A move needs no phrase.** It is an apply, in one transaction, as 4.2 says: the device stores the change and its secret, leaves the generation it was in, carries what it holds (7.3), and keeps the change it left as a head set aside.

- Two rules of 4.2 are not asked of a move: that the number is above the one followed (rule 2), and that the change was made after it (rule 6). Rule 5 of 4.2, that no removal is undone, is kept by the device's removed keys, which only grow.
- **A move to a lower number.** The renumbering of 2.3 runs forward only. A version, or a folder's record, whose revision is in a band above the change moved to is not carried as a version: the record is dropped, and its file meets the new channel as a new file does (4.2). A revision is in such a band only where a device jumped (2.3), so this is rare.
- **A command that waits after a change the device has moved from** ends with status 3, as for any change applied since (decision 2026-10-19, rule 8), and says: "a change made apart on <label> removed <label>, which this change lists: this device follows that change now".
- **Where:** `person::apply_judged` and `come_to` (`person.rs` 1454, 1511), and `Carry` (1808).

**Rule 10. A closed device seals nothing, sends nothing, and takes nothing in a channel of its own.** It is the state that a fork is today, and it is stored under the same name (`fork`).

- It keeps new content on the device: its folders keep their files, and nothing is published. What waits stays in its store.
- It shows each relay every head it keeps (rule 18), and has no leave anywhere.
- It says, in red on its status line and in `cordelia devices`: "two changes were made apart, and none that lists this device is clear of a removed device: settle it with the phrase (`cordelia settle`)", with the lists of each head.
- It leaves the state by rule 8, when it is shown a clear change that lists it: the settlement, or a change made after it.
- `cordelia add-device`, `cordelia accept` and the commands of `msg` refuse there, as in a fork today. `cordelia remove-device`, `cordelia renew` and `cordelia settle` there make the settlement (rule 21).
- **Where:** `held_rows::set_state`, `at_relays::stands` (`at_relays.rs` 123), `device_entries::pass_at` (`device_entries.rs` 1023) and `say` (2967).

**Rule 11. A device that follows a clear change goes on, with any head set aside.** It syncs, sends and takes as any device does.

- `cordelia devices` names each head set aside, with its lists, and, where it is not clear, the removed key it lists: "a change made apart on laptop (change 3) lists tablet, which a change made on desktop removed: it is set aside". The status line is amber for seven days from when the head was set aside (`REMOVAL_NOT_APPLIED_SHOWN_DAYS`), and `cordelia devices` names it until a change joins it (rule 21).
- **Two devices that each follow a clear change made apart go on apart.** (Each removed the same device, say.) They do not sync with each other until a change joins them. Nothing is sealed where a removed key reads: that is a cost, not a fault.

**Rule 12. At its first start on this version,** a device that is in a fork applies rule 8 to the entry it kept apart: it moves, goes on, or stays closed. An entry of the version before has no lineage, and is judged by its statement alone.

### How a removal reaches every device

**Rule 13. A change entry says its lineage in the clear.** At the end of its content: a mark (the first 8 bytes of SHA-256 of the label `cordelia v2 lineage`, `LABEL_CHANGE_LINEAGE`), the hash of its statement, a count, and the hash of each statement on its chain; then zeros. Each hash is the first 8 bytes of the statement's hash (`LINEAGE_HASH_BYTES`).

- **It fits.** The part for the phrase shrinks from 4,096 bytes to 1,024: at every bound it needs 382 (a nonce, a tag, the secret, a count, and eight earlier secrets with their numbers). The lineage takes the 3,072 freed: 2,066 at its bound, a chain of 256. **The part for the devices does not move,** so a device of the version before opens it as before (section 6).
- The entry's two signatures cover all of its content, so only the phrase can write a lineage.
- **A device refuses an entry whose lineage does not match its statement:** it is not well formed. An entry with no lineage (one made on the version before) is judged by its statement alone.
- **Why 8 bytes.** A relay uses them only to tell apart the statements of one phrase, and only the phrase makes one. Two of 256 share 8 bytes with a chance of about 2^-49.
- **Why the whole chain, and not the statement before.** A relay can then tell that one entry is behind another without having seen those between.
- **Where:** `cordelia-crypto/src/change_entry.rs` (its layout, building, opening, and an opener of the part for the phrase in each layout), and `protocol.rs` (`CHANGE_ENTRY_PHRASE_PART_BYTES`, `CHANGE_ENTRY_LINEAGE_BYTES`, `LINEAGE_HASH_BYTES`, `LABEL_CHANGE_LINEAGE`).

**Rule 14. A relay keeps every head.** In a slot, for one author, where entries carry a lineage, a relay keeps each entry that no other entry it keeps was made after, by the lineages: up to eight (`MAX_CHANGE_HEADS`), the highest numbers first.

- **An entry that another one it keeps was made after is not stored,** whether it is shown or passed. A change shown again is such an entry: whoever shows every change of a branch again pushes no head out.
- **An entry that was made after some that it keeps replaces them.**
- **An entry made apart from all that it keeps is kept beside them.**
- **An entry with no lineage** (made on the version before) is kept as today: while no entry in the slot has a higher revision. So a change made on the version before behaves as it does today, and a change made on this version is never dropped for one.
- **Where:** `cordelia-storage/src/relay.rs` (`would_take`, `shown`, `taken`: lines 969, 975, 537), and the relay's pull from a relay it works with (`relay_entries.rs`, `pulled`).

**Rule 15. A relay keeps room for a second head.** It counts a slot whose entry carries a lineage at twice that entry's size, from when it takes the first such entry there. So a second head always has room, and a removed device that fills a relay with the old channels it holds cannot keep a removal out of it.

- **In a slot that is new,** the room for both is asked when the first entry comes, as for any new entry.
- **Where the first such entry replaces one of the version before** (a person's first change made on this version), the relay takes it all the same, as it takes any replacement that is no larger. Where it has no room for the second share, it makes the room as a relay whose cap came down does: its newest channels first (the record of 2026-10-04, 2.5). The phrase's channel is the one a relay has held longest, so it is never what goes.
- A third head, and those after it, take room as any new entry does.
- **Where:** the relay's count of its room (`Room`, `relay.rs`).

**Rule 16. A relay hands every head before it says that it holds the entry shown.** Shown an entry, whole or in short, a relay first hands, one in each answer, each entry that it keeps in that slot and that the connection has neither shown nor been handed, the lowest number first, and of two at one number the lower ID: whole, as today's "another" (`ShowAnswer::Another`), or, to a short show, its revision and ID (`ShowAnswer::Other`). Only once there is none left does it answer that it holds the entry, took it, or refused it for room.

- The answers are today's. A device of the version before reads each as it does now (section 6).
- A relay remembers, for a connection, each entry that it was shown whole or handed there, up to eight in a slot, as it remembers today the one shown whole (2.4, item 5; `ShownWhole`, `relay_entries.rs` 241). So a device that shows every head it keeps (rule 18) shows each in short after the first time.
- **The lowest number first:** a device that slept through two changes made apart meets the lower first, and so does not apply a higher one only to move from it.
- **Where:** `relay_entries.rs` (`shown`, `shown_short`, `ShownWhole`: lines 674, 758, 241) and `relay.rs` (`show`, `show_short`: 949, 1035).

**Rule 17. Relays pass every head on.** A head that a relay keeps beside another is passed on to the relays it works with, as an entry it took is today (`RelayEntries::took` and `pass_on`, `relay_entries.rs` 1071 and 1625, each 5 seconds: `ENTRY_OFFER_INTERVAL_SECS`). Today an entry is passed on only where it was stored as the newest of its author in its slot.

**Rule 18. A device shows every head it keeps,** to each relay, on every pass: each head set aside first, and the change it follows last. So a removal stays at a relay for as long as any device that knows of it is on, and reaches every relay that such a device reaches.

- **Leave comes from the answer to the change it follows,** as today. **An answer that hands a head the device keeps gives leave too.** A relay of the version before answers so for good where it holds a head that the device has set aside; the device then knows all that the relay holds.
- **Only the answer to the show of the change followed is the relay's latest answer** in the sense of the record of 2026-10-19 (§1). So a relay that holds a head set aside, and not the change followed, lacks the change, and the status says so.
- **Where:** `at_relays::to_show` (`at_relays.rs` 148), `device_entries::show_round` (`device_entries.rs` 1667 to 1792), and the leave (`leave.rs`).

**Rule 19. A change in what a device keeps wakes its pass at once.** Where it moves, closes, applies a change, or sets a new head aside, it shows at every relay it reaches at once, as a publish wakes the pass that sends today, and does not wait for its next pass.

### Changes made from here on

**Rule 20. Every change lists as removed every key that its device knows to be removed,** and lists none of them as a device. `cordelia remove-device`, `cordelia renew` and `cordelia settle` are handed the removed keys by the node, show them, and sign them; `cordelia recover` reads them itself (rule 22). The node refuses a change of its own that lacks one, or lists one as a device.

- **Where:** `commands::change_prepare` (`commands.rs` 1091), `change::prepare_change`, `prepare_settlement` and `prepare_recovery` (`change.rs` 125, 153, 192), and `person::apply_made` (`person.rs` 1203).

**Rule 21. A change made on a device that keeps a head set aside joins it.** There, `cordelia remove-device` and `cordelia renew` make a settlement: its chain holds the change followed and every head set aside, and its prompt asks of each device of a head set aside as `cordelia settle` asks today. `cordelia settle` is the same, with no device named. So any change made there joins the histories. On a closed device the three make the settlement too.

- `cordelia settle` on a device that keeps no head set aside is refused, as today.
- The part for the phrase of a settlement holds the secrets of every branch it joins, as many as fit (`MAX_EARLIER_SECRETS`), the newest first.
- **Where:** `change_prepare` (which refuses `settle` today on a device in no fork, `commands.rs` 1103), and `Statement::settle` (`statement.rs` 311), which comes to take more than two heads.

**Rule 22. A recovery lists one device,** as today. So its secret is clear by construction. It lists as removed every key that any change it read removes (the record of 2026-10-04, section 9, step 2, already settles two found apart).

### Shared channels (for when they are built)

**Rule 23. A removal makes every shared channel that the person holds not clear.** A device seals nothing in a shared channel whose seed one of its removed keys holds. Every device of the person's holds every shared channel (the shared record, property 19), so a removed key held every seed the person held while it counted.

**Rule 24. The device that makes a removal makes each shared channel anew, in the same act.** After the transaction that applies the change, its node makes each channel anew as `cordelia shared anew` does (the shared record, section 7): a new seed, sealed to every key of the device's table of that channel but its removed keys. The person's own devices stay through the person's list.

- **The person's other devices follow,** with no yes: the filing is in the new personal channel, which the removed device cannot read (the shared record, 3.4).
- The removal's prompt names each shared channel, and says that it will be made anew without the device removed, and that the other people in it move with a yes of their own. The one yes of the removal covers it.
- A recovery does the same.

**Rule 25. A device that applies a removal and finds a shared channel that the person has not made anew** (the device that made the removal was lost first, or the filing has not come) sends nothing there, and says so: "<name> was held by a device that was removed: make it anew with `cordelia shared anew <name>`". It does not make the channel anew by itself: two devices would make two channels.

**Rule 26. Another person's device that reads an offer which seals to its person and leaves out a key sends nothing more in the old channel.** What its agents send there waits, and the send says why. It goes on when its person moves (`cordelia shared move`, with a yes, as the shared record has it), or says at a terminal, with a yes, to go on in the old channel, where the keys left out read: `cordelia shared stay <name>`. An offer that leaves this person out ("without you") changes nothing here.

- **Why.** A removed device of Alice's is a key to Bob, and Bob's device cannot know that it was removed. The offer is what it can read.
- It changes a settled record, and is for the person to confirm (section 12).

## 3. What makes each property true

| Property | The rules that make it true |
|---|---|
| 1. Nothing sealed after a device knew opens for a removed device | Rule 4: a device seals only under a clear secret, in the two functions that every path takes the secret from. Rule 20: every change lists every key known to be removed, so a renewal, a removal and a settlement made by a device that knows are clear. An addition hands over only a clear secret (rule 4), and never to a removed key (rule 6). Rule 22: a recovery lists one device. Rule 9: a move is only to a clear change. Every new secret is random (`statement::new_secret`), and every channel is derived from one, or from a random seed. |
| 2. A removal takes effect when it is read, with no person's act | Rule 8: one function, in which step 3 stops the removed device on any branch, and steps 6 and 7 move or close a device whose change is not clear. Rule 9: a move needs no phrase. Rules 13 to 18: a relay keeps every head and hands each before it gives leave, relays pass them on, and devices show them, so a removal is read wherever any device or relay that holds it reaches. |
| 3. It fails closed | Rule 10, and rule 4 beneath it. |
| 4. Shared channels | Rules 23 to 26. |
| 5. Nothing sent after a removal is applied (the owner's ruling) | Rule 6: from the moment a device knows, it takes nothing the removed key signs, messages included. Rule 7: of what it took before it knew, nothing the removed key wrote in a branch made apart from its removal is carried on, or left in a folder. Rule 2 keeps which change removed each key. |
| 6. The window | Rules 5, 16 to 19; section 8. |

## 4. The candidate rule, judged

**The candidate:** a device never seals under a secret that a device removed on any branch it knows can open. In the fault, the laptop, on meeting relay B, drops its own change 3 and seals under the desktop's change 3, of which it is a member, with no phrase.

**The verdict: it is the right rule for sealing, and it is not enough by itself.**

- **It holds in every case below, for a device that knows of the removal,** with "can open" read as rule 3 reads it: listed, or added by a record that the device has seen. It is rule 4.
- **It fails where a device does not come to know.** A relay that holds a change made apart from a removal, at the same number or a higher one, never takes the removal, and never hands it (section 0). In the fault the laptop learns only because it comes to reach relay B. Let the two relays pass entries to each other, and let no device reach both: relay A never takes the desktop's change, the laptop never knows, and it seals under the tablet's secret for good, with the candidate rule kept to the letter. Rules 13 to 18 are needed beside it.
- **It says what not to do, and not what to do.** Rules 8 to 10 say it: move to a clear change that lists the device, or close.

**The cases.**

1. **The fault.** The laptop: its own change 3 lists the tablet, which it knows to be removed, so it is not clear; the desktop's change 3 is clear and lists it, so it moves (rule 9). The desktop follows a clear change, sets the laptop's aside, and goes on (rule 11). The tablet is removed (rule 8, step 3). No `settle` is needed. What the laptop sent under its own change 3 before it learned is at relay A, where the tablet reads it: the window of section 8. What it holds is carried into the desktop's change, but for what the tablet wrote under the laptop's change 3, which is carried by nobody, and goes from the laptop's folders into its local history (rule 7).
2. **Each side removes a different device.** The laptop removes the phone, and the desktop removes the tablet. A device that has seen both: each change lists a device that the other removed, so neither is clear, and it is closed until settle (rule 10). The settlement removes both (rule 20) and is clear. The tablet and the phone are each removed by the change made apart (rule 8, step 3). The rule holds, and gives safety, not going on.
3. **A removal and an addition at once.** The desktop removes the tablet (change 3) while the laptop, on change 2, adds the phone. An addition is no change: the phone holds the secret of change 2, which the tablet holds anyway. The laptop applies change 3 when it reads it, since it was made after change 2. The phone is in no list of change 3, and stops, as today. The rule holds. Two variants:
   - The laptop renews after it adds the phone, and its change 3 lists the tablet and the phone. That is case 1. The phone is in no list of the desktop's change 3, so it stops, and is added again by hand.
   - **A removed key added again by hand on a branch that never heard of the removal:** a person there adds the tablet again. Its record hands it that branch's secret. A device that has read the record and the removal takes that branch as not clear. One that has read the removal and not yet the record seals under it until it reads the record: that is the window of section 8, by another road. `cordelia add-device` refuses the key on any device that knows of the removal (rule 6).
4. **A recovery from an old state.** The relays lost the desktop's change 3, and the person recovers on a new machine from change 2. The recovery lists only the new machine, so it is clear by construction (rule 22). When the desktop's change 3 comes to light, each device judges by its removed keys. The new machine stays on its own, unless it has since added again by hand a key that change 3 removed, where it is closed. The desktop is removed where the person said it was gone. Otherwise it goes on, with the recovery set aside, and the two are joined by a change made on a device that has seen both (rule 21), whose prompt asks whether the desktop stays. The rule holds.
5. **A device that was off through several changes.** The phone, on change 2, wakes. Relay A holds two heads: the laptop's change 4 (after its own change 3, both listing the tablet) and the desktop's change 3. The relay hands change 3 first (rule 16): the phone applies it (made after change 2, clear, it lists the phone), and then sets change 4 aside. Where another relay, of the version before, hands it change 4 first, it applies that, and then moves to change 3 at a lower number (rule 9). It sends nothing under change 4 between the two: a device that wakes sends nothing until every relay has answered (the record of 2026-10-04, 4.6), and a relay of this version answers only after it has handed every head. The rule holds.
6. **A removed device that shows old changes again.** Each is behind a head that a relay of this version keeps, and is not stored there (rule 14), and is behind what a device keeps (rule 8, step 1). It pushes no head out. The rule holds.
7. **A lost maker's change that comes to light** (the record of 2026-10-04, 7.6). Relays keep both heads, and a device that is behind is handed both before it has leave. The change made again removes the lost maker, so the lost maker's change is not clear, and the device follows the other. The rule holds, and better than today, where a device far behind follows the lost maker's change until it is shown the other.

## 5. What changes in other records

Each is given as it reads today, and as it would read. The standing documents (the README, the whitepaper, the threat model, the specs) are changed when this is built, not before.

### The record of 2026-10-04

1. **Section 1, property 1.** Today: "**A removed device reads nothing that a device which has applied the removal writes afterwards.**" Becomes: "**A removed device reads nothing that a device which knows of the removal writes afterwards,** on any branch: a device seals only under a secret that no key it knows to be removed holds (decision 2026-10-24, rule 4)." The rest of the property stands, with "(decision 2026-10-24, section 8, bounds the time)" after "it cannot be otherwise for a device that is off."
2. **Section 1, property 2, its second bullet.** Today: "**What it wrote between the removal and a device's hearing of it is kept too,** on a device that took it in that time, and carried from there." Add: "**But never what it wrote in a branch made apart from its removal:** that is carried by nobody, and goes from the folders into local history (decision 2026-10-24, rule 7). Nothing that it sends after a device knows of its removal is taken by that device (rule 6), by the owner's ruling of 24 October that nothing sent after a removal is applied."
3. **Section 1, property 4.** Today: "It travels in the phrase's channel: only the phrase writes there, its one entry is always the same size, and it is the channel of the person's that each relay has held longest". Becomes: "It travels in the phrase's channel: only the phrase writes there, its entry is always the same size, a relay keeps room for a second one made apart from it (decision 2026-10-24, rule 15), and it is the channel of the person's that each relay has held longest".
4. **Section 1, property 5.** Today: "Two changes made apart are seen as that by every device that sees a statement of the other branch, however many changes each side has made (4.2, 4.5). **The limit** is a recovery made from a state before a removal, where the relays have lost the later statement: it knows nothing of the removal, carries what the removed device wrote since, and leaves its key in no list, until the two are settled (section 9)." Becomes: "**A removal takes effect on every device that reads it, whatever it holds besides.** A device that follows a change which lists a key removed on another branch moves to a clear change that lists it, or seals nothing until the two are joined (decision 2026-10-24, rules 8 to 10). A relay keeps each change made apart and hands each to every device (rules 14 to 16). **The limit** is a recovery made from a state before a removal, where the relays have lost the later statement: until that statement reaches it, it knows nothing of the removal, and its look carries what the removed device wrote since, unless the person answered that device as in someone else's hands (section 9)."
5. **Section 2.2, the phrase's channel.** Today: "holds one entry, the change entry (4.6, section 9), under the name `change`". Becomes: "holds the change entry (4.6, section 9), under the name `change`: one, or one for each change made apart that is a head (decision 2026-10-24, rule 14)".
6. **Section 2.4, item 2.** After "**It keeps the newest revision for each author in each slot.**" add: "In a slot whose entries carry a lineage it keeps every head instead (decision 2026-10-24, rule 14)."
7. **Section 2.4, item 5.** After "and here it is." add: "First, it hands each head that it keeps in that slot and that the connection has neither shown nor been handed, the lowest number first (decision 2026-10-24, rule 16)."
8. **Section 2.5.** Today: "**The removal itself needs no new channel and no new room** (4.6, 7.2)." Becomes: "**The removal itself needs no new channel and no new room** (4.6, 7.2): a relay keeps room for a second change made apart from the first from when it takes the first (decision 2026-10-24, rule 15)."
9. **Section 4.2, rule 6.** After its sentence, add: "A change made apart is applied only by a move, where the change the device follows is not clear (decision 2026-10-24, rule 9)." And today: "**A device applies the latest statement it is shown,** and a relay holds only the latest (4.6): it never passes through the ones between." Becomes: "**A device applies the latest statement it is shown that is clear and lists it,** and a relay holds only the heads (decision 2026-10-24, rule 14): it never passes through the ones between."
10. **Section 4.3, the first sentence.** Today: "A device that sees a statement which passes rules 1, 2, 5 and 6, and is not among its devices, is no longer one of the person's." Add after it: "So is a device that sees a statement made apart from the one it follows that lists its key as removed (decision 2026-10-24, rule 8, step 3)."
11. **Section 4.5, the last bullet.** Today: "**Anything else is a fork:** a statement that is not on the applied one's chain and does not have the applied one on its own." Becomes: "**Anything else was made apart:** a statement that is not on the applied one's chain and does not have the applied one on its own. The device keeps it as a head, with its removed keys, and goes on where the change it follows is clear, moves where another clear change lists it, and is closed where none does (decision 2026-10-24, rules 1, 2, 8 to 10)."
12. **Section 4.5.** Today: "A device in a fork neither publishes in its own channels nor takes from them". Becomes: "A closed device neither publishes in its own channels nor takes from them". Its words become: "two changes were made apart, and none that lists this device is clear of a removed device: settle it with the phrase (`cordelia settle`)".
13. **Section 4.5, "Which devices see a fork".** Today: "A relay holds one statement's entry, the latest it was given (4.6). Where one branch is longer, the relays come to hold its last statement, and the devices of the shorter branch are shown it and see the fork. The devices of the longer branch may never be shown the other, and go on. It is settled from a device that has seen both, and every device applies the settlement." Becomes: "**Every device sees both.** A relay keeps the change entry of each head, and hands each to every connection before it says that it holds the one shown (decision 2026-10-24, rules 14 to 16). Each device judges each. A device that follows a clear change goes on. The two are joined by the next change made on a device that keeps both (rule 21)."
14. **Section 4.5.** Today: "Its removed keys are every key that either removed: a settlement undoes nothing." Becomes: "Its removed keys are every key that the device which makes it knows to be removed (decision 2026-10-24, rule 20): a settlement undoes nothing."
15. **Section 4.5.** Today: "Until it has seen both, a device goes on under the one it has. That is the limit of property 1 again: it has not seen the other removal." Add: "Decision 2026-10-24, section 8, bounds it."
16. **Section 4.6.** Today: "**Every device keeps the latest change entry it has seen,** and shows it to each relay on every pass". Becomes: "**Every device keeps the change entry of the change it follows, and of each head it has set aside,** and shows each to each relay on every pass (decision 2026-10-24, rule 18)". Today: "A relay that holds another at that number, or a later one, answers with the one it holds." Becomes: "A relay hands each head it keeps that the connection has neither shown nor been handed (rule 16)." Today: "It keeps the entry and shows that one from then on, unless it is in a fork, where it keeps both, and does not ask a relay again for one it has." Becomes: "It keeps the entry as rule 1 of decision 2026-10-24 says, and does not ask a relay again for one it has."
17. **Section 4.6, the leave.** Today: "**A device has leave on a connection for 10 seconds from an answer there which says that the relay holds no later change than the one the device keeps:**" Becomes: "**A device has leave on a connection for 10 seconds from an answer there which says that the relay holds no change that the device does not keep:**", with a fourth case: "or that hands an entry the device keeps as a head set aside (decision 2026-10-24, rule 18)". Today: "**A device in a fork has no leave anywhere,**" Becomes: "**A closed device has no leave anywhere,**".
18. **Section 7.1, step 4.** Today: "It says that the change is made, and that it must not be made again on another device, even if this command is stopped now: two changes made apart have to be settled with the phrase." Becomes: "It says that the change is made, and that it must not be made again on another device, even if this command is stopped now: where another change is made apart from it, each device follows the one that lists no device removed, and a device that has none seals nothing until the two are joined with the phrase."
19. **Section 7.4, the first bullet.** Today: "**What the removed device wrote, on a device that took it before it applied the removal.** It is that device's version of the file, and is carried as such (property 2)." Add: "Not where it was written in a generation made apart from the removal (decision 2026-10-24, rule 7)."
20. **Section 7.6.** Today: "If the lost maker's ever comes to light, the two are a fork, and are settled." Becomes: "If the lost maker's ever comes to light, it is a head made apart that lists a removed key, the lost maker's own, and devices set it aside (decision 2026-10-24, rule 8)." Today: "A device that is far behind is then answered with it, applies it, and is with the lost device, in a generation whose secret that device holds, until it is shown the other statement. Every device that sees both is in a fork until they are settled; the settlement removes the lost maker, and the statement it held is then behind." Becomes: "A device that is far behind is handed both before it has leave, and follows the one made again, which removes the lost maker (decision 2026-10-24, rules 8 and 16). Where the relays it reaches hold only the lost maker's, it follows that one until it is shown the other: the window of that record's section 8."
21. **Section 8, the status line.** Today: "A fork, and a device that was removed or is in no list, are red." Becomes: "A closed device, and a device that was removed or is in no list, are red. A head set aside is amber for seven days (decision 2026-10-24, rule 11)."
22. **Section 9, "What it cannot know".** Today: "A device that went on shows the relay its own, later, change entry on its next pass, and the relay takes it in place of the recovery's if its number is higher. Whichever of the two is answered with the other's sees a statement that is not on its chain, and is in a fork: the new machine where the device's number is the higher, the device where the recovery's is, and, where the numbers are equal, the one that shows second, since the relay keeps what it has and answers with it. A device that has seen both says so, and `cordelia settle` on it ends it." Becomes: "A device that went on shows the relay its own change entry on its next pass, and the relay keeps both, as two heads (decision 2026-10-24, rule 14). Each device is handed the other, and judges it by the keys it knows to be removed (rule 8). A change made on a device that has seen both joins them (rule 21)."
23. **Section 12.** Today: "**Two changes made apart stop every device that sees both,** until a person settles them with the phrase." Becomes: "**Two changes made apart stop a device only where no change that lists it is clear** (decision 2026-10-24, rule 10), until a person joins them with the phrase. A device that follows a clear change goes on, apart from devices that follow the other."
24. **Section 13 and section 15.** Each gains a line: "Two changes made apart, and removals that must not stop at a relay: decision 2026-10-24, sections 7 and 12."

### The record of 2026-10-19

25. **Section 1, "The kept entry".** Today: "**The kept entry** is the latest change entry that the device keeps". Becomes: "**The kept entry** is the change entry of the change that the device follows (decision 2026-10-24)".
26. **Section 1, "The answers to a show".** After the list, add: "A relay of decision 2026-10-24 may hold the entry shown and hand another first (its rule 16). Only the last answer of a round counts, and only the answer to the show of the kept entry is the latest answer (its rule 18)."

### The messages record

27. **Property 1.** Today: "**A message is shown only on a device that stands applied under the person's latest statement it has seen,**" and "or is in a fork shows nothing and sends nothing." Becomes: "**A message is shown only on a device that stands applied under the change it follows, which is clear (decision 2026-10-24, rule 4),**" and "or is closed shows nothing and sends nothing."

### The record of recovery (2026-10-17)

28. **Section 4.4.** Today: "A device that has stopped (it was removed, is in no list, could not open a change, or is in a fork) has no leave anywhere". Becomes: "A device that has stopped (it was removed, is in no list, could not open a change, or is closed: decision 2026-10-24, rule 10) has no leave anywhere".

### The shared record (not built)

29. **Property 20.** Today: "**A statement changes no shared channel.**" Becomes: "**A statement that removes a key makes each shared channel anew without it** (decision 2026-10-24, rule 24); any other statement changes none."
30. **Property 7.** After "Who stays in a channel made anew is chosen by a person at a terminal, key by key" add: "except at a removal, where every key stays but the keys the person removed (decision 2026-10-24, rule 24)".
31. **Section 3.5, the first bullet.** Today: "**Whoever holds the removed device's key and the seeds stays a full member of every shared channel the person was in,** reading and writing there, until each is made anew without it and the others move (S4)." Becomes: "**Whoever holds the removed device's key and the seeds reads, in the old channel, only what is written there by a device that has not read the offer.** The person's own devices move at the removal (decision 2026-10-24, rule 24), and another person's device sends nothing more there once it has read the offer, until that person moves or says to stay (rule 26)."
32. **Section 3.5, "Turned down: making each shared channel anew at a removal, by itself."** Becomes: "**Made anew at a removal, by the device that makes it** (decision 2026-10-24, rule 24). The other people still move with a yes of their own, and their devices send nothing in the old channel meanwhile (rule 26)."
33. **Section 7, "What the one left out keeps, and can still do".** Today: "it keeps the old seed, and reads everything written in the old channel for as long as a relay holds it, what anyone who has not moved goes on writing there included". Becomes: "... what anyone who has not read the offer, or who chose at a terminal to stay, goes on writing there included (decision 2026-10-24, rule 26)".

### The standing documents, when this is built

34. The README ("**Make a change once, on one device.** Two changes made apart stop every device that sees both."), the whitepaper (its line "Two changes made apart, by two devices that had not met, stop every device that sees both", and the row "Two removals made apart, or an old statement shown again"), the glossary ("**Fork**"), `network-protocol.md` ("A device in a fork has no leave anywhere"), `data-formats.md` (the table `person_change_entries`, and the layout of the change entry), `operations.md` (the status's words), and the threat model: T16 gains the window of section 8, and T20's "Two changes made apart stop every device that sees both, until a person settles them with the phrase" becomes "Two changes made apart stop only a device for which no change that lists it is clear of a removed key".

## 6. A device of the version before

**What a device of 0.2.0-alpha.16 meets.**

- **A change entry made on this version.** It opens the part for the devices, which has not moved, and applies the change as any. Its node never opens the part for the phrase. **Its commands cannot make a change over such an entry:** `cordelia remove-device`, `renew`, `settle`, `sync carry --phrase` and `recover` of the version before open the part for the phrase at its old place, find that it does not open, and refuse. A change is made on a device of this version.
- **A relay of this version that keeps two heads.** It is handed the other with today's answer (`Another`), judges a fork as today, and stops. It fails closed. A device behind both is handed the lower first, applies it where it can, and is then handed the other, and stops. A relay of this version hands no change that is behind another it keeps (rule 14).
- **A device of this version, and a relay of the version before.** That relay keeps one entry, as today. Nothing a device does is less safe for it. A removal made apart from the change that relay holds does not reach the devices that use only it, as today, and every device that knows of the removal names that relay as lacking the change it follows (rule 18). An answer that hands a head set aside gives the device leave there (rule 18), so it goes on syncing through it.
- **A change made on the version before** has no lineage. A relay of this version keeps it as today (rule 14).
- **A device in a fork that takes this version** judges its two entries at its first start (rule 12).

**Can it ship without every device taking it at once? Yes.**

- **The order:** the relays first, where a person runs their own (the default relays are the project's), then the devices, one at a time and in any order. Nothing breaks where the order is not kept: a relay of the version before stores a change entry of this version, as it checks only the two signatures.
- **Properties 1, 3 and 5 hold on a device from when it takes this version,** for what it knows.
- **Property 2's spreading holds where the relays a device uses are of this version.** Until then a removal reaches a device as today.
- **A device of the version before is never less safe than today.** At a relay of this version it sees a change made apart sooner, and stops.
- **What it loses:** making a change over a change made on this version, until it takes this version.

## 7. Tests

**Each test fails on an assertion when the rule it names is taken out,** and each is run so once, by hand, when it is built (a mutation check). The real-process tests are in a new file, `crates/cordelia-node/tests/removal_e2e.rs`, with the harness of `person_e2e.rs`: relays of the test's own, devices set up with one relay or both, relays listed together or not, and the secrets a device holds read from its database, as `threat_model.rs` reads them. CI runs them as it runs the others.

### With real processes

1. **`a_removal_made_apart_from_a_renewal_takes_effect_without_settle`.** The fault, kept for good. The laptop and the tablet use relay A; the desktop uses relay B; the relays are not listed together. The desktop removes the tablet. The laptop renews. The tablet applies the laptop's change. The laptop is then set up with relay B too, and started again. It asserts:
   - (a) the laptop follows the desktop's change 3, by its ID, with its own set aside, and no phrase was typed;
   - (b) the tablet's status says "this device was removed", with no `settle`, once the laptop has shown the desktop's change at relay A;
   - (c) the desktop's state is applied at every look through the test, and it never says that two changes were made apart;
   - (d) a file that the laptop edits after (a) reaches the desktop;
   - (e) every entry that the laptop pushed to either relay after (a) is in a channel of the desktop's change 3, and none opens with any secret that the tablet's database holds;
   - (f) no entry that the laptop signed reaches either relay in a channel of its own change 3 after (a).
   Taken out: rule 9 (the laptop is closed: (a) and (d) fail); rule 4 or 5 (it goes on under its own change: (e) and (f) fail); rule 8, step 3 (the tablet is in a fork: (b) fails); rules 14 to 16 (relay A never hands the desktop's change: (b) fails); rule 11 (the desktop stops: (c) fails).
2. **`relays_that_work_together_spread_a_removal_made_apart`.** As test 1, with relays A and B listed together, and no device set up with both. It asserts (a), (b), (e) and (f) of test 1. Taken out: rule 14 or 17 (relay A never takes the desktop's change: (a) times out).
3. **`two_removals_made_apart_close_both_sides_until_settle`.** Four devices: the laptop and the tablet use relay A, the desktop and the phone use relay B, and the relays are listed together. The laptop removes the phone, and the desktop removes the tablet. It asserts: the laptop and the desktop are each closed, with the words of rule 10 in red; a file edited on each while closed reaches no relay (no entry signed by either arrives in a channel of either change 3 after it closed); the tablet and the phone are each removed; `cordelia settle` on the laptop makes change 4, which lists both as removed; the desktop applies it, with no phrase; the files edited while closed arrive on the other; and neither the tablet's database nor the phone's holds change 4's secret. Taken out: rule 10 (a device goes on under one of the two: the second assertion fails); rule 20 (change 4 lacks a removal: the fourth fails).
4. **`a_device_that_slept_through_changes_made_apart_follows_the_clear_one`.** As test 2, with a phone that uses relay A and is stopped. The laptop renews twice (changes 3 and 4) while the desktop removes the tablet. The phone is started. It asserts: it follows the desktop's change 3, with the laptop's change 4 set aside, and no entry that it signed reaches a relay in a channel of the laptop's change 3 or 4. Taken out: rule 16's order with rule 9 (it applies change 4 and is then closed: the first assertion fails); rule 9's move to a lower number (closed: the same).
5. **`a_removed_device_that_shows_old_changes_pushes_no_head_out`.** As test 2. A client of the test's own shows relay A, again and again, every change entry that the tablet's database holds and every one it was handed. It asserts that the laptop still learns of the desktop's change, and that relay A holds the desktop's change throughout. Taken out: rule 14's test of lineage (kept by number alone, a head is pushed out: the second assertion fails).
6. **`the_window_before_a_device_reads_a_removal_is_bounded`.** The laptop uses relay A only, and relay A lacks the removal: the laptop's edits reach relay A under the old secret (the window, shown). Relay A is then listed with relay B, which holds the removal. It asserts that the last entry the laptop pushes under the old secret reaches relay A no more than 30 seconds after relay A first holds the removal (section 8's bound with a margin). Taken out: rule 17 (relay A does not take the removal from relay B: it times out); a leave longer than `SHOW_LEAVE_SECS` (the bound fails).
7. **`nothing_a_removed_device_sends_after_its_removal_is_taken_by_a_device_that_knows`.** Property 5, the owner's ruling. As test 1, with the tablet's agent sending messages and the tablet's folder edited at each step.
   - **In the window:** after the tablet applies the laptop's change 3, and before the laptop is set up with relay B, the tablet edits a file and sends a message to the laptop's agent. The laptop takes both (it does not know yet). Then the laptop is set up with relay B and moves. It asserts: (a) the laptop's folder no longer holds the tablet's text, which is in its local history (`cordelia history`); (b) no channel of the desktop's change 3, at either relay, holds that text, whoever signed it; (c) the desktop's folder never holds it, and no conflict file beside a file holds it; (d) `cordelia msg summary` and `msg read` on the laptop no longer show the tablet's message, and `msg log` shows it as from a removed device.
   - **After the laptop knows:** the tablet, a client of the test's own that holds its database, writes again in every channel it holds, of the laptop's change 3 and of change 2, and sends a message in each messages channel it holds. It asserts: (e) neither the laptop nor the desktop stores any entry that the tablet signed after the laptop moved; (f) no folder of either holds that text; (g) neither shows the message, in any command or hook.
   - Taken out: rule 7's cut (the laptop carries the tablet's text into the desktop's change: (a) to (c) fail); rule 6 in the messages' check of who counts (the laptop still shows, from the messages it held of its own change 3, the tablet's message: (d) fails); a move that still reads the generation it left (rule 9, which leaves it as 7.5 of the record of 2026-10-04 has it: (e) to (g) fail). The test of rule 6 in who counts for files is unit test 12.
8. **`a_relay_of_the_version_before_that_holds_a_head_set_aside_gives_leave`** (`device_entries_e2e.rs`, with the relay that answers as a test says, `relay.says`). The relay answers each show with a change that the device keeps as a head set aside. It asserts that the device has leave there, and that the relay is named as lacking the change followed. Taken out: rule 18's leave (the device has none: it fails).
9. **For when shared channels are built: `a_removal_makes_each_shared_channel_anew_and_the_removed_device_reads_nothing_new`.** Alice's laptop, desktop and tablet, Bob's laptop, and a shared channel that all hold. The desktop removes the tablet. It asserts: the channel is made anew in the same act, without the tablet; Alice's laptop moves with no yes; no entry signed by Alice's devices reaches the old channel after each applied the removal; Bob's laptop sends nothing in the old channel after it read the offer, until Bob runs `cordelia shared move`; and the tablet's database holds no seed of the new channel. Taken out: rule 24 (no offer: the first fails); rule 23 (Alice's laptop writes in the old channel: the third fails); rule 26 (Bob's message reaches the old channel: the fourth fails).

### In units

10. **The statement and the choice** (`statement.rs`, `person.rs`): a change is clear only where no removed key is listed in it or added under it by a record seen; a change made apart that removes this device stops it as removed; a device on a change that is not clear moves to the clear one that lists it, at a higher number, at the same number, and at a lower one, with its carry and with a record in a band above it dropped; a device on a clear change sets the other aside and goes on; with none clear it is closed; of two clear changes it moves to the higher number, then the lower hash; a head that a change was made after is dropped; the removed keys only grow, and a ninth head closes the device. Each step of rule 8 has a test that fails without it.
11. **Sealing** (`person.rs`, `publish.rs`, `adding.rs`, `sender.rs`): `applied_secret` and `Standing::to_write` refuse a secret that is not clear, with the rows set so by hand; a publish, a hand-over, a message and a name's word are refused there; what waits under a secret that stops being clear is not sent, from that moment, also on a request already built (rule 5).
12. **Who counts, and the carry** (`person.rs`, `messages.rs`, the adapter): an entry signed by a key removed on another branch is not stored; a record that adds such a key does not count; `add-device` refuses it; a message it signed is not shown but by `msg log`. At a carry, a version that a removed key signed in a generation made apart from its removal is not carried, the slot carries the newest version a key that counts signed, and the folder goes back to it with the removed key's text in local history and nowhere else; one that it signed in a generation its removal was made after is carried, with its key first in the chain. Each fails when rule 6 or rule 7 is taken out.
13. **Changes made** (`change.rs`, `commands.rs`): each kind lists every removed key the device knows and none as a device, and the node refuses its own change otherwise; a change made where a head is set aside has it on its chain and settles it; a settlement of three heads holds the secrets of each in its part for the phrase, as many as fit.
14. **The change entry** (`change_entry.rs`): the lineage is built from the statement and read back; an entry whose lineage does not match is refused; the part for the devices is where it was, and opens with the opener of the version before (a published vector); the part for the phrase opens in both layouts; at every bound together the lineage and the part for the phrase fit.
15. **A relay** (`relay.rs`, `relay_entries.rs`): an entry behind a head is not stored and is answered with each head; an entry made apart is kept beside; one made after replaces those it was made after; every change of a branch shown again pushes no head out; each head is handed once on a connection, the lowest number first, and "held" comes only after; a short show of each head kept is answered in short; a second head is kept at a relay at its cap; a third head at a full relay is refused for room (the limit, shown); an entry with no lineage is kept as today; a head kept beside another is passed on to a relay it works with.
16. **A device's show** (`device_entries.rs`): it shows each head it keeps, those set aside first; leave comes from the answer to the change followed, and from an answer that hands a head it keeps; only that answer is noted as the relay's latest; a change in what it keeps wakes the pass at once.
17. **Sequences** (`crates/cordelia-sync/src/claude/sequences.rs`): the harness gains a step, "a change made apart", whose two sides are shown to each device in either order. Its check: no entry that a device sealed after it knew of a removal opens with any secret that the removed device holds.

The threat model's T16 names tests 1, 2, 6 and 7, and T20 names tests 3 and 5.

## 8. The window, for the threat model

**What physics leaves.** A device that has not read a removal does not know of it. Until it reads it, it seals under the secret of the change it follows, which the removed device may hold, and it sends what it seals to its relays. The removed device reads what was sent at a relay that both of them reach.

**Its bound,** from the moment that a relay holds the removal, by the constants of today:

- **A device connected to that relay** reads it within about 20 seconds. Its leave there runs out within 10 seconds (`SHOW_LEAVE_SECS`), and nothing is sent or taken there after that without a show, whose answer hands the removal (rule 16). Its pass comes every 10 seconds. Meanwhile it can still send at another relay that lacks the removal, until that show: so about 20 seconds in all.
- **A relay that works with one that holds it** comes to hold it within 5 seconds (`ENTRY_OFFER_INTERVAL_SECS`, rule 17), or at its next pull, within 10 (`RELAY_ENTRY_PULL_INTERVAL_SECS`), while the two are connected.
- **A device that wakes** sends nothing until each relay it is set up with has answered, or 30 seconds have gone (`WAKE_WAIT_SECS`). Where a relay that holds the removal answers within that, it sends nothing under the old secret.
- **A device that reaches no relay which holds the removal,** and whose relays get it from no device and no relay, seals and sends so for as long as that lasts. There is no bound: that is the limit.
- **A removed device at the same address as a device** can use up the address's limits at a relay, and delay that device's hearing there (the record of 2026-10-04, 2.5, "what is not defended"). That is one more way of being cut off.
- **A record of an addition that hands a removed key a secret,** on a branch that never heard of its removal, is one more thing a device may not yet have read (section 4, case 3).

**What narrows it cheaply,** each in a rule above:

- **Relays pass every head on at once:** at the next offer, within 5 seconds (rule 17).
- **A device shows every head it keeps on every pass,** so a removal is at every relay that a device which knows of it reaches (rule 18).
- **A change in what a device keeps wakes its pass at once,** so it tells its relays without waiting for the next pass (rule 19).
- **A device fetches before it sends:** the leave of 10 seconds already makes every send at a relay follow a show there by 10 seconds at most. Section 10 says why it is not tightened across relays.

**For the threat model (T16).** In place of its sentence "(A device that has not heard of the removal still writes where the removed device can read, and still takes what the removed device writes there. ...)": "A device that has not read the removal still seals under a secret that the removed device holds, and still takes what the removed device writes there. It reads the removal within about 20 seconds of any relay it is connected to holding it, and a relay holds it within 10 seconds of a relay it works with holding it. A device that reaches no relay which holds the removal writes so for as long as that lasts, and the removed device reads it at any relay that both reach. Once a device has read the removal, on any branch, it seals nothing that the removed device can open, and takes nothing that the removed device sends, messages between the person's agents included. Of what it took before it knew, what the removed device wrote in a branch made apart from the removal goes from its folders and is carried by nobody; what it wrote in a generation that its removal was made after is carried, and every other device keeps its own text beside it (the decision record of 2026-10-24, rules 6 and 7, and section 8)."

## 9. What it costs

- **A relay holds two change entries of a person's while two changes made apart are both heads,** and keeps room for a second always: 32 KB more for each person at each relay. Where a relay has no room for that at a person's first change made on this version, it drops its newest channels to make it (rule 15).
- **Whoever holds an old channel of one slot,** and replaces its entry with one that carries a lineage, makes a relay at its cap give up as much of its newest channels' room as that entry, once for each such channel (rule 15).
- **A relay reads a change entry's lineage.** It learns how a person's statements follow each other, and when two were made apart. It learned before each time a phrase is used.
- **A device of the version before cannot make a change over one made on this version** (section 6).
- **While two heads stand, each new connection to a relay is handed each head once,** 32 KB each.
- **A change made apart from a removal is set aside:** a device that it listed, and that the removal's change does not, is in no list, and stops until it is added again or the two are joined. That is so at any change today.
- **Two devices that each follow a clear change made apart go on apart,** and do not sync with each other until a change joins them (rule 11).
- **A closed device stops, as a device in a fork does today,** in fewer cases: only where each change that lists it lists a key removed on another.
- **A move to a lower number** drops a record whose revision is in a band above it, and its file meets the channel as a new file does (rule 9).
- **Shared channels, when built:** every removal makes every shared channel anew; the other people move with a yes each; until each moves or says to stay, their devices send nothing in the old channel, and a member can so pause another person's sending by making a channel anew that leaves out a key.
- **A device's word that it left is not written by a device that is closed** (rule 4).
- **What a removed device wrote in a branch made apart from its removal is gone from the folders** of the device that took it, and is in that device's local history alone: where local history is off, it is gone (rule 7). A version that a remaining device wrote over it in that time is kept, and every other device keeps its own text beside it.

## 10. Set aside, and why

- **A relay that keeps a few change entries by number alone, with no lineage.** No change to the change entry is needed. But a removed device holds every change of its branch, and by showing them again pushes a removal out of what a relay keeps, wherever its branch has made enough changes since the two parted. That is a failure mode a thief can use.
- **A change entry whose number is ordered by what it removes.** One entry would still be enough where a removal meets a renewal. It cannot order two removals of different devices, which must both reach every device; and devices of the version before refuse an entry whose revision is not its number.
- **A device that writes the other change into the personal channel of a branch that is not clear,** so that devices on that branch learn of it through any relay. It needs an exception to rule 4, and a removed device that holds that channel can fill it so that the entry finds no room. Relays that keep every head do it without either.
- **Every device moves to one clear change by rank,** so that two clear branches join without a change. It moves devices that are safe where they are, and carries everything twice, for something that is not safety.
- **A device that sends only while every relay it is connected to has given it leave in the last 10 seconds.** It would narrow the window by about 10 seconds, and let one slow relay hold up all of them. The record of 2026-10-04 (16) chose that one relay never holds up another.
- **A relay that is told whether it is of this version, by the protocol's version in the handshake,** so that a device can say which relays keep every head. Today the end that accepts refuses a proposal whose highest version is below its own (`handshake.rs` 224): raising it first needs that check changed, or devices of the version before are refused. Nothing in this record needs it.
- **Hiding later statements from a removed device.** A removed device keeps the statement key, and reads each later statement: who the devices are, by key and label, and which made the change (the record of 2026-10-04, 4.6 and section 12). The ruling, read strictly, reaches that too: it is new information. The six properties do not ask for it, and it is not done here. With the lineage in the clear (rule 13), a later format could seal each statement to the devices it lists alone, since a device could then judge a change by its lineage without reading it; a device that is not listed would be told only that a change it is not in was made. Section 12 asks the person.

## 11. Constants

| Name | Value | Why |
|---|---|---|
| `MAX_CHANGE_HEADS` | 8 | The heads a relay keeps in a slot, and a device keeps. Only the phrase makes a head: an honest person has two at most, now and then |
| `MAX_KNOWN_REMOVED` | 2,048 (derived: `MAX_STATEMENT_REMOVED` times `MAX_CHANGE_HEADS`) | The keys a device keeps as removed |
| `CHANGE_ENTRY_PHRASE_PART_BYTES` | 1,024 (was 4,096) | At every bound it needs 382 |
| `CHANGE_ENTRY_LINEAGE_BYTES` | 3,072 (derived: `CHANGE_ENTRY_BYTES` less the two parts) | At its bound the lineage is 2,066 |
| `LINEAGE_HASH_BYTES` | 8 | Rule 13 |
| `LABEL_CHANGE_LINEAGE` | `cordelia v2 lineage` | Its first 8 bytes of SHA-256 open a lineage. It begins no other label, and none begins it |
| `CHANGE_HEADS_ROOM` | 2 | The heads a relay keeps room for in a slot (rule 15) |

Each goes in `protocol.rs`, with its reason in `parameter-rationale.md` (§12.3 for the change entry, §12.7 for a relay). `CHANGE_ENTRY_BYTES` stays 32 KB.

## 12. For the review to attack, and for the person

**For the review:**

- **Rule 8's order.** A case where a device seals under a secret that a removed key it knows holds; a case where it moves to a change it cannot open; a case where a change made after the one followed should be set aside and is applied, or the reverse.
- **Rule 15's room.** Whether making room for a second head by dropping the newest channels can be used by a stranger to push others out, beyond what section 9 says.
- **Rule 16 and the leave.** Any answer that gives a device leave at a relay that holds a head the device has not judged.
- **Rule 9 across bands.** A move to a lower number, and what a dropped record costs.
- **Rule 13.** The 8 bytes; an entry whose lineage a relay misreads; the opener of the part for the phrase in two layouts.
- **Section 8's arithmetic,** and any way to send under a secret that is not clear after a relay the device is connected to holds the removal, beyond the 20 seconds.
- **Rule 26:** what a member who makes a channel anew can do to other people's sending.

**For the person to decide:**

1. **Shared channels (rule 26).** The shared record turned down a move by itself, and kept a yes for each person. Rule 26 keeps that yes for a move, and adds that another person's device sends nothing more in the old channel once it has read an offer that leaves out a key, until that person moves or says to stay. It is what makes property 4 hold for what other people write. Is that the line?
2. **Later statements (section 10).** A removed device still reads who the person's devices are, at each later change. The ruling's "any new information" reaches that. Hiding it is possible in a later format, at the cost of what a device that is not listed can be told. Is it wanted?
3. **Property 5's limit, in a generation that the removal was made after.** A stolen device can go on writing in the generation it was removed from, and a device that has not heard takes it. When that device hears, it carries it, and every other device keeps its own text beside it (the record of 2026-10-04, property 2). No device can tell what was written there after the removal from what was written before, so the owner's ruling ("nothing sent after removal is applied") holds there only for devices that know. Closing it is the stricter way that the record of 2026-10-04 set aside (14, item 1): only the device that makes the removal carries what the removed device wrote, and every other device carries only its own. Its costs are there: conflict files on every device at every removal, and the removed device's work left behind where the maker is lost before its carry is done. Should this record take it?
