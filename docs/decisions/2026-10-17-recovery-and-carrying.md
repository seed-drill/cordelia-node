# Decision: four changes to recovery and carrying

**Date**: 2026-10-17
**Status**: Proposed. Not built. It changes [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md) in sections 6, 9 and 16, and that record now says what this one decides.
**Cited as**: code comments cite the sections of this record ("decision 2026-10-17 §3.2"), and the numbered properties ("§1, property 4"). The numbers do not change.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md).
- **Alpha.11** is the release 0.2.0-alpha.11, and **this version** is the version of the node that first carries what is below.
- **A record** is a record of an addition (the record of 2026-10-04, section 6). **Its adder** is the key that signed it, and **its key** is the key that it adds.
- **An adder that may add** is a key that `Counting::may_add` says yes of (`crates/cordelia-api/src/person.rs`): a device of the statement, or a key that counts and that such a device added.
- **A key that the 64 kept out** is the key of a record that fails for one thing only, that 64 devices count already (`NotCounted::NoRoom`).
- **The bound of 256** is `MAX_NOT_COUNTED_RECORDS`, the records that a reader keeps as not counted, and **the 256 rows** are `RECOVERY_MAX_DEVICES_SHOWN`, the rows that a recovery shows.
- **A carried name** is a name that a carry by command, or a recovery, brought versions into (section 4.3 says how a device knows).
- Examples say laptop and desktop.

---

## 0. What this is

Reviews of alpha.11 found four places where recovery and carrying keep a rule that does not protect what it is for. This record defines a change for each.

1. **Fairness between adders in the two bounds of 256** (section 2). Which records a reader keeps, and which rows a recovery shows, go by who signed them and not by when they were seen. Each adder that may add keeps its first three keys that the 64 kept out, whatever another device signs.
2. **A recovery reads its two channels on to their end** (section 3). The phrase's own channel and the personal channel of the change recovered from are read on from the place reached, for up to 615 seconds, which is what a channel at its cap takes. The command says that it is reading.
3. **What "sent to no relay" means where a carried name is let go** (section 4). A version counts as held at a relay only where a relay that the device is set up with handed it, in a read made after the person asked.
4. **A way out for a carried name that no relay takes** (section 5). A typed `discard`, at a terminal, lets the name go with what no relay holds.

Nothing on the wire changes, and no relay needs a change (section 6). Two of the changes alter what every device runs: the order of keeping records (section 2), which every reader applies, and the check before a carried name is let go (section 4), which is local to each device. A person whose devices run alpha.11 and this version at once is safe with both (section 6).

## 1. The properties

Each is one sentence that a test can hold. Section 9 names the tests. Security properties come first.

1. **No record that one key signs takes from another adder that may add the first three places of its keys that the 64 kept out,** among the records a reader keeps and among the rows a recovery shows (`KEPT_OUT_PER_ADDER`).
2. **The records that a reader keeps do not turn on the order in which it saw them,** given who counts.
3. **A row of a key that the 64 kept out shows the label that each adder that may add gave it,** each beside that adder, and no one adder's label stands for the key.
4. **A key whose adder was itself kept out by the 64 is not asked about at a recovery,** and its row gives its key written whole with the two commands that reach it.
5. **A carried name is let go with a version that no relay holds only after the word `discard` is typed at a terminal,** once the command has said how many such versions there are, and where they still are.
6. **For that check, a version counts as held only where a relay that the device is set up with handed it, or an entry at a higher revision in its slot signed by a key that counts, in a read that began after the person asked.**
7. **A folder's unmapping never lets go of a carried name,** whether the folder was mapped before the carry or after it.
8. **On a device that has stopped, a carried name is let go only after the same typed word,** and the command says that the device could not read the relays.
9. **A `discard` lets go of nothing that the command did not show:** where the store has taken anything of the name since the read that was shown, or the read is more than ten minutes old, the node refuses.
10. **A recovery reads the phrase's own channel, and the personal channel of the change it recovers from, on from the place each relay reached,** until each relay has handed it to its end or holds none of it, until a round moves no place, or until 615 seconds have passed (`RECOVERY_READ_ON_MAX_SECS`).
11. **A recovery that read either of those channels in part at a relay says so before its yes,** by relay.
12. **The count of versions sent to no relay that a command says before its yes counts only entries that this device signed.**
13. **Nothing on the wire changes:** a relay of alpha.11 serves a device of this version as it serves one of alpha.11.

## 2. Fairness between adders in the two bounds of 256 (C1)

### 2.1 What the code does today

- **A reader keeps 256 records that do not count, the oldest it saw going first.** `keep_to_the_bound` (`crates/cordelia-api/src/person.rs`) splits the records that do not count into those that let a key add (`Counting::lets_add`: for each key that counts by a record, the oldest record that a device of the statement signed) and the rest. The rest are dropped in the order the device saw them (`held_rows::additions` reads them `ORDER BY seen`), until 256 are left. Every device runs it, after each record it takes (`see_addition`).
- **A recovery reads the records in the order of the statement.** `recover::read_generation` (`crates/cordelia-api/src/recover.rs`) sorts what the relays handed by the place of the signer in the statement, then by key, slot and revision, and gives it to the same functions over a database in memory. So the bound of 256 drops first the records of the device listed first.
- **A recovery shows 256 rows.** `read_generation` puts every device of the statement first, then the keys added since that count, then the records that do not count: those that fail only for the 64 (`only_for_room`) before the others, each group in order of key. `rows.split_off(RECOVERY_MAX_DEVICES_SHOWN)` cuts the rest.
- **A row of a key that the 64 kept out is shown by the record whose adder has the lowest key** among those that fail only for the 64 (the sort by `(row.key, !row.counts, !for_room, adder)` and `dedup_by`). Its label is that adder's word. The question is asked under the first adder, in order of key, that is not in someone else's hands (`asked_for_room`), and `recover_cmd::for_room_says` names that adder where it differs, without the label it gave.
- **What holds today:** nothing a key that does not count signed comes in. The command says how many rows it could not show (`not_shown_says`), counts the keys that a record was read for and that have no row at all (`Generation::no_row`, `no_row_says`), and marks each row one of whose records was read and not kept (`Row::record_let_go`). The key can be removed afterwards by `cordelia remove-device <key>`. But a key that has no row cannot be shown.

### 2.2 The rule: the order of keeping

A reader keeps the records that do not count in one order, and drops from its end until 256 are left. The order is a function of the records it holds and of who counts. It does not use the order in which they were seen.

1. **Records that let a key add** (`Counting::lets_add`), as today. They are never dropped. There are at most 63: one for each key that counts by a record.
2. **Records whose key the 64 kept out and whose adder may add.** They are dealt to their adders in turn: each adder's first before any adder's second, each adder's second before any adder's third, and so on.
   - An adder's own records are in the order of the time each says it was made (`Addition::at`), the oldest first, and then by the key they add. That is the adder's word, and it orders only that adder's records.
   - Among the records of one turn, the devices of the statement come first, in its order, and then the other adders by key.
3. **Records whose adder may not add yet** (`NotCounted::MayNotAdd`): dealt to their adders in turn, in the same way. Such a record comes to count where a record by a device of the statement is kept for its adder, so it is kept before the rest.
4. **Every other record that does not count:** a record of a removed key (`NotCounted::Removed`), and a record of a key that counts already that lets nothing add (`NotCounted::CountsAlready`). By the time each says, and then by key and adder.

**What it gives.** At most 63 records are of the first kind, and at most 64 adders may add. So at least 193 places are left for the second kind, and each adder that may add keeps at least its first three keys that the 64 kept out: `KEPT_OUT_PER_ADDER`, 3. That holds whatever any other key signs, and however many adders sign.

**The rows of a recovery follow the same order.** After every device of the statement and every key added since that counts (at most 64 rows together), the rows of records that do not count are in the order above. At least 192 rows are left, so each adder that may add has a row for at least its first three keys that the 64 kept out: 3 again. A row of a key that several adders added stands at the best place any of them gives it.

**Why three is enough.** A person adds devices one at a time, from a device in hand. An adder that added more than three devices since the last change, all while 64 already counted, is not an ordinary case. Where it happens, the command still says what it could not show (section 2.5).

### 2.3 A key whose adder was itself kept out

A phone added from a tablet, where the 64 had kept the tablet out, is a second level. Its record fails because its adder does not count (`NotCounted::MayNotAdd`).

**It is not asked about at a recovery.** What lets a key that does not count be asked about is that an adder that counts vouched for it. An adder that never counted vouches for nothing. Were such keys asked about, any chain of records would be asked about, and each answer of "gone" would take one of the phrase's 256 removals.

**Its row says so,** and gives its key written whole with the two commands that reach it afterwards. Its records are kept in the third group of 2.2, so its row is shown where room is left.

### 2.4 Labels

A label is the word of the key that added a device. Where several adders that may add added one key, each gave it a label, and the labels can differ.

**The row shows each of those labels, each beside the adder that gave it, in the order of the adders' rows.** The first four words of the key's fingerprint are shown first, as everywhere (the record of 2026-10-04, section 16). An adder that may be in someone else's hands, by what was said of it and of the devices that added it (`in_other_hands`), is counted and not shown: "and 2 more added it, which may be in someone else's hands". So no one adder's label stands for the key, and the words are what tell a device.

The question is asked under the first adder, in the order of the rows, that the person still has or said is lost or broken. Today it is the first in order of key: the order of the rows is the statement's, which no adder chooses.

### 2.5 What a person reads

At a recovery, a row of a key that two adders gave two labels:

```
able baker charlie delta "phone", added since change 3, from able echo fox golf "laptop" at
2026-10-12 09:14 as "phone", and from hotel india juliet kilo "desktop" at 2026-10-13 18:02 as
"kitchen tablet", by a record that does not count: 64 devices counted already. It signed 4
entries in the personal channel of that change.
  The labels differ. A label is what the device that added it called it: the words are what
  tells two apart.
```

A row of a key whose adder was itself kept out:

```
lima mike november oscar "phone", added since change 3, from papa quebec romeo sierra
"tablet", which 64 devices counted already kept out too. It signed 2 entries in the personal
channel of that change.
  It is no device: nothing is asked of it, nothing that it wrote is brought back, and its key
  is not removed. A device added from one that did not count is not asked about. If it is a
  device of yours that is gone, its key is removed afterwards, on this machine, by `cordelia
  remove-device <key written whole>`, and what it wrote then comes in by `cordelia sync carry
  <name> --from <key written whole>`, with the phrase. One that you still have is added again
  by hand.
```

What `no_row_says` says before the first question gains one sentence after its first:

```
Each device that may add keeps a row for at least the first 3 devices that it added since
change 3 and that 64 devices counted already kept out: a device that added more than that
may have left one of them here.
```

The other lines of a recovery, of `cordelia devices` and of the prompt of the next statement stay as they are.

### 2.6 Turned down

- **The oldest first, as today.** It drops a record by when it was seen. A device that signs many records drops another adder's, at a live reader where they come after it, and at a recovery where its signer is listed after it.
- **A larger bound.** Every reader loads what it keeps each time it asks who counts. A larger bound costs every device on every record, and moves the edge without removing it.
- **A bound of four for each adder, and no more.** It gives the same floor, and leaves room unused where few adders sign. Dealing in turn uses all 256 places and keeps the floor.
- **Signers that are not listed read first, at a recovery.** It mends the recovery and not a live reader, whose order is the order records arrived.

### 2.7 What every device runs

`keep_to_the_bound` changes, and every device runs it. A person whose devices run alpha.11 and this version at once is safe:

- **Who counts does not change inside the bound of 64.** A record that counts is never dropped, by either version. The records that can come to count later are those whose adder may not add yet. Where a reader drops one, and then a record comes to count or a key comes to add, the reader reads every channel of its own again from the start (the record of 2026-10-04, section 16; `at_relays::take_page` forgets every place where `came_to_count` or `came_to_add` is not 0). The dropped record is given again, and is judged again. So two versions that kept two sets beyond the bound count the same keys, as two readers that saw records in two orders do today.
- **What differs beyond the bound is which records that do not count each keeps,** and so what `cordelia devices` and the prompt of a statement show of them. Beyond the bound two readers can differ already (the record of 2026-10-04, section 6).
- **A recovery reads with the command's own functions,** so a recovery of this version reads by this order, whichever version the devices ran.

**Schema:** nothing is stored. The order is worked out from the rows of `person_additions` as they are: the record's bytes hold its time, and the row holds its key and adder.

**Constants,** in `crates/cordelia-core/src/protocol.rs`:

- `KEPT_OUT_PER_ADDER: usize = 3`. Derived: the lesser of `(MAX_NOT_COUNTED_RECORDS − (MAX_COUNTED_DEVICES − 1)) / MAX_COUNTED_DEVICES` (193 / 64 = 3) and `(RECOVERY_MAX_DEVICES_SHOWN − MAX_COUNTED_DEVICES) / MAX_COUNTED_DEVICES` (192 / 64 = 3), checked at compile time to be at least 1. For `parameter-rationale.md` §12.6: "How many keys that the 64 kept out each adder that may add keeps among the records a reader keeps, and among the rows a recovery shows, whatever another key signs. It is what is left of each bound once the records that let a key add, or the rows of the devices that count, have their places, shared among the 64 adders there can be. It is not chosen: it follows from the three bounds it is made of. A person who adds more than three devices from one device while 64 count is told what could not be shown."

## 3. A recovery reads its two channels on to their end (C2)

### 3.1 What the code does today

- **The command reads each channel in one call.** `recover_cmd::read_channel` calls `carry_cmd::read_with_secret`, which posts to `POST /api/v1/carry/read` (`carrying::read_proved`). There `read_with_proofs` reads at every relay until `CARRY_READ_MAX_SECS` (120 seconds), through `DeviceEntries::read_left` (`crates/cordelia-node/src/device_entries.rs`), which starts at `(NO_MARK, 0)`: from the start. Where a connection changed, `read_again_where_changed` reads again, from the start, up to `CARRY_PROOFS_MADE_AGAIN` times.
- **A device takes from one relay about 2 MiB a minute.** `room_to_take` holds a read to `PUSH_BYTES_PER_PEER_PER_MINUTE`, counted with `ENTRY_OVERHEAD_BYTES` for each entry, and a relay sizes a page to leave `SHOW_ANSWER_ROOM_BYTES` for the answer to a show. A channel may hold `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, 16 MiB, counted the same way. So one read reaches about 4 MiB, and a channel at its cap takes about 8¼ minutes.
- **The personal channel read in part.** The command goes on with what it read, and `WasRead::lines` says so before its yes. It refuses only where nothing is known at any relay (`personal_not_read_says`).
- **Step 1, the phrase's own channel.** It is read by the same `read_channel`. Where a change is found, the command goes on from the one with the highest number (`recover::found`), and what was not read is used only where none was found (`none_found_says`). Where the channel was read in part, nothing says so.
- **The tests.** A recovery that read its personal channel in part and went on to its yes is tested in process only (`recover_cmd`, `test_a_recovery_goes_on_with_what_it_could_read_of_the_personal_channel`). The real-process test (`recover_e2e.rs`, `a_recovery_says_at_which_relay_the_personal_channel_was_not_read`) has a second relay that was not reached, and a first that handed the channel whole.

### 3.2 The rule: read on

**The command reads each of its two channels on from where each relay reached,** round after round:

1. The first round is the read of today: from the start, for `CARRY_READ_MAX_SECS` at most.
2. The node says, of each relay that it read in part, the place it reached there: the mark of the relay's holding and the next place, as a pull keeps them (`at_relays.mark`, `at_relays.place`).
3. The command asks again, of those relays only, from those places. It makes its proofs again where a connection changed, as today. A relay that answers under another mark than the place was asked under has dropped and taken the channel again since: it is read from the start there, and what was read before is kept.
4. It stops at a relay that has handed the channel to its end or holds none of it; at a relay where a round moved no place; and everywhere at `RECOVERY_READ_ON_MAX_SECS` (615 seconds) from the first round. A relay that is not reached in a round stays as it was.

It is for **the phrase's own channel** (step 1) and for **the personal channel of the change recovered from** (step 3). The personal channels of the generations before, which are read for names, are read once each, as today (section 11).

Through the door the node still stores nothing of what it pulls and pushes nothing (the record of 2026-10-04, section 4.6). It keeps no place of its own either: the command is handed the place, and asks from it.

**Where a relay is still read in part at the end,** the command goes on with what it read, as today, and says so before its yes. For step 1 that is new: the change it recovers from is the latest in what was read, and a later one may be in what was not.

The command holds the phrase while it reads, as it does today for the first round. Ctrl-C stops it there, and nothing is made.

### 3.3 What a person reads

After the first round, where a relay was read in part:

```
The personal channel of change 3 is larger than one read. Reading on at relay-one: a relay
may hold up to 16 MiB of it, which takes up to 10 minutes to read. Ctrl-C stops here, and
nothing is made.
  relay-one: 4.0 MiB read so far.
  relay-one: 8.1 MiB read so far.
  relay-one: read to its end, 9.3 MiB.
```

The same lines are said of "the recovery phrase's own channel" at step 1. A line is said after each round, at most every 30 seconds.

Where a relay is still read in part at the end, the line of `WasRead::lines` for a channel read to its end at no relay ends so, in place of what it says of a device that filled the channel:

```
It was read for 10 minutes, which is what a channel at its largest takes: a relay that hands
it more slowly than that, or stops, leaves it in part.
```

Step 1, after the change to recover from is chosen, and again before the yes:

```
The recovery phrase's own channel could not be read to its end at relay-two (part): a later
change may be held there, in what was not read. This recovery is made from change 3, the
latest in what was read. Only the recovery phrase writes in that channel.
```

### 3.4 Turned down

- **A longer read for every carry.** `CARRY_READ_MAX_SECS` bounds the read of every name by `cordelia sync carry` and by the look of a recovery, and the time a mapped folder waits for its first cycle (`CARRY_FIRST_MAX_SECS`). Those are read for each name. Ten minutes for each would hold a folder up for ten.
- **One call that lasts ten minutes.** A connection that changes in that time would cost the read from the start, and the person would see nothing for ten minutes. Rounds from a place cost one round where a connection changes, and say how far they are.
- **Refusing where the channel was read in part.** A relay that answers slowly could refuse every recovery for ever. That is why today's rule goes on, and this one keeps it.
- **Reading only the slots that matter.** A relay sees no names, and the command does not know them before it reads: a slot is the hash of a name under the channel's slot key.

### 3.5 What every device runs

Only the command of a recovery and the node it talks to. The door's read gains a place to start from, and `POST /api/v1/carry/read` gains, for each relay, a place to start from and the place reached. A command of alpha.11 does not talk to a node of this version: a command that changes anything refuses a node of another version (the record of 2026-10-04, section 10.1, rule 6). Nothing else of a device changes.

**Schema:** nothing is stored.

**Constants,** in `crates/cordelia-core/src/protocol.rs`:

- `RECOVERY_READ_ON_MAX_SECS: u64 = 60 × MAX_ENTRY_CHANNEL_BYTES_AT_RELAY / (PUSH_BYTES_PER_PEER_PER_MINUTE − SHOW_ANSWER_ROOM_BYTES) + CARRY_READ_MAX_SECS`, that is 495 + 120 = 615. For `parameter-rationale.md` §12.9: "How long a recovery reads the phrase's own channel, and the personal channel of the change it recovers from, at most, counted from its first round (decision 2026-10-17 §3). It is what a channel at its cap takes to read at what a device takes from one relay in a minute, less the room a relay keeps for the answer to a show, and one round more: so a relay that hands what it may is read to its end. What a person's devices write there is small, so this is reached only where a channel is near its cap, or a relay is slow."
- No other. A round is `CARRY_READ_MAX_SECS`, and the line of progress is said at most every 30 seconds, which is not a protocol value: it is a constant of the command.

## 4. What "sent to no relay" means where a carried name is let go (C3)

### 4.1 What the code does today

- **Unmapping a carried name is refused while a version of it was sent to no relay.** `sync::let_go_of_a_carried_name` asks `names::waits_to_be_sent`, which asks `at_relays::sent_to_no_relay` (`crates/cordelia-storage/src/at_relays.rs`): the entries of the name's channel in the store whose place is above what the device keeps as sent to every relay (`at_relays.sent_to`, or `carried_to` for what it carried), or that a relay refused for room (`at_relays_refused`). The refusal is `sync::not_let_go_says`.
- **What that counts as sent:**
  - **what went to a relay the device is no longer set up with.** Rows of such a relay go only in `at_relays::forget_what_is_done`, where every relay's key is known, which is while all of them are connected;
  - **what a relay refused as not checking** (`Pushed::DoesNotCheck`), **and what it holds in another form** (`Pushed::HoldsAnother`): `at_relays::sent` moves on past both;
  - **what a relay dropped since,** until the next pull there finds no holding, or another mark (`take_page`, `start_again`), or a proof is answered no (`not_held_at`).
- **The refusal lasts for as long as no relay has room.** An entry refused for room stays in `at_relays_refused`, and is offered again after a wait.
- **A name that a folder was mapped to before a carry brought versions in is the folder's name.** `names::hold_for_a_carry` adds a name to `person.names_carried` only where no folder is mapped to it. A folder's unmapping (`sync::names_follow`) then stops the name with what waits.
- **On a device that has stopped,** `waits_to_be_sent` counts none (it asks `at_relays::stands` first). So `cordelia sync unmap <name>` lets go of a carried name at once, what no relay holds included. The line after a folder's unmapping (`still_held_says` in `crates/cordelia-node/src/main.rs`) says "once nothing of it waits to be sent" there too, where nothing is ever sent again.
- **And the count can overstate.** `take_page` marks what it took from a relay as sent there only where nothing else waited (`if !waiting`). On a device that sends, the next push clears that: the relay answers that it holds it. On a device that has stopped, nothing clears it. So the count that `cordelia init --new-key`, `cordelia phrase` and `cordelia accept` say before their yes (`names::waits_in_every_name`) can include entries that came from a relay.

### 4.2 The rule: held is what a relay just handed

The check protects one thing: **a version of a carried name that is nowhere else in the generation applied.** On a machine that has just recovered, that is the only copy outside the generation that was left. So the check asks the relays, and not the device's notes of what it sent.

1. **Before a carried name is let go, the device reads the name's channel at each relay it is set up with.** It is a pull of the device's own channel, under leave, from the start, as a pass makes it (the record of 2026-10-04, section 4.6), for `CARRY_READ_MAX_SECS` at most. It takes what it is handed as any pull does, and notes besides what each relay handed in each slot.
2. **The versions asked about are each slot's current version in the name's channel,** as the device reads it with who counts: every version that the device would show a folder.
3. **A version is held where one relay handed, in that slot, in that read:**
   - an entry that is the same version (the same text or delete at the same revision, whoever signed it: the record of 2026-10-04, section 2.3); or
   - an entry at a higher revision signed by a key that counts: what the slot shows has moved on, and the version would not be the current one anywhere.
4. **One relay is enough.** Relays that work together pass entries on, and a recovery is set up with relays of the person's choosing.
5. **Anything else is held by no relay:** a relay that was not reached; one that was read in part, for what it did not hand; one that refused the entry as not checking, holds another, dropped the channel, or had no room.

So each of the gaps of 4.1 closes by the same rule. A relay that the device is no longer set up with is not read. What was refused, held in another form that is not the same version, dropped, or refused for room, is not handed.

**The notes of what was sent stay as they are** for what they decide: what is offered again, what `cordelia devices` says is still to send, and whether a device writes that it has sent what it carried (the record of 2026-10-04, section 8). Section 11 says why.

### 4.3 A name a carry brought versions into, folder or not

**A name into which a carry by command, or a recovery, brings a version is a carried name from then,** whether or not a folder is mapped to it:

- Where no folder is mapped, it is in `person.names_carried`, as today.
- Where a folder is mapped, it is in a new key of `node_meta`, `person.names_brought_in`, a list of names as the first is. `carry::bring` adds the name in the transaction that brings the version in.

**A folder's unmapping never lets go of a carried name.** Where the folder was the name's last, the name moves to `person.names_carried`, and is held as it is held today when a carry brought it with no folder. `cordelia sync unmap <name>` then lets it go by the check of 4.2. A name leaves `person.names_brought_in` when the device stops it, and both lists go when the device leaves its phrase, as the first does today.

### 4.4 A device that has stopped

A device that has stopped (it was removed, is in no list, could not open a change, or is in a fork) has no leave anywhere, and reads none of its channels. It cannot ask the relays.

- **`cordelia sync unmap <name>` there lets a carried name go only after the typed word of section 5,** where the device's own notes say that it holds a version of the name that it signed and sent to no relay. Where they say none, it lets the name go at once, as today.
- What it loses matters for one case: a device in no list, or one that could not open a change, can be added again, and then carries what it holds.
- **The notes count only what the device signed** (4.5). They are a device's own word, and the command says that it could not check them.

### 4.5 The count said before a yes counts only this device's entries

`at_relays::sent_to_no_relay` counts only entries whose author is this device's key. An entry that another key signed came to this device from a relay. So `names::waits_in_every_name`, which `cordelia init --new-key`, `cordelia phrase` and `cordelia accept` say before their yes, no longer counts what a device took from a relay while something else waited there. The same count is what 4.4 uses.

### 4.6 What a person reads

`cordelia sync unmap lab`, where every version is held:

```
This device holds lab no longer. It held it by a carry, with no folder mapped to it: a relay
held each of its 12 versions when it was read just now, so nothing is lost by it. Your other
devices keep what they hold of it.
```

`cordelia sync unmap lab`, where a version is held by no relay, with no terminal. The node's refusal, in place of `not_let_go_says`:

```
lab is not let go: no relay that this device is set up with held 3 of its versions when it
was read just now.
  relay-one: read to its end. It had no room for 3 of them, the last time 2 minutes ago.
  relay-two: not reached.
This device goes on sending them, and lab can be let go once a relay holds them. To let it go
now, with them, run `cordelia sync unmap lab` at a terminal.
```

At a terminal, the same lines, and then the prompt of section 5.

After a folder's unmapping, where the name is a carried name, on a device that sends (in place of `still_held_says`):

```
This device still holds lab, since a carry or a recovery brought versions into it:
`cordelia sync unmap lab` lets it go, once a relay holds each of its versions.
```

On a device that has stopped:

```
This device still holds lab, since a carry or a recovery brought versions into it. This
device has stopped, and sends nothing more: `cordelia sync unmap lab` lets it go, and asks
first where this device's own notes say that it sent a version of lab to no relay.
```

### 4.7 Turned down

- **Mending each gap in the notes.** It needs a rule and a row for each: for a relay no longer set up with, for an entry refused as not checking, for one held in another form. And a relay that dropped the channel since cannot be known without asking it. A read asks it, and closes the four at once.
- **Every relay must hold it.** A relay that is down for a day would hold up every let-go for a day, where a relay that holds the version is enough for every device and recovery to find it.
- **No check at all.** On a machine that has just recovered, it would let go of the only copy.
- **A read at every folder's unmapping.** A folder's unmapping is answered at once today. It leaves a carried name held instead (4.3), and the read is made when the name itself is let go.

### 4.8 What every device runs

Each device, for itself. Nothing is sent to another device or to a relay but a pull that a pass would make anyway. A device of alpha.11 beside one of this version is not affected.

**Schema:** one key of `node_meta`, `person.names_brought_in`, listed in `crates/cordelia-storage/src/meta.rs`. No step of the schema: a key of `node_meta` is a row of a table that exists.

**Constants:** none. The read is bounded by `CARRY_READ_MAX_SECS`.

## 5. A way out for a carried name that no relay takes (C4)

### 5.1 What the code does today

Short of beginning again (`cordelia init --new-key`, or `cordelia phrase`), a carried name whose versions no relay takes can never be let go. `let_go_of_a_carried_name` refuses while a version was sent to no relay, and a folder's unmapping leaves the name held (`names_follow`). The device goes on offering what was refused for room, after a wait that doubles up to `OUTBOX_REFUSED_RETRY_MAX_SECS`.

### 5.2 The rule: a typed `discard`, at a terminal

**Where the check of 4.2 finds a version held by no relay, `cordelia sync unmap <name>`, at a terminal, says what it found and asks for a typed word: `discard`.** No answer is suggested. Anything else, or Enter, keeps the name.

- **Who may give it.** The rules of a yes in the record of 2026-10-04 (section 5): it is asked by the command, at a terminal, and refused where the command's input is not a terminal. It stops a command run by mistake, or by a script that has no terminal. It does not stop a program that runs as the person (section 7).
- **It asks for no phrase.** Nothing comes in by it, and nothing is signed. It lets go of what this device holds, which a program that runs as the person could delete from the database anyway.
- **What is let go is what was shown.** The node keeps the result of the read in memory, by an ID, for `LET_GO_READ_STANDS_SECS` (600 seconds). The command sends that ID with the word and the number of versions it showed. The node lets go only where the read stands, the number is the one it found, and its store has taken nothing of the name's channel since the read. Otherwise it refuses, and the command says to run it again.
- **Where the versions still are.** The prompt says it, from what the device knows: for each generation that it left and still holds the secret of, how many more days it holds that secret (section 3 of the record of 2026-10-04). What was carried is still in the channels it was carried from, at the relays, for that long at most, and the command that carried it brings it in again: `cordelia sync carry <name>` for what keys that count signed, and `--from <device>`, with the phrase, for what a removed key signed. Where the device holds no such secret, the prompt says that the versions are on this device alone.

On a device that has stopped (4.4) the same word is asked, and the prompt says that the device could not read the relays.

### 5.3 What a person reads

```
laptop$ cordelia sync unmap lab
lab is not let go: no relay that this device is set up with held 3 of its versions when it
was read just now.
  relay-one: read to its end. It had no room for 3 of them, the last time 2 minutes ago.
  relay-two: not reached.
This device goes on sending them, and lab can be let go once a relay holds them.

Letting lab go now drops those 3 versions from this device. What was carried into lab is
still at the relays, in the channels it was carried from, for 61 more days at most: `cordelia
sync carry lab` brings in again what a device that counts wrote, and `cordelia sync carry lab
--from <device>`, with the recovery phrase, what a removed device wrote.
  Type `discard` to let lab go with them. Anything else keeps it:
```

On `discard`:

```
This device holds lab no longer, and 3 versions that no relay held went with it.
```

followed, where the statement lists another device, by "Your other devices keep what they hold of it."

On anything else: "lab is still held. Nothing was changed."

Where the device holds no secret of a generation it left, the second paragraph is: "Letting lab go now drops those 3 versions from this device: they are on this device alone."

On a device that has stopped, the first paragraph is:

```
This device has stopped (it was removed), and sends nothing more. It cannot read the relays to
learn whether they hold lab. Its own notes say that it sent 3 versions of lab, which it wrote
or carried, to no relay. If this device is added again, it carries what it holds: what is let
go now is not among it.
```

The words in brackets are those of its status: "it was removed", "it is in no list of the last change", "it could not open the last change", "two changes were made apart". The last sentence is said only where the device can be added again (it is in no list, or could not open a change).

### 5.4 Turned down

- **The phrase.** An agent with a shell can give a yes and not the phrase. But nothing comes in by a discard: it lets go of what one device holds, and what was carried is still in the channels it was carried from for as long as that device could carry it again. The phrase is for what lets a removed key's work in, or changes who is a device.
- **Letting go by itself after a time.** That loses what no relay holds without a person's word.
- **Beginning again,** which is all there is today. It lets go of every name, every secret and the device's key, to let go of one name.

### 5.5 What every device runs

Each device, for itself. `POST /api/v1/sync/unmap` gains the ID of a read, the word and a number. A command of alpha.11 does not send them to a node of this version, which it refuses (rule 6). A node of this version answers a request without them as in 4.6.

**Schema:** nothing is stored. The read is held in memory.

**Constants,** in `crates/cordelia-core/src/protocol.rs`:

- `LET_GO_READ_STANDS_SECS: u64 = CARRY_WORD_SECS` (600). For `parameter-rationale.md` §12.9: "How long the read that `cordelia sync unmap` shows stands for the `discard` that follows it (decision 2026-10-17 §5). The person reads the lines and types the word in that time. A word typed later lets go of nothing, and the command is run again. Derived: as long as a word of the phrase for a carry stands, the other act at a prompt that follows what the node read."

## 6. Alpha.11 and this version together, and what a relay sees

**Nothing on the wire changes.** No stream, no answer, no entry, no record and no statement changes form. A relay of alpha.11 serves a device of this version, and a device of alpha.11 is served by a relay of this version, as before. **No relay needs a change.**

**A person whose devices run two versions at once:**

- **Who counts is the same on both** inside the bound of 64 (2.7). Beyond the bound of 256, each keeps what its version keeps, and each shows that. A recovery made with this version reads by this version's order.
- **A recovery made with this version** reads its two channels on (section 3). It reads channels that devices of either version wrote. A command and a node of two versions do not work together (rule 6).
- **The check before a carried name is let go, and the word,** are of the device where the name is let go (sections 4 and 5). A carried name on a device of alpha.11 is let go as alpha.11 lets it go.
- **The count before a yes** counts only a device's own entries on this version (4.5), and all of them on alpha.11. Each device says its own.

**What a relay sees of it:**

- **Of section 3:** a recovery's longer read of two channels, page after page, within what a relay hands a connection in a minute, as a carry's read is. It is a pull of a channel that a proof opened, from a place, like any pull.
- **Of section 4:** a pull of one channel of the device's own, from the start, when a person lets a name go.
- **Of sections 2 and 5:** nothing.

## 7. Who can do what

**A device that counts, in someone else's hands, while it still counts:**

- It can sign any number of records. Under the order of 2.2 those records take places only from its own share and from the shares of keys it added. Each other adder that may add keeps its first three keys that the 64 kept out, among what a reader keeps and among a recovery's rows (property 1).
- It can add keys that count until 64 do, and each key it adds so may add in its turn. That makes at most 64 adders, and the floor of three holds with 64 adders.
- It can give a key a label. Its label is shown beside it, among every other adder's label for that key (property 3). It cannot change the words of a key's fingerprint.
- It can fill the personal channel up to its cap. A recovery then reads for up to 615 seconds, and reads it to its end at a relay that hands what it may (property 10).
- What holds as before: nothing it signed comes in at a recovery where it was said to be in someone else's hands, and its records are no device.

**A key that it added:** the same as the device that added it, within the same share. Where the 64 kept that key out, it may not add (2.3), and what it adds is not asked about at a recovery.

**A relay that answers falsely or slowly:**

- It can hand less than it holds, and say that it has handed the channel to its end. A recovery and the check of 4.2 then believe it, as today: a relay is a cache. A second relay set up with the device answers for itself.
- It can hand a channel slowly. A recovery reads for 615 seconds and goes on with what it read, and says so (property 11). The check of 4.2 reads for `CARRY_READ_MAX_SECS`, and counts what was not handed as held by no relay: the name stays held, and the person can type `discard`.
- It can say that it holds a version that it does not, only by handing that version, which it cannot forge: an entry is signed by the channel's key and its author's. A relay that handed a version can drop it a moment later. Nothing defends against that, as nothing defends against a relay dropping anything.
- It cannot change which records a reader keeps: the order goes by what the records say and who counts, and not by when they arrived.

**A person who types yes at the wrong prompt:**

- At the prompt of section 5, a typed `discard` drops the versions that no relay holds. A `y`, a `yes` or Enter keeps the name. The prompt says how many versions go, and where they still are.
- At a recovery, an answer typed to a row whose labels differ is an answer about the key that the words name, under every label shown.
- A program that runs as the person can type `discard` (the threat model's T17). What is left is that the carried versions are still in the channels they were carried from, for as long as the device holds those secrets, and the command that carried them brings them in again.

## 8. What it costs

- **Time.** A recovery whose personal channel holds more than one read takes up to about ten minutes more at step 3, and up to as much at step 1 where something filled the phrase's channel. In ordinary use both channels are read in the first round, and nothing changes. `cordelia sync unmap <name>`, for a carried name, waits for a read of one channel, usually a second or two, and `CARRY_READ_MAX_SECS` at most.
- **The phrase is held longer.** A recovery holds the phrase in its process while it reads, as it does today. A longer read is longer in memory, in a process that cannot be dumped (the record of 2026-10-04, section 16).
- **Bytes.** A recovery's read of a channel at its cap is 16 MiB from each relay, once. The read before a carried name is let go is the name's channel, from the start, once from each relay.
- **Work.** A reader works out the order of 2.2 each time it keeps a record: at most 256 records and 64 adders, parsed from their rows.
- **Rows.** One key of `node_meta`. Nothing else is stored. A read before a `discard` is held in memory for ten minutes.
- **What a person may meet.** A carried name that a folder was mapped to is held after the folder's unmapping where today it went: one more command lets it go.

## 9. Tests

Each test is written so that taking its rule out makes it fail on an assertion. A test that runs real processes is marked so, and runs under a pseudo-terminal where a command asks.

**Property 1 (the floor of three):**

- `crates/cordelia-api/src/person.rs`, `test_a_flood_of_records_keeps_each_adders_first_three_kept_out`. Device 0 of the statement adds keys until 64 count. Device 1 of the statement then adds three keys, which the 64 keep out. Device 0 signs 300 more records. Of device 1's three records, all three are kept, seen before device 0's or after them. With the oldest-first rule, the three go where they were seen first, and the test fails.
- `crates/cordelia-api/src/recover.rs`, `test_a_recovery_shows_each_adders_first_three_kept_out_rows`. The same records, read by `read_generation`, with device 0 listed first and then with device 1 listed first: each of device 1's three keys has a row. With today's sort by key, a flood of keys below them cuts them from the 256 rows.
- Real processes, `crates/cordelia-node/tests/recover_e2e.rs`, `a_device_that_signs_hundreds_of_records_leaves_a_phone_its_row`. A change lists the laptop and the desktop. The laptop signs records until 64 count. The desktop adds a phone, which the 64 keep out, and the phone writes a file. The laptop signs 300 records more. Every device stops. A recovery shows the phone's row and asks about it.
- `crates/cordelia-core/src/protocol.rs`: `KEPT_OUT_PER_ADDER` is 3, and the two quotients it is the lesser of are checked at compile time.

**Property 2 (the order of keeping is not the order of seeing):**

- `person.rs`, `test_the_records_kept_do_not_turn_on_the_order_they_were_seen`. Three hundred records of four adders are given to two readers in two orders. Both keep the same 256. With the oldest-first rule they keep two sets.
- `person.rs`, `test_who_counts_does_not_turn_on_which_records_beyond_the_bound_were_kept`. One reader keeps by the order of 2.2 and one by the oldest first; a record by a device of the statement then lets a key add, and each reads its channels again. Both count the same keys.

**Property 3 (each label beside its adder):**

- `recover.rs`, `test_a_row_kept_out_by_the_64_shows_every_label_its_adders_gave`. Two adders that may add give one key two labels. The row holds both, each with its adder, in the order of the adders' rows.
- `crates/cordelia-node/src/recover_cmd.rs`, `test_what_is_said_of_a_key_added_under_two_labels`: the lines of 2.5, and an adder that may be in someone else's hands counted and not shown.

**Property 4 (a second level is not asked about):**

- `recover.rs`, `test_a_key_whose_adder_was_kept_out_is_shown_and_not_asked_about`. `asked_for_room` is `None` for its row, and `gone` never lists it.
- `recover_cmd.rs`, `test_what_is_said_of_a_key_whose_adder_the_64_kept_out`: its row gives its key written whole and the two commands.

**Properties 5, 6 and 9 (held, and the discard):**

- `crates/cordelia-api/src/sync.rs`, `test_a_version_is_held_only_where_a_relay_read_after_the_ask_handed_it`, on the harness of several devices (`several.rs`). Each of these leaves the name held: a relay that the device is no longer set up with; a relay that refused the entry as not checking; one that holds another entry of the device's at that revision with another text; one that dropped the channel after the push; one that had no room; one read in part. Each of these lets it go: the same version signed by another key; an entry at a higher revision by a key that counts. Taking the read out, and counting by the notes, lets the first four go.
- `sync.rs`, `test_a_discard_lets_go_only_of_what_was_shown`. A read is shown, and then the store takes an entry of the name: the discard is refused. A read older than `LET_GO_READ_STANDS_SECS` is refused. A number that is not the one found is refused.
- Real processes, `crates/cordelia-node/tests/carry_e2e.rs`, `a_carried_name_is_not_let_go_while_no_relay_holds_what_it_brought`. A device carries a name through a relay whose cap leaves no room for it. `cordelia sync unmap <name>` with no terminal is refused with the lines of 4.6, naming the relay. The relay is given room: the device sends what waits, and the name is let go.
- Real processes, `carry_e2e.rs`, `a_relay_that_dropped_a_carried_channel_keeps_the_name_held`. The relay is sent everything, and is then started again with the channel gone from its store. Until the device has sent it again, the name is not let go.
- Real processes, `carry_e2e.rs`, `a_carried_name_that_no_relay_takes_is_let_go_on_a_typed_discard`. Under a pseudo-terminal: `yes` keeps the name, Enter keeps it, `discard` lets it go; the prompt says the number of versions and the days left. With no terminal the word is never asked.

**Property 7 (a folder's unmapping keeps a carried name):**

- `sync.rs`, `test_a_name_a_carry_brought_versions_into_under_a_folder_is_held_after_the_folders_unmapping`. A folder is mapped to a name, a carry brings a version in, and the folder is unmapped: the name is held, and is in `person.names_carried`. Without the list of 4.3, the name is stopped.

**Property 8 (a device that has stopped):**

- Real processes, `crates/cordelia-node/tests/carry_e2e.rs`, `a_removed_device_lets_go_of_a_carried_name_only_on_a_typed_discard`. A device carries a name through a relay with no room, and is removed from another device. `cordelia sync unmap <name>` on it asks for `discard`, and says that it could not read the relays. Today it lets go at once.
- `crates/cordelia-node/src/main.rs`, `test_what_unmap_says_on_a_device_that_has_stopped`: the line of 4.6 for a device that has stopped, and never "once nothing of it waits to be sent" there.

**Properties 10 and 11 (reading on):**

- `crates/cordelia-node/src/device_entries.rs`, `test_a_read_of_a_left_channel_goes_on_from_a_place`. A read asked from a place hands what follows it, and says the place it reached. Asked under a mark that the relay no longer has, it reads from the start.
- `crates/cordelia-api/src/carrying.rs`, `test_a_read_with_proofs_says_the_place_it_reached_at_each_relay`.
- `recover_cmd.rs`, `test_a_recovery_reads_its_personal_channel_on_until_its_end`, with a read that hands a third of the channel at each round: the command reads three rounds and says "read to its end". Taking the rule out leaves it in part after one.
- `recover_cmd.rs`, `test_a_recovery_stops_reading_on_at_the_bound` and `test_a_round_that_moves_no_place_ends_the_reading`.
- `recover_cmd.rs`, `test_the_phrases_channel_read_in_part_is_said_before_the_yes`: the lines of 3.3 for step 1, after the choice and before the yes. Today nothing is said.
- Real processes, `recover_e2e.rs`, `a_recovery_reads_a_personal_channel_larger_than_one_read_to_its_end`. Devices that count fill the personal channel with about 6 MiB of words, and the desktop's record of a phone is among the last of them. The recovery says that it is reading on, says "read to its end", and asks about the phone. Taking the rule out, the phone has no row. It takes about four minutes.
- Real processes, `recover_e2e.rs`, `a_recovery_whose_personal_channel_stays_read_in_part_goes_on_to_the_look`. One relay, which is stopped during the second round and started again before the yes. The command says what 3.3 says of a read in part, takes the yes, and the look ends and carries what was read. This is the real-process test that today's rule lacks.
- `protocol.rs`: `RECOVERY_READ_ON_MAX_SECS` is 615, from the values it is made of.

**Property 12 (the count before a yes):**

- `crates/cordelia-storage/src/at_relays.rs`, `test_what_was_sent_to_no_relay_counts_only_this_devices_own_entries`. On a device that has stopped, entries that another key signed, taken from a relay while something else waited there, are not counted.

**Property 13 (nothing on the wire changes):**

- The tests of the wire in `crates/cordelia-network` are unchanged, and pass unchanged.

**Existing tests that change:**

- `crates/cordelia-api/src/take.rs`, `test_a_flood_of_records_drops_none_that_lets_a_key_add`: what goes beyond the bound goes by the order of 2.2.
- `recover.rs`: `test_a_recovery_shows_at_most_so_many_devices_and_takes_nothing_from_the_rest`, `test_a_recovery_counts_the_keys_whose_record_was_read_and_that_have_no_row` and `test_a_row_says_that_a_record_read_for_its_key_was_not_kept`: which rows are shown, and which records were let go.
- `recover_cmd.rs`: `test_what_is_said_of_a_key_that_only_the_bound_of_64_kept_out` (each label), `test_what_is_said_of_the_keys_whose_record_was_read_and_that_have_no_row` (the added sentence), `test_a_recovery_goes_on_with_what_it_could_read_of_the_personal_channel` (the line of a read in part).
- `recover_e2e.rs`: `a_device_that_signs_hundreds_of_records_pushes_no_device_out_of_a_recovery` (the count of keys kept as left out), `a_device_added_since_is_asked_about_where_only_the_bound_of_64_kept_it_out` and `a_device_that_the_64_kept_out_and_was_not_asked_about_is_removed_by_its_key` (the lines of a row).
- `sync.rs`: `test_a_folders_unmapping_does_not_let_go_of_a_name_that_a_carry_holds` and `test_a_name_that_a_carry_holds_with_no_folder_is_let_go`: the check reads the relays.
- `crates/cordelia-api/src/names.rs`, `test_what_was_sent_to_no_relay_is_counted_over_every_name_held`: only the device's own entries.
- `main.rs`: `test_what_unmap_says_of_a_name_that_a_carry_held`, `test_what_unmap_says_of_the_nodes_answer_to_letting_go` and `test_what_unmap_says_of_a_name_that_is_still_held_after_its_folder`: the lines of 4.6.
- `carry_e2e.rs`, `from_holds_a_name_only_once_something_is_taken_and_unmap_lets_go_of_it`: the unmapping waits for the read, and says that each version was held.

## 10. The order of building

Each slice can be reviewed and merged alone. The smallest come first.

1. **The count before a yes counts only this device's entries** (4.5), and the line after a folder's unmapping on a device that has stopped (4.6). Storage and one line. Property 12.
2. **The order of keeping** (2.2), in `keep_to_the_bound`, with `KEPT_OUT_PER_ADDER`. Properties 1 and 2, for a reader.
3. **The rows of a recovery** (2.2 to 2.5): their order, each label, and the second level. `read_generation`, `asked_for_room` and the command's lines. Properties 1, 3 and 4, for a recovery. It needs slice 2 for its reader.
4. **A read from a place** (3.2): the door, `read_left` and `POST /api/v1/carry/read`. Nothing reads on yet.
5. **A recovery reads on** (3.2, 3.3), with `RECOVERY_READ_ON_MAX_SECS`, at steps 1 and 3, and the lines. Properties 10 and 11. It needs slice 4.
6. **The read before a carried name is let go** (4.2), the list of 4.3, and a device that has stopped (4.4) refused without the word. Properties 6, 7 and 8, with a way out only by `init --new-key` until slice 7.
7. **The `discard`** (section 5), with `LET_GO_READ_STANDS_SECS`. Properties 5 and 9. It needs slice 6. Slices 6 and 7 can be merged together where a release would otherwise carry slice 6 alone: alone, it refuses more than today and gives no way out.

## 11. What is put off, and why

- **Reading on the personal channels of the generations before,** which are read for names. There can be eight of them, and ten minutes each is too long for a second source. A name that is missing there is said before the yes, and comes in by `cordelia sync carry <name>`.
- **Reading on in the look of a recovery, and in `cordelia sync carry`.** Each name is read for two minutes. A name read in part is said, and `cordelia sync carry <name>` reads it again. A name's channel is read from the start each time, so a name of more than about 4 MiB stays in part; that is a name near its cap, and is put off with a carry from a place.
- **The notes of what was sent** (4.2): what is offered again, what `cordelia devices` says is still to send, and when a device writes that it has sent what it carried. They keep counting what a relay refused as not checking, and what it holds in another form, as sent. Nothing that lets go of a version rests on them now but on a device that has stopped, where the word is asked. A device that writes that it has sent what it carried when a relay holds another form is worth a review of its own.
- **A label chosen by an adder elsewhere.** The prompt of the next statement and `cordelia devices` show a key added since by the label of the record that counts. That record is the first one kept, and its adder counted; the case of 2.4 is a key that the 64 kept out, which only a recovery asks about.
- **A floor of more than three.** It needs larger bounds of 256, each a cost to every reader (2.6).

## 12. Where to look for faults

Where I am least sure, said plainly.

- **The order of 2.2 against `judge_again`.** A record that the order drops can be one that would have come to count after a later record. The record of 2026-10-04 relies on reading every channel again when a key comes to count or to add. I have read that `take_page` forgets every place when `came_to_count` or `came_to_add` is not 0. I have not checked that every way a record arrives (a hand-over, a recovery's reader, a statement's prompt) does the same.
- **The floor counts adders that may add.** A key can come to add after its records were dealt. Then the deal changes, and what was dropped is gone until it is given again. I believe the reading again closes it; a test should show a key whose adder comes to add after a flood.
- **The second level (2.3).** I chose not to ask about it. A person whose real tablet was kept out loses the question about the phone it added. The row still gives its key. If that is wrong, the fix is to ask where the adder's own row was asked about, and that costs removals.
- **A read from a place (3.2).** A place means something only with its mark, and a sweep frees places that are not given again (the record of 2026-10-04, section 16). I rely on that for a read that resumes. A relay that drops the channel between two rounds and takes it again under the same mark would hand the start again as what follows; I believe a new holding has a new mark, and did not prove it.
- **The read before a let-go (4.2) is under leave, from the start.** It is a pull that a pass would make. I have not checked how it shares a relay's minute with the pass that is running, or how a read in part of a large name is said.
- **A relay that holds the version for a moment.** "Held" is what a relay handed in that read. A relay that drops it afterwards loses it, and the device has let go. Nothing in this record defends against that, and nothing can short of keeping the version.
- **The ID of a read for a discard (5.2).** It is in memory. A node that restarts between the read and the word refuses the word, and the person runs the command again. I think that is right, and it is untested in this design.
- **The bound of 615 seconds.** It assumes that a relay hands what it may in a minute. A relay that hands less leaves a channel near its cap in part, and the command goes on, as today.

## 13. Questions for the person

1. **Is three enough?** `KEPT_OUT_PER_ADDER` follows from the bounds. Raising it means raising `MAX_NOT_COUNTED_RECORDS` and `RECOVERY_MAX_DEVICES_SHOWN`. **Recommendation:** keep three, and the bounds as they are.
2. **Should a second level be asked about at a recovery (2.3)?** **Recommendation:** no, as this record has it: an adder that never counted vouches for nothing, and asking would let any chain of records spend the phrase's removals.
3. **Should the `discard` need the phrase (5.4)?** **Recommendation:** no. Nothing comes in by it, and what was carried is still in the channels it was carried from.
4. **Should the check before a let-go need every relay, or one (4.2, item 4)?** **Recommendation:** one.
5. **Should slices 6 and 7 ship in one release (section 10)?** **Recommendation:** yes. Slice 6 alone refuses on a device that has stopped where today it lets go, with no way out but beginning again.

**Where the code differs from the brief this record was written from.** The code is right about today.

- The brief says a reader keeps 256 records, "the oldest it saw going first". The code keeps besides, and never drops, one record for each key that counts by a record and that a device of the statement also signed (`Counting::lets_add`). So the floor of 2.2 is worked out with up to 63 places taken.
- The brief says a recovery reads records "in the statement's order, signers that are not listed last". The code sorts by the place in the statement, then by key, slot and revision. Under the oldest-first rule, the records that go first at a recovery are those of the device listed first.
- The brief says a recovery shows the record "whose adder has the lowest key among adders that may add". The code shows the record of the lowest-key adder among those whose record fails only for the 64, and the question names another adder where it is asked under one (`for_room_says`), without that adder's label.
- The brief says a device takes 2 MiB a minute, and a channel at its cap takes about 8 minutes. Both are counted with `ENTRY_OVERHEAD_BYTES` for each entry, and a relay keeps `SHOW_ANSWER_ROOM_BYTES` of each minute for the answer to a show: about 8¼ minutes.
- The brief says the read of the personal channel is one read of 120 seconds from the start. Where a connection changed, `read_again_where_changed` reads again from the start, up to `CARRY_PROOFS_MADE_AGAIN` times.
- The brief says the count can overstate on a device that has stopped. On a device that sends, the overstatement lasts only until the next push. And the count that overstates there is the one said before the yes of `init --new-key`, `cordelia phrase` and `cordelia accept` (`waits_in_every_name`): the check before a let-go counts none on such a device (`waits_to_be_sent`).
- The record of 2026-10-04 has no list of later records, so none was added to it.
