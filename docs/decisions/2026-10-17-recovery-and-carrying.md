# Decision: four changes to recovery and carrying

**Date**: 2026-10-17
**Status**: Proposed. Not built. It changes [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md) in sections 6, 9 and 16, and that record now says what this one decides.
**Cited as**: code comments cite the sections of this record ("decision 2026-10-17 §3.2"), and the numbered properties ("§1, property 5"). The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The record of 2026-10-04** is [`2026-10-04-a-persons-devices.md`](2026-10-04-a-persons-devices.md).
- **Alpha.11** is the release 0.2.0-alpha.11, and **this version** is the version of the node that first carries what is below.
- **A record** is a record of an addition (the record of 2026-10-04, section 6). **Its adder** is the key that signed it, and **its key** is the key that it adds.
- **An adder that may add** is a key that `Counting::may_add` says yes of (`crates/cordelia-api/src/person.rs`): a device of the statement, or a key that counts and that such a device added.
- **A key that the 64 kept out** is the key of a record that fails for one thing only, that 64 devices count already (`NotCounted::NoRoom`). Such a key does not count.
- **The bound of 256** is `MAX_NOT_COUNTED_RECORDS`, the records that a reader keeps as not counted, and **the 256 rows** are `RECOVERY_MAX_DEVICES_SHOWN`, the rows that a recovery shows.
- **A carried name** is a name that a carry by command, or a recovery, brought versions into (section 4.3 says how a device knows).
- Examples say laptop and desktop.

---

## 0. What this is

Reviews of alpha.11 found four places where recovery and carrying keep a rule that does not protect what it is for. This record defines a change for each.

1. **Fairness between adders in the two bounds of 256** (section 2). Which records a reader keeps, and which rows a recovery shows, go by who signed them and not by when they were seen. Among the records the relays hold, each adder that may add keeps its first three keys that the 64 kept out, whatever another device signs.
2. **A recovery reads the personal channel on to its end** (section 3). The personal channel of the change recovered from is read on from the place reached, for up to 615 seconds, which is what a channel at its cap takes. The command says that it is reading. The phrase's own channel holds one entry, and a relay that handed none of it is said before the yes.
3. **What "sent to no relay" means where a carried name is let go** (section 4). Each entry of the name that this device signed counts as held only where a relay that the device is set up with handed it, or what moved its slot on, in a read made after the person asked, which reads on until each is found or the channel's end is reached.
4. **A way out for a carried name that no relay takes** (section 5). A typed `discard`, at a terminal, lets the name go with what no relay holds.

Nothing on the wire changes, and no relay needs a change (section 6). Two of the changes alter what every device runs: the order of keeping records (section 2), which every reader applies, and the check before a carried name is let go (section 4), which is local to each device. A person whose devices run alpha.11 and this version at once is safe with both (section 6).

## 1. The properties

Each is one sentence that a test can hold. Section 9 names the tests. Security properties come first.

1. **Among the records the relays hold, no record that one key signs takes from another adder that may add the first three places of its keys that the 64 kept out,** among the records a reader keeps and among the rows a recovery shows (`KEPT_OUT_PER_ADDER`).
2. **The records that a reader keeps do not turn on the order in which it saw them,** given who counts.
3. **A row of a key that the 64 kept out shows the label that each adder that may add gave it,** each beside that adder, and no one adder's label stands for the key.
4. Not used.
5. **On a device that reads the relays, a carried name is let go with an entry of its own that no relay holds only after the word `discard` is typed at a terminal,** once the command has said how many such entries there are, and where they may still be.
6. **For that check, an entry that this device signed counts as held only where a relay that the device is set up with handed, in a read that began after the person asked, the same version signed by a key that counts, or entries that, read as a slot is read, give its slot a current version at a higher revision.**
7. **A folder's unmapping never lets go of a name that a carry on this version brought versions into,** whether the folder was mapped before the carry or after it.
8. **On a device that has stopped, a carried name of which its own notes say it sent a version that it signed to no relay is let go only after the same typed word,** and the command says that the device could not read the relays.
9. **No let-go lets go of an entry that the read did not ask about:** where the store has taken anything of the name's channel since the read ended, or a `discard` comes with a read that is more than ten minutes old or a number that is not the one found, the node refuses.
10. **A recovery reads the personal channel of the change it recovers from on from the place each relay reached,** until each relay has handed it to its end or holds none of it, or until it has made `RECOVERY_READ_ON_READS` readings of `CARRY_READ_MAX_SECS`: five, the readings that fit in 615 seconds (`RECOVERY_READ_ON_MAX_SECS`).
11. **A recovery says before its yes each relay at which it read that channel in part, and each at which it could not read the phrase's own channel to its end.**
12. **The count of versions sent to no relay that a command says before its yes counts only entries that this device signed.**
13. **Nothing on the wire changes:** a relay of alpha.11 serves a device of this version as it serves one of alpha.11.

## 2. Fairness between adders in the two bounds of 256 (C1)

### 2.1 What the code does today

- **A reader keeps 256 records that do not count, the oldest it saw going first.** `keep_to_the_bound` (`crates/cordelia-api/src/person.rs`) splits the records that do not count into those that let a key add (`Counting::lets_add`: for each key that counts by a record, one record that a device of the statement signed, the first of them it saw) and the rest. The rest are dropped in the order the device saw them (`held_rows::additions` reads them `ORDER BY seen`), until 256 are left. Every device runs it, after each record it takes (`see_addition`).
- **A reader takes no record whose adder does not count.** The one door refuses every entry whose signer does not count (`take::taken_as_its_own`, `NotTaken::SignerDoesNotCount`), and `see_addition` refuses such a record besides. A recovery reads through the same door (`recover::read_generation` calls `take::take`).
- **A recovery reads the records in the order of the statement.** `read_generation` (`crates/cordelia-api/src/recover.rs`) sorts what the relays handed by the place of the signer in the statement, then by key, slot and revision, and gives it to the same functions over a database in memory. So the bound of 256 drops first the records of the device listed first.
- **A recovery shows 256 rows.** `read_generation` puts every device of the statement first, then the keys added since that count, then the records that do not count: those that fail only for the 64 (`only_for_room`) before the others, each group in order of key. `rows.split_off(RECOVERY_MAX_DEVICES_SHOWN)` cuts the rest.
- **A row of a key that the 64 kept out is shown by the record whose adder has the lowest key** among those that fail only for the 64 (the sort by `(row.key, !row.counts, !for_room, adder)` and `dedup_by`). Its label is that adder's word. The question is asked under the first adder, in order of key, that is not in someone else's hands (`asked_for_room`), and `recover_cmd::for_room_says` names that adder where it differs, without the label it gave.
- **What holds today:** nothing a key that does not count signed comes in. The command says how many rows it could not show (`not_shown_says`), counts the keys that a record was read for and that have no row at all (`Generation::no_row`, `no_row_says`), and marks each row one of whose records was read and not kept (`Row::record_let_go`). The key can be removed afterwards by `cordelia remove-device <key>`. But a key that has no row cannot be shown.

### 2.2 The rule: the order of keeping

A reader keeps the records that do not count in one order, and drops from its end until 256 are left. The order is a function of the records it holds and of who counts. It does not use the order in which they were seen.

1. **Records that let a key add** (`Counting::lets_add`). They are never dropped. There are at most 63: one for each key that counts by a record. Where several devices of the statement signed a record for that key, the one kept here is the oldest by the time it says (`Addition::at`), and then by the record's bytes; the others are in the fourth group. So which one is kept does not turn on when a reader saw them.
2. **Records whose key the 64 kept out and whose adder may add.** They are dealt by key to their adders in turn: each adder's first key before any adder's second, each adder's second before any adder's third, and so on.
   - An adder's keys are in the order of the time its first record for each says it was made (`Addition::at`), the oldest first, and then by key. That is the adder's word, and it orders only that adder's keys.
   - An adder has one place for each key. Where it signed two records for one key (`cordelia add` run twice), the oldest by its time, and then by the record's bytes, takes the place, and the other is in the fourth group.
   - Among the keys of one turn, the devices of the statement come first, in its order, and then the other adders by key.
3. **Records whose adder counts and may not add yet** (`NotCounted::MayNotAdd`): the adder was added by a key added since, not by a device of the statement. Dealt to their adders in turn, in the same way. Such a record comes to count where a record by a device of the statement is kept for its adder, so it is kept before the rest.
4. **Every other record that does not count:** a record of a removed key (`NotCounted::Removed`), a record of a key that counts already that is not the one of the first group (`NotCounted::CountsAlready`), and an adder's second record for a key it has a place for. By the time each says, and then by key, adder and the record's bytes.

**What it gives.** At most 63 records are of the first kind, and at most 64 adders may add. So at least 193 places are left for the second kind, and each adder that may add keeps at least its first three keys that the 64 kept out: `KEPT_OUT_PER_ADDER`, 3. That holds whatever any other key signs, and however many adders sign, **among the records that the relays hold.** A record that no relay holds reaches no reader (section 7).

**The rows of a recovery follow the same order.** After every device of the statement and every key added since that counts (at most 64 rows together), the rows of records that do not count are in the order above. At least 192 rows are left, so each adder that may add has a row for at least its first three keys that the 64 kept out: 3 again. A row of a key that several adders added stands at the best place any of them gives it.

**Why three is enough.** A person adds devices one at a time, from a device in hand. An adder that added more than three devices since the last change, all while 64 already counted, is not an ordinary case. Where it happens, the command still says what it could not show (section 2.5).

### 2.3 A key that a key the 64 kept out added

A tablet that the 64 kept out does not count. A phone added from that tablet is a second level.

**The phone has no row, and is counted nowhere.** Its record is signed by a key that does not count, so no reader takes it: not a live reader and not a recovery (2.1). It is not among the records a reader keeps, so it is not in `no_row` either. This is the rule of the record of 2026-10-04 (section 4.4): a key that does not count adds nothing, and its word is not read.

**It is not the case of `NotCounted::MayNotAdd`.** That is a record whose adder counts, but was itself added by a key added since. Such a record is kept, in the third group of 2.2, and has a row where room is left.

**The row of a key that the 64 kept out says it, where that key signed a record:** a device that it added is not shown, since a key that does not count adds nothing. The door takes nothing that key signed, so `read_generation` looks for it in what the relays handed, outside the door, as `names_before` reads names there: an entry of the personal channel under an `added/` name, signed by that key, that opens with the channel's secret. So a person whose tablet is asked about learns that a phone added from it is in no row. What the phone wrote is not brought back. If the person still has the phone, they add it again by hand.

**It is not asked about.** What lets a key that does not count be asked about is that an adder that counts vouched for it. An adder that never counted vouches for nothing. Were such keys read, any chain of records would be read, and each answer of "gone" would take one of the phrase's 256 removals.

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
  A device that it added is not shown here: a device that does not count adds nothing.
```

The last line is said only where the key signed a record of an addition (2.3).

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
- **Reading a second level outside the door, at a recovery.** It would show at a recovery a key that no live reader reads, and ask the person about a chain that no device vouched for.

### 2.7 What every device runs

`keep_to_the_bound` changes, and every device runs it. A person whose devices run alpha.11 and this version at once is safe:

- **Who counts does not change inside the bound of 64.** A record that counts is never dropped, by either version. The records that can come to count later are those whose adder may not add yet. Where a reader drops one, and then a record comes to count or a key comes to add, the reader reads every channel of its own again from the start (the record of 2026-10-04, section 16; `at_relays::take_page` forgets every place where `came_to_count` or `came_to_add` is not 0). The dropped record is given again, and is judged again. So two versions that kept two sets beyond the bound count the same keys, as two readers that saw records in two orders do today.
- **What differs beyond the bound is which records that do not count each keeps,** and so what `cordelia devices` and the prompt of a statement show of them. Beyond the bound two readers can differ already (the record of 2026-10-04, section 6).
- **A recovery reads with the command's own functions,** so a recovery of this version reads by this order, whichever version the devices ran.

**Schema:** nothing is stored. The order is worked out from the rows of `person_additions` as they are: the record's bytes hold its time, and the row holds its key and adder.

**Constants,** in `crates/cordelia-core/src/protocol.rs`:

- `KEPT_OUT_PER_ADDER: usize = 3`. Derived: the lesser of `(MAX_NOT_COUNTED_RECORDS − (MAX_COUNTED_DEVICES − 1)) / MAX_COUNTED_DEVICES` (193 / 64 = 3) and `(RECOVERY_MAX_DEVICES_SHOWN − MAX_COUNTED_DEVICES) / MAX_COUNTED_DEVICES` (192 / 64 = 3), checked at compile time to be at least 1. For `parameter-rationale.md` §12.6: "How many keys that the 64 kept out each adder that may add keeps among the records a reader keeps, and among the rows a recovery shows, whatever another key signs, of the records the relays hold. It is what is left of each bound once the records that let a key add, or the rows of the devices that count, have their places, shared among the 64 adders there can be. It is not chosen: it follows from the three bounds it is made of. A person who adds more than three devices from one device while 64 count is told what could not be shown."

## 3. A recovery reads the personal channel on to its end (C2)

### 3.1 What the code does today

- **The command reads each channel in one call.** `recover_cmd::read_channel` calls `carry_cmd::read_with_secret`, which posts to `POST /api/v1/carry/read` (`carrying::read_proved`). There `read_with_proofs` reads at every relay until `CARRY_READ_MAX_SECS` (120 seconds), through `DeviceEntries::read_left` (`crates/cordelia-node/src/device_entries.rs`), which starts at `(NO_MARK, 0)`: from the start. Where a connection changed, `read_again_where_changed` reads again, from the start, up to `CARRY_PROOFS_MADE_AGAIN` times.
- **`read_left` says where a channel ends.** A page that holds nothing, or that leaves the place where it was, is the channel's end: the read is whole. A page of which nothing is an entry of the channel, though the relay handed something, is not: the read is in part. So is a read that reaches its time.
- **A device takes from one relay about 2 MiB a minute.** `room_to_take` holds a read to `PUSH_BYTES_PER_PEER_PER_MINUTE`, counted with `ENTRY_OVERHEAD_BYTES` for each entry, and a relay sizes a page to leave `SHOW_ANSWER_ROOM_BYTES` for the answer to a show. A channel may hold `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, 16 MiB, counted the same way. So one read reaches about 4 MiB, and a channel at its cap takes about 8¼ minutes.
- **The personal channel read in part.** The command goes on with what it read, and `WasRead::lines` says so before its yes. It refuses only where nothing is known at any relay (`personal_not_read_says`).
- **Step 1, the phrase's own channel.** It holds one entry, the change entry of 32 KB, which only the phrase writes (the record of 2026-10-04, section 2.2). So one read takes it whole at a relay that hands anything. It is read by the same `read_channel`. As it reads, the command says each relay that it could not read to its end, but not one that holds none of it (`recover_cmd::read_channel`, `not_read_to_its_end`). Where a change is found, the command goes on from the one with the highest number (`recover::found`). It says nothing of those relays again before its yes, and `none_found_says` names them only where no change was found.
- **The tests.** A recovery that read its personal channel in part and went on to its yes is tested in process only (`recover_cmd`, `test_a_recovery_goes_on_with_what_it_could_read_of_the_personal_channel`). The real-process test (`recover_e2e.rs`, `a_recovery_says_at_which_relay_the_personal_channel_was_not_read`) has a second relay that was not reached, and a first that handed the channel whole.

### 3.2 The rule: read on

**The command reads the personal channel of the change it recovers from (step 3) on from where each relay reached,** round after round:

1. The first round is the read of today: from the start, for `CARRY_READ_MAX_SECS` at most.
2. The node says, of each relay that it read in part, the place it reached there: the mark of the relay's holding and the next place, as a pull keeps them (`at_relays.mark`, `at_relays.place`).
3. The command asks again, of those relays only, from those places. Where a relay says in a round that its connection changed, the command makes its proofs again and reads again **that relay alone,** from the place it had: the others answered, and are not read again from the same place. A relay that answers under another mark than the place was asked under has dropped and taken the channel again since: it is read from the start there, and what was read before is kept.
4. It stops at a relay that has handed the channel to its end or holds none of it, and everywhere once it has made `RECOVERY_READ_ON_READS` readings (five). **Each round is a reading, and so is each reading again of a relay whose connection changed.** The bound is counted in readings and not in seconds since the first round: what a reading takes beyond its `CARRY_READ_MAX_SECS` (a page in flight at its end, the handing of what it read to the command) then never costs the fifth reading, which a channel at its cap needs. So the reading is five readings of two minutes and what each takes beyond that. **The end is what `read_left` says it is:** a page that holds nothing, or that leaves the place where it was. A relay that stalls so is read to its end, as today. **A relay that is not reached in a round is not asked again:** it stays as it was, and a relay that is down does not hold the read for 615 seconds. A relay that handed part of the channel and then answers that it holds none of it is read in part.

The personal channels of the generations before, which are read for names, are read once each, as today (section 11).

**The phrase's own channel (step 1) is read in one round, as today.** It holds one entry, so a relay that hands anything of it hands it whole. A relay that holds none of it says so, and is not said. A relay that could not be read to its end (it was not reached, or its read ended before the entry was handed) is said as today while the command reads, and again before the yes, whether or not a change was found elsewhere: it may hold a later change than the one recovered from.

Through the door the node still stores nothing of what it pulls and pushes nothing (the record of 2026-10-04, section 4.6). It keeps no place of its own either: the command is handed the place, and asks from it.

**Where a relay is still read in part at the end,** the command goes on with what it read, as today, and says so before its yes.

The command holds the phrase while it reads, as it does today for the first round. Ctrl-C stops it there, and nothing is made.

### 3.3 What a person reads

After the first round, where a relay was read in part, and then one line after each round:

```
The personal channel of change 3 is larger than one read. Reading on at relay-one: a relay
may hold up to 16 MiB of it, which takes up to 10 minutes to read. Ctrl-C stops here, and
nothing is made.
  relay-one: 4.0 MiB read so far.
  relay-one: 8.1 MiB read so far.
  relay-one: read to its end, 9.3 MiB.
```

The lines are on standard output, as the other lines of a recovery are. A size is counted as a relay counts it against its cap: each entry's content and `ENTRY_OVERHEAD_BYTES`. So 9.3 MiB is of the 16 MiB a relay may hold.

Where a relay is still read in part at the end, the line of `WasRead::lines` for a channel read to its end at no relay ends so, in place of what it says of a device that filled the channel. It says what can have stopped the reading, and not that it lasted ten minutes, which it often did not:

```
It was read on at each relay until the relay was not reached, held none of it, handed no
more, or had been read for 10 minutes, as long as a channel at its largest takes: a relay
that hands it more slowly than that, or stops, leaves it in part.
```

Step 1, before the yes, where the phrase's own channel could not be read to its end at a relay:

```
The recovery phrase's own channel could not be read to its end at relay-two: it may hold a
later change. This recovery is made from change 3, the latest in what was read. Only the
recovery phrase writes in that channel.
```

### 3.4 Turned down

- **A longer read for every carry.** `CARRY_READ_MAX_SECS` bounds the read of every name by `cordelia sync carry` and by the look of a recovery, and the time a mapped folder waits for its first cycle (`CARRY_FIRST_MAX_SECS`). Those are read for each name. Ten minutes for each would hold a folder up for ten.
- **One call that lasts ten minutes.** A connection that changes in that time would cost the read from the start, and the person would see nothing for ten minutes. Rounds from a place cost one round where a connection changes, and say how far they are.
- **Refusing where the channel was read in part.** A relay that answers slowly could refuse every recovery for ever. That is why today's rule goes on, and this one keeps it.
- **Reading only the slots that matter.** A relay sees no names, and the command does not know them before it reads: a slot is the hash of a name under the channel's slot key.
- **Reading the phrase's own channel on.** It holds one entry: a relay that hands anything of it hands it whole.

### 3.5 What every device runs

Only the command of a recovery and the node it talks to. The door's read gains a place to start from, and `POST /api/v1/carry/read` gains, for each relay, a place to start from and the place reached. A command of alpha.11 does not talk to a node of this version: a command that changes anything refuses a node of another version (the record of 2026-10-04, section 10.1, rule 6). Nothing else of a device changes.

**Schema:** nothing is stored.

**Constants,** in `crates/cordelia-core/src/protocol.rs`:

- `RECOVERY_READ_ON_MAX_SECS: u64 = 60 × MAX_ENTRY_CHANNEL_BYTES_AT_RELAY / (PUSH_BYTES_PER_PEER_PER_MINUTE − SHOW_ANSWER_ROOM_BYTES) + CARRY_READ_MAX_SECS`, that is 60 × 16,777,216 / 2,030,592 = 495, and 495 + 120 = 615. For `parameter-rationale.md` §12.9: "How long a recovery reads the personal channel of the change it recovers from, at most, counted from its first round, and how long the check before a carried name is let go reads the name's channel (decision 2026-10-17 §3, §4.2). It is what a channel at its cap takes to read at what a device takes from one relay in a minute, less the room a relay keeps for the answer to a show, and one round more: so a relay that hands what it may is read to its end. What a person's devices write in the personal channel is small, so this is reached only where a channel is near its cap, or a relay is slow."
- `RECOVERY_READ_ON_READS: u64 = RECOVERY_READ_ON_MAX_SECS / CARRY_READ_MAX_SECS`, that is 5. For `parameter-rationale.md` §12.9: "How many readings of `CARRY_READ_MAX_SECS` a recovery makes of the personal channel of the change it recovers from, at most: each round is one, and so is each reading again of a relay whose connection changed. The bound is counted in readings so that what a reading takes beyond its time never costs the reading that reaches a channel at its cap."
- No other. A round is `CARRY_READ_MAX_SECS`, and a line is said after each round.

## 4. What "sent to no relay" means where a carried name is let go (C3)

### 4.1 What the code does today

- **Unmapping a carried name is refused while a version of it was sent to no relay.** `sync::let_go_of_a_carried_name` asks `names::waits_to_be_sent`, which asks `at_relays::sent_to_no_relay` (`crates/cordelia-storage/src/at_relays.rs`): the entries of the name's channel in the store whose place is above what the device keeps as sent to every relay (`at_relays.sent_to`, or `carried_to` for what it carried when it last applied a statement, `carried_up_to`), or that a relay refused for room (`at_relays_refused`). The refusal is `sync::not_let_go_says`. The route `sync::unmap` holds the database's lock for the whole of its body.
- **What that counts as sent:**
  - **what went to a relay the device is no longer set up with.** Rows of such a relay go only in `at_relays::forget_what_is_done`, where every relay's key is known, which is while all of them are connected;
  - **what a relay refused as not checking** (`Pushed::DoesNotCheck`), **and what it holds in another form** (`Pushed::HoldsAnother`): `at_relays::sent` moves on past both;
  - **what a relay dropped since,** until the next pull there finds no holding, or another mark (`take_page`, `start_again`), or a proof is answered no (`not_held_at`).
- **The refusal lasts for as long as no relay has room.** An entry refused for room stays in `at_relays_refused`, and is offered again after a wait.
- **A name that a folder was mapped to before a carry brought versions in is the folder's name.** `names::hold_for_a_carry`, which a carry by command (`carrying::holds`, `carrying::brought_holding`) and a recovery's look (`recover::follow`, after `names::hold_mapped`) each call, adds a name to `person.names_carried` only where no folder is mapped to it. A folder's unmapping (`sync::names_follow`) then stops the name with what waits.
- **On a device that has stopped,** `waits_to_be_sent` counts none (it asks `at_relays::stands` first). So `cordelia sync unmap <name>` lets go of a carried name at once, what no relay holds included. The line after a folder's unmapping (`still_held_says` in `crates/cordelia-node/src/main.rs`) says "once nothing of it waits to be sent" there too, where nothing is ever sent again.
- **And the count can overstate.** `take_page` marks what it took from a relay as sent there only where nothing else waited (`if !waiting`). On a device that sends, the next push clears that: the relay answers that it holds it. On a device that has stopped, nothing clears it. So the count that `cordelia init --new-key`, `cordelia phrase` and `cordelia accept` say before their yes (`names::waits_in_every_name`) can include entries that came from a relay.
- **A refusal is said on standard error, and the command ends with status 1.** A let-go is said on standard output, with status 0.

### 4.2 The rule: held is what a relay just handed

The check protects one thing: **a version of a carried name that is nowhere else in the generation applied.** On a machine that has just recovered, that is the only copy outside the generation that was left. So the check asks the relays, and not the device's notes of what it sent.

1. **Before a carried name is let go, the device reads the name's channel at each relay it is set up with.** It is a pull of the device's own channel, under leave, as a pass makes it (the record of 2026-10-04, section 4.6), from the start and then on from the place reached, round after round as a recovery reads (3.2). It stops at a relay that has handed the channel to its end or holds none of it; everywhere once each entry asked about is held at one relay; and everywhere at `RECOVERY_READ_ON_MAX_SECS` from the first round.
2. **What it pulls through, and what it keeps.** The carry door refuses a device's own channel (`LeftRefused::OwnChannel`), so the read is a pull of pages under leave, taken through `at_relays::take_page` and the one door, as a pass takes them. It differs from a pass in three things:
   - **Its places are its own,** in memory, under the read's ID: it starts at `(NO_MARK, 0)` and never writes the stored place (`keep_place`). The pass's place at each relay is left as it was.
   - **It marks nothing as sent.** What it is handed is stored as any entry is, but `at_relays.sent_to` does not move for it.
   - **It notes what each relay handed in each slot,** for the check.

   It asks and takes within the same budget as the pass at that relay, and not beside it: what the device takes from one relay in a minute (`room_to_take`, `PUSH_BYTES_PER_PEER_PER_MINUTE`), and the requests it makes there on its own channels (`OWN_ENTRY_REQUESTS_PER_MINUTE`). Where the minute is used, it waits, as a pass does.
3. **The read runs outside the database's lock.** The node keeps the read in memory under an ID, with its places, and the command asks it to read on, round by round, under that ID. The let-go itself takes the lock.
4. **The entries asked about are every entry of the name's channel that this device signed, as the store holds them when the read ends.** A slot keeps one entry for each author, so this is at most one for each slot: the device's current version there, one that lost a tie (`version::Slot::lost`), or one that another device wrote over. What a carry or a recovery brought is among them: a carried entry is this device's own (`person::carried_entry`). An entry that another key signed came here from a relay (4.5).
5. **An entry is held where one relay handed, in its slot, in that read:**
   - an entry that is the same version (the same text or delete at the same revision: the record of 2026-10-04, section 2.3) signed by a key that counts; or
   - entries that, read as a slot is read (`version::read`, with who counts and under the statement applied), give the slot a current version at a higher revision. An entry that does not open, is over its bound, or is in a band above the statement is no version there, and moves nothing on.

   So an entry of this device's that lost a tie is held only where a relay handed it, or the same version, or a higher one: the winner of the tie does not hold it.
6. **One relay is enough.** Relays that work together pass entries on, and a recovery is set up with relays of the person's choosing.
7. **Anything else is held by no relay:** a relay that was not reached; one that was read in part, for what it did not hand; one that refused the entry as not checking, holds another, dropped the channel, or had no room; and an entry signed by a key that does not count, which no reader takes.
8. **Every let-go is bound to its read.** The node lets go only where its store has taken nothing of the name's channel since the read ended (`at_relays::last_taken` of the channel is what it was then). Otherwise it refuses, and the command says to run it again. So an entry that a pass or a `sync carry` brought in after the read is never let go unasked.

So each of the gaps of 4.1 closes by the same rule. A relay that the device is no longer set up with is not read. What was refused, held in another form that is not the same version, dropped, or refused for room, is not handed.

**The notes of what was sent stay as they are** for what they decide: what is offered again, what `cordelia devices` says is still to send, and whether a device writes that it has sent what it carried (the record of 2026-10-04, section 8). Section 11 says why.

### 4.3 A name a carry brought versions into, folder or not

**A name into which a carry by command, or a recovery, brings a version is a carried name from then,** whether or not a folder is mapped to it:

- Where no folder is mapped, it is in `person.names_carried`, as today.
- Where a folder is mapped, it is in a new key of `node_meta`, `person.names_brought_in`, a list of names as the first is.

**The mark is set where a version is brought in.** Where `carry::bring` returns `Brought::Carried` under a name that a folder is mapped to, the caller adds the name to `person.names_brought_in`, in the transaction of the bring. Every carry brings through `carry::bring`: a carry by command (`carrying::carry_name` for `cordelia sync carry`, `carrying::take_from` for the carry `--from`, and `carrying::take_handed` for what a command hands under the phrase's word) and the look of a recovery (`recover::the_look`). Holding a name sets no mark: `names::hold_for_a_carry` is called before anything is brought, and not at all for a name that a folder already holds (`carrying::holds`).

**The carry that `cordelia sync map` makes is not a carry by command.** It brings, before the folder's first cycle, versions of the folder's own name into the slots that hold nothing (`carry_name` with `only_where_empty`, from `sync::map`). The name is the folder's from the start, and the folder publishes over what it brought. It sets no mark, and the folder's unmapping stops the name as it stops any folder's name.

**A folder's unmapping never lets go of a carried name.** Where the folder was the name's last, the name is added to `person.names_carried`, and is held as it is held today when a carry brought it with no folder. It stays in `person.names_brought_in`, which then says that a folder was mapped to it. `cordelia sync unmap <name>` then lets it go by the check of 4.2. A name leaves `person.names_brought_in` when the device stops it, and both lists go when the device leaves its phrase, as the first does today.

**A name brought in under a folder on alpha.11 is not in the list.** Nothing fills `person.names_brought_in` for it at the upgrade. Unmapping that folder still stops the name, as on alpha.11. The relays still hold what was carried, in the channels it was carried from.

### 4.4 A device that has stopped

A device that has stopped (it was removed, is in no list, could not open a change, or is in a fork) has no leave anywhere, and reads none of its channels. It cannot ask the relays.

- **`cordelia sync unmap <name>` there lets a carried name go only after the typed word of section 5,** where the device's own notes say that it holds a version of the name that it signed and sent to no relay. Where they say none, it lets the name go at once, as today.
- **The node keeps the count it took from its notes under an ID,** as it keeps a read (4.2), for `LET_GO_READ_STANDS_SECS`. A `discard` there is bound to that ID and that number, and to a store that has taken nothing of the channel since, as anywhere.
- **Property 5 is of a device that reads the relays.** On a device that has stopped, the notes decide: where they are wrong (a relay dropped the channel, or the entry went to a relay the device is no longer set up with), the name is let go at once, with no word. Property 8 is what holds there.
- What it loses matters for one case: a device in no list, or one that could not open a change, can be added again, and then carries what it holds.
- **The notes count only what the device signed** (4.5). They are a device's own word, and the command says that it could not check them.

### 4.5 The count said before a yes counts only this device's entries

`at_relays::sent_to_no_relay` counts only entries whose author is this device's key. An entry that another key signed came to this device from a relay. So `names::waits_in_every_name`, which `cordelia init --new-key`, `cordelia phrase` and `cordelia accept` say before their yes, no longer counts what a device took from a relay while something else waited there. The same count is what 4.4 uses.

**It can still overstate in one case:** a device's own entries that come back to it from a relay. A device restored from a backup takes its own later entries from a relay. One taken while something else waited is counted until the next push clears it, and for ever on a device that has stopped. The count then errs toward asking.

### 4.6 What a person reads

`cordelia sync unmap lab`, where every version is held, on standard output, with status 0:

```
This device holds lab no longer. It held it by a carry, with no folder mapped to it: a relay
held each of its 12 versions when it was read just now, so nothing is lost by it. Your other
devices keep what they hold of it.
```

Where the read takes more than one round, a line is said after each on standard output, as in 3.3: "Reading lab at relay-one: 4.0 MiB so far."

`cordelia sync unmap lab`, where a version is held by no relay, with no terminal. The node's refusal, in place of `not_let_go_says`, on standard error, with status 1:

```
lab is not let go: no relay that this device is set up with held 3 of its versions when it
was read just now.
  relay-one: read to its end. It had no room for 3 of them, the last time 2 minutes ago.
  relay-two: not reached.
This device goes on sending them, and lab can be let go once a relay holds them. To let it go
now, with them, run `cordelia sync unmap lab` at a terminal.
```

Where the store took something of the channel since the read, on standard error, with status 1: "lab is not let go: this device took something of it while it was read. Run `cordelia sync unmap lab` again."

Where the node no longer knows the read's ID (it was started again during the read, or before the word), on standard error, with status 1: "lab is still held: the node was started again since lab was read. Run `cordelia sync unmap lab` again."

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
- **One read of 120 seconds from the start.** A name of more than about 4 MiB would never be read to its end, and every let-go of it would need `discard`. That teaches the word.

### 4.8 What every device runs

Each device, for itself. Nothing is sent to another device or to a relay but a pull that a pass would make anyway. A device of alpha.11 beside one of this version is not affected.

**Schema:** one key of `node_meta`, `person.names_brought_in`, listed in `crates/cordelia-storage/src/meta.rs`. No step of the schema: a key of `node_meta` is a row of a table that exists.

**Constants:** none. The read is bounded by `RECOVERY_READ_ON_MAX_SECS`, in rounds of `CARRY_READ_MAX_SECS`.

## 5. A way out for a carried name that no relay takes (C4)

### 5.1 What the code does today

Short of beginning again (`cordelia init --new-key`, or `cordelia phrase`), a carried name whose versions no relay takes can never be let go. `let_go_of_a_carried_name` refuses while a version was sent to no relay, and a folder's unmapping leaves the name held (`names_follow`). The device goes on offering what was refused for room, after a wait that doubles up to `OUTBOX_REFUSED_RETRY_MAX_SECS`.

### 5.2 The rule: a typed `discard`, at a terminal

**Where the check of 4.2 finds a version held by no relay, `cordelia sync unmap <name>`, at a terminal, says what it found and asks for a typed word: `discard`.** No answer is suggested. Anything else, or Enter, keeps the name.

- **Who may give it.** The rules of a yes in the record of 2026-10-04 (section 5): it is asked by the command, at a terminal, and refused where the command's input is not a terminal. It stops a command run by mistake, or by a script that has no terminal. It does not stop a program that runs as the person (section 7).
- **It asks for no phrase.** Nothing comes in by it, and nothing is signed. It lets go of what this device holds, which a program that runs as the person could delete from the database anyway.
- **What is let go is what was shown.** The node keeps the result of the read in memory, by an ID, for `LET_GO_READ_STANDS_SECS` (600 seconds) from the end of the read, measured on the node's monotonic clock (an `Instant`), so that a step of the wall clock neither widens nor shortens it. The command sends that ID with the word and the number of versions it showed. The node lets go only where the read stands, the number is the one it found, and its store has taken nothing of the name's channel since the read ended (4.2, item 8). Otherwise it refuses, and the command says to run it again.
- **Where the versions may still be.** The prompt says it, from what the device knows, and promises nothing it does not know:
  - **What a carry brought** is still in the channels it was carried from, at the relays, for as long as the device holds the secret of each generation that it left (section 3 of the record of 2026-10-04), and the command that carried it brings it in again: `cordelia sync carry <name>` for what keys that count signed, and `--from <device>`, with the phrase, for what a removed key signed. The prompt says how many more days the device holds the latest of those secrets.
  - **What was written on this device since,** by a folder mapped to the name, or over what was carried, is on this device alone in the channel, and goes from the channel for good. The store keeps no mark of which entry a carry made, so the prompt does not say how many of the versions are of each kind. It says that any written here go from the channel for good.
  - **A folder that was mapped to the name keeps its files.** Unmapping a folder forgets only what the folder had agreed with the channel (`sync::forget_what_is_not_mapped`); it deletes no file. So the words a folder wrote may still be in it, as files, and the prompt says so where a folder was mapped to the name (it is in `person.names_brought_in`, or was when its last folder was unmapped).
  - Where the device holds no secret of a generation it left, the prompt says that the versions are on this device alone.

On a device that has stopped (4.4) the same word is asked, and the prompt says that the device could not read the relays.

### 5.3 What a person reads

```
laptop$ cordelia sync unmap lab
lab is not let go: no relay that this device is set up with held 3 of its versions when it
was read just now.
  relay-one: read to its end. It had no room for 3 of them, the last time 2 minutes ago.
  relay-two: not reached.
This device goes on sending them, and lab can be let go once a relay holds them.

Letting lab go now drops those 3 versions from this device. A version that a carry brought
into lab is still at the relays, in the channel it was carried from, for 61 more days at
most: `cordelia sync carry lab` brings in again what a device that counts wrote, and
`cordelia sync carry lab --from <device>`, with the recovery phrase, what a removed device
wrote. A version written on this device since it was carried is on this device alone, and
goes for good: this device does not keep which of the 3 those are.
  Type `discard` to let lab go with them. Anything else keeps it:
```

Where a folder was mapped to lab, a sentence follows the second: "A folder that was mapped to lab keeps its files: what it wrote may still be there."

On `discard`, on standard output, with status 0:

```
This device holds lab no longer, and 3 versions that no relay held went with it.
```

followed, where the statement lists another device, by "Your other devices keep what they hold of it."

On anything else, on standard output, with status 0, as for any yes not given: "lab is still held. Nothing was changed."

Where the node refuses the word (the read is older than ten minutes, the number differs, or the store took something since), on standard error, with status 1: "lab is still held: what was read has changed since, or is too old. Run `cordelia sync unmap lab` again."

Where the device holds no secret of a generation it left, the second paragraph is: "Letting lab go now drops those 3 versions from this device: they are on this device alone."

On a device that has stopped, the first paragraph is:

```
This device has stopped (it was removed), and sends nothing more. It cannot read the relays to
learn whether they hold lab. Its own notes say that it sent 3 versions of lab, which it wrote
or carried, to no relay. If this device is added again, it carries what it holds: what is let
go now is not among it.
```

The words in brackets are those of its status: "it was removed", "it is in no list of the last change", "it could not open the last change", "two changes were made apart". The last sentence is said only where the device can be added again (it is in no list, or could not open a change). With no terminal there, the command says the first paragraph and "To let it go now, with them, run `cordelia sync unmap lab` at a terminal.", on standard error, with status 1.

### 5.4 Turned down

- **The phrase.** An agent with a shell can give a yes and not the phrase. But nothing comes in by a discard: it lets go of what one device holds. The phrase is for what lets a removed key's work in, or changes who is a device.
- **Letting go by itself after a time.** That loses what no relay holds without a person's word.
- **Beginning again,** which is all there is today. It lets go of every name, every secret and the device's key, to let go of one name.
- **Counting apart what was written here.** The store keeps no mark of which entry a carry made. `carried_up_to` marks where the store stood when the device last applied a statement, not a carry by command or a recovery's look. A mark for each entry is a step of the schema; section 11 puts it off.

### 5.5 What every device runs

Each device, for itself. `POST /api/v1/sync/unmap` gains the ID of a read, the word and a number, and a way to ask the node to read on under that ID. A command of alpha.11 does not send them to a node of this version, which it refuses (rule 6). A node of this version answers a request without them as in 4.6.

**Schema:** nothing is stored. The read is held in memory.

**Constants,** in `crates/cordelia-core/src/protocol.rs`:

- `LET_GO_READ_STANDS_SECS: u64 = CARRY_WORD_SECS as u64` (600), with `CARRY_WORD_SECS > 0` checked at compile time. It is a `u64`: it bounds a `Duration` on a monotonic clock, where `CARRY_WORD_SECS`, an `i64`, is compared with a time in seconds of the wall clock. For `parameter-rationale.md` §12.9: "How long the read that `cordelia sync unmap` shows, or the count that a device that has stopped took from its notes, stands for the `discard` that follows it (decision 2026-10-17 §5). The person reads the lines and types the word in that time. A word typed later lets go of nothing, and the command is run again. Derived: as long as a word of the phrase for a carry stands, the other act at a prompt that follows what the node read."

## 6. Alpha.11 and this version together, and what a relay sees

**Nothing on the wire changes.** No stream, no answer, no entry, no record and no statement changes form. A relay of alpha.11 serves a device of this version, and a device of alpha.11 is served by a relay of this version, as before. **No relay needs a change.**

**A person whose devices run two versions at once:**

- **Who counts is the same on both** inside the bound of 64 (2.7). Beyond the bound of 256, each keeps what its version keeps, and each shows that. A recovery made with this version reads by this version's order.
- **A recovery made with this version** reads the personal channel on (section 3). It reads channels that devices of either version wrote. A command and a node of two versions do not work together (rule 6).
- **The check before a carried name is let go, and the word,** are of the device where the name is let go (sections 4 and 5). A carried name on a device of alpha.11 is let go as alpha.11 lets it go.
- **The count before a yes** counts only a device's own entries on this version (4.5), and all of them on alpha.11. Each device says its own.

**What a relay sees of it:**

- **Of section 3:** a recovery's longer read of one channel, page after page, within what a relay hands a connection in a minute, as a carry's read is. It is a pull of a channel that a proof opened, from a place, like any pull.
- **Of section 4:** a pull of one channel of the device's own, from the start and on, for up to 615 seconds, when a person lets a name go.
- **Of sections 2 and 5:** nothing.

## 7. Who can do what

**A device that counts, in someone else's hands, while it still counts:**

- It can sign any number of records. Under the order of 2.2 those records take places only from its own share and from the shares of keys it added. Among the records the relays hold, each other adder that may add keeps its first three keys that the 64 kept out, among what a reader keeps and among a recovery's rows (property 1).
- It can add keys that count until 64 do, and each key it adds so may add in its turn. That makes at most 64 adders, and the floor of three holds with 64 adders.
- It can give a key a label. Its label is shown beside it, among every other adder's label for that key (property 3). It cannot change the words of a key's fingerprint.
- **It can fill the personal channel at a relay to its cap,** `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`, 16 MiB. A record and its name (`added/` and a key of 70 characters) take more than `MIN_ENTRY_CONTENT_BYTES`, so each is a content of 512 bytes at least, counted at 1,536 with `ENTRY_OVERHEAD_BYTES`: some 11,000 records at most do it. The relay then refuses every later entry of that channel, whoever signs it (`relay::taken`, `Refused::ChannelFull`): a record, a word that a device syncs a name, a word that it has applied a statement.
  - **What does not hold then.** A record that comes after the channel is full reaches no reader at that relay, and no recovery that reads there. The floor of three holds only among the records the relays hold. An honest record that the 64 keep out is always late: a device does not sign one where it has seen the 64 count (`adding::add_device` refuses `NoRoom`), so it signs one only where it had not yet seen them. Nothing in this record keeps a place for it at the relay.
  - **What the person sees.** Each device whose entry the relay refused, and that syncs a folder, shows the status line "memory: a relay has no room" for as long as the refusal stands (`indicator`, `NO_ROOM_STANDS_SECS`). On each such device `cordelia devices` names the relay and says that it is full (`look::relays`). It also shows the records that do not count, by the device that signed them: hundreds from one device. A name that a device maps after that is not listed there, and a device's word that it applied a statement is not seen.
  - **What the person can do:** remove that device (`cordelia remove-device`, with the phrase). The next statement makes a new personal channel, which the removed device cannot write in. Records are not carried to it (the record of 2026-10-04, section 6): a device that was refused is added again by hand after the statement.
  - A recovery reads a full channel for up to 615 seconds, and reads it to its end at a relay that hands what it may (property 10). A device whose record the relay refused has no row there, and is not counted in `no_row`.
- What holds as before: nothing it signed comes in at a recovery where it was said to be in someone else's hands, and its records are no device.

**A key that it added:** the same as the device that added it, within the same share. Where the 64 kept that key out, it does not count: no reader reads what it signs, and a key that it adds has no row (2.3).

**A relay that answers falsely or slowly:**

- It can hand less than it holds, and say that it has handed the channel to its end. A recovery and the check of 4.2 then believe it, as today: a relay is a cache. A second relay set up with the device answers for itself.
- It can hand a channel slowly. A recovery reads for 615 seconds and goes on with what it read, and says so (property 11). The check of 4.2 reads for as long, and counts what was not handed as held by no relay: the name stays held, and the person can type `discard`.
- It can say that it holds a version that it does not, only by handing that version, which it cannot forge: an entry is signed by the channel's key and its author's, and only an author that counts makes it held. A relay that handed a version can drop it a moment later. Nothing defends against that, as nothing defends against a relay dropping anything.
- It cannot change which records a reader keeps: the order goes by what the records say and who counts, and not by when they arrived. It can keep a record from every reader that reads only there, by not handing it.

**A key that holds the secret and does not count** (one that the 64 kept out, that was handed the secret): it can write entries in the name's channel at a relay. It cannot make an entry held for the check of 4.2: only an entry signed by a key that counts does (property 6).

**A device that counts, in someone else's hands, and the check of 4.2:** it can push an entry into a slot of a carried name at a relay. It makes an entry of this device's held only where that entry is a version, read as a slot is read: one that does not open, is over its bound, or is in a band above the statement moves nothing on. A real version above it is shown on every device, as any write over another's is.

**A person who types yes at the wrong prompt:**

- At the prompt of section 5, a typed `discard` drops the entries that no relay holds. A `y`, a `yes` or Enter keeps the name. The prompt says how many go, where what a carry brought may still be, that what was written here goes from the channel for good, and that a folder that was mapped keeps its files.
- At a recovery, an answer typed to a row whose labels differ is an answer about the key that the words name, under every label shown.
- A program that runs as the person can type `discard` (the threat model's T17). What is left is that the carried versions are still in the channels they were carried from, for as long as the device holds those secrets, and the command that carried them brings them in again. What was written here since is lost.

## 8. What it costs

- **Time.** A recovery whose personal channel holds more than one read takes up to about ten minutes more at step 3. In ordinary use the channel is read in the first round, and nothing changes. `cordelia sync unmap <name>`, for a carried name, waits for a read of one channel, usually a second or two, and 615 seconds at most.
- **The phrase is held longer.** A recovery holds the phrase in its process while it reads, as it does today. A longer read is longer in memory, in a process that cannot be dumped (the record of 2026-10-04, section 16).
- **Bytes.** A recovery's read of a channel at its cap is 16 MiB from each relay, once. The read before a carried name is let go is the name's channel, from the start, once from each relay, and less where every version is found early.
- **Work.** A reader works out the order of 2.2 each time it keeps a record: at most 256 records and 64 adders, parsed from their rows.
- **Rows.** One key of `node_meta`. Nothing else is stored. A read before a let-go is held in memory for ten minutes.
- **What a person may meet.** A carried name that a folder was mapped to is held after the folder's unmapping where today it went: one more command lets it go. A let-go on a name that another device writes to often can be refused, and run again.

## 9. Tests

Each test is written so that taking its rule out makes it fail on an assertion. A test that runs real processes is marked so, and runs under a pseudo-terminal where a command asks.

**Property 1 (the floor of three):**

- `crates/cordelia-api/src/person.rs`, `test_a_flood_of_records_keeps_each_adders_first_three_kept_out`. Device 0 of the statement adds keys until 64 count. Device 1 of the statement then adds three keys, which the 64 keep out. Device 0 signs 300 more records, of 300 keys. Of device 1's three records, all three are kept, seen before device 0's or after them. With the oldest-first rule, the three go where they were seen first, and the test fails.
- `person.rs`, `test_an_adder_has_one_place_for_each_key`. Device 1 signs two records for one key, and one each for two more. Device 0 floods. Device 1 keeps a record for each of its three keys. Dealing records and not keys keeps two for the first key and drops the third.
- `crates/cordelia-api/src/recover.rs`, `test_a_recovery_shows_each_adders_first_three_kept_out_rows`. The same records, read by `read_generation`, with device 0 listed first and then with device 1 listed first: each of device 1's three keys has a row. With today's sort by key, a flood of keys below them cuts them from the 256 rows.
- Real processes, `crates/cordelia-node/tests/recover_e2e.rs`, `a_device_that_signs_hundreds_of_records_leaves_a_phone_its_row`. A change lists the laptop first and the desktop second. The desktop adds a phone by `cordelia add`, while few count. The test then signs, with the laptop's key, records of 62 keys, and with the key of one of those, which counts and is in no list, 300 records of 300 keys. It signs them itself and hands them to the relay, since `cordelia add` signs no record once 64 count. Every device stops. A recovery gives the laptop's records first: the 64 count without the phone, and the phone's record fails only for the 64. The flood is given last, being signed by a key in no list. The recovery shows the phone's row and asks about it. With the oldest-first rule, the phone's record is the oldest that does not count, goes first, and the phone has no row.
- `crates/cordelia-core/src/protocol.rs`: `KEPT_OUT_PER_ADDER` is 3, and the two quotients it is the lesser of are checked at compile time.

**Property 2 (the order of keeping is not the order of seeing):**

- `person.rs`, `test_the_records_kept_do_not_turn_on_the_order_they_were_seen`. Two readers are first given, in one order, the records that make 64 count. Three hundred more records of four adders are then given to them in two orders. Both keep the same 256. With the oldest-first rule they keep two sets.
- `person.rs`, `test_the_record_that_lets_a_key_add_does_not_turn_on_the_order_seen`. A key counts by a record of a device added since; two devices of the statement each sign a record for it. Two readers see the two in two orders, and then a flood. Both keep the same one in the first group, the older by its time.
- `person.rs`, `test_who_counts_does_not_turn_on_which_records_beyond_the_bound_were_kept`. One reader keeps by the order of 2.2 and one by the oldest first; a record by a device of the statement then lets a key add, and each reads its channels again. Both count the same keys.

**Property 3 (each label beside its adder):**

- `recover.rs`, `test_a_row_kept_out_by_the_64_shows_every_label_its_adders_gave`. Two adders that may add give one key two labels. The row holds both, each with its adder, in the order of the adders' rows.
- `crates/cordelia-node/src/recover_cmd.rs`, `test_what_is_said_of_a_key_added_under_two_labels`: the lines of 2.5, and an adder that may be in someone else's hands counted and not shown.

**A key that a key the 64 kept out added (2.3):**

- `recover.rs`, `test_a_key_added_by_a_key_the_64_kept_out_has_no_row`. A tablet that the 64 kept out adds a phone. The phone has no row, `no_row` does not count it, and `gone` never lists it. The tablet's row is asked about, and says that it signed a record.
- `recover_cmd.rs`, `test_a_row_kept_out_by_the_64_says_that_what_it_added_is_not_shown`: the last line of the row of 2.5, said where the key signed a record, and not where it signed none.

**Properties 5, 6 and 9 (held, and the discard):**

- `crates/cordelia-api/src/sync.rs`, `test_a_version_is_held_only_where_a_relay_read_after_the_ask_handed_it`, on the harness of several devices (`several.rs`). Each of these leaves the name held: a relay that the device is no longer set up with; a relay that refused the entry as not checking; one that holds another entry of the device's at that revision with another text; one that dropped the channel after the push; one that had no room; one read in part; the same version signed by a key that holds the secret and does not count. Each of these lets it go: the same version signed by another key that counts; an entry at a higher revision by a key that counts. Taking the read out, and counting by the notes, lets the first four go.
- `sync.rs`, `test_an_entry_that_lost_a_tie_is_held_only_where_it_was_handed`. The device's own entry loses a tie to another device's at the same revision; the read hands only the winner. The name stays held. Asking only of each slot's current version lets it go.
- `sync.rs`, `test_an_entry_that_is_no_version_moves_nothing_on`. A relay hands, above the device's entry, an entry by a key that counts in a band above the statement, and one that does not open. The name stays held.
- `sync.rs`, `test_the_read_before_a_let_go_keeps_its_own_places`: after the read, the stored place at each relay and `at_relays.sent_to` are as they were.
- `sync.rs`, `test_a_let_go_reads_on_until_each_version_is_found`. A read that hands a third of the channel at each round finds a version in the third round, and lets the name go. Taking the reading on out leaves it held.
- `sync.rs`, `test_a_let_go_lets_go_only_of_what_was_read`. A read is made, and then the store takes an entry of the name: an ordinary let-go is refused, and so is a discard. A read older than `LET_GO_READ_STANDS_SECS` on the monotonic clock is refused, and a step of the wall clock changes nothing. A number that is not the one found is refused. An ID the node does not know is refused.
- `sync.rs`, `test_the_read_before_a_let_go_does_not_hold_the_lock`: another request is answered while the read runs.
- Real processes, `crates/cordelia-node/tests/carry_e2e.rs`, `a_carried_name_is_not_let_go_while_no_relay_holds_what_it_brought`. A device carries a name through a relay whose cap leaves no room for it. `cordelia sync unmap <name>` with no terminal is refused with the lines of 4.6, naming the relay, on standard error, with status 1. The relay is given room: the device sends what waits, and the name is let go.
- Real processes, `carry_e2e.rs`, `a_relay_that_dropped_a_carried_channel_keeps_the_name_held`. The relay is sent everything, and is then started again with the channel gone from its store. Until the device has sent it again, the name is not let go.
- Real processes, `carry_e2e.rs`, `a_carried_name_that_no_relay_takes_is_let_go_on_a_typed_discard`. Under a pseudo-terminal: `yes` keeps the name, Enter keeps it, `discard` lets it go; the prompt says the number of entries, the days left, and that what was written here goes from the channel for good. With no terminal the word is never asked.

**Property 7 (a folder's unmapping keeps a carried name):**

- `sync.rs`, `test_a_name_a_carry_brought_versions_into_under_a_folder_is_held_after_the_folders_unmapping`. A folder is mapped to a name, `cordelia sync carry` brings a version in through `carrying::carry_name`, and the folder is unmapped: the name is held, and is in `person.names_carried`. The same where the look of a recovery brings it. Without the list of 4.3, the name is stopped.
- `sync.rs`, `test_only_a_version_brought_in_marks_a_name`: a look that brings nothing into a mapped name, and the carry that `cordelia sync map` makes, set no mark, and the folder's unmapping stops the name.

**Property 8 (a device that has stopped):**

- Real processes, `crates/cordelia-node/tests/carry_e2e.rs`, `a_removed_device_lets_go_of_a_carried_name_only_on_a_typed_discard`. A device carries a name through a relay with no room, and is removed from another device. `cordelia sync unmap <name>` on it asks for `discard`, and says that it could not read the relays. Today it lets go at once.
- `sync.rs`, `test_a_stopped_device_lets_go_at_once_where_its_notes_show_nothing_unsent`, and that a `discard` there with an ID older than `LET_GO_READ_STANDS_SECS`, or another number, is refused.
- `crates/cordelia-node/src/main.rs`, `test_what_unmap_says_on_a_device_that_has_stopped`: the line of 4.6 for a device that has stopped, and never "once nothing of it waits to be sent" there.

**Properties 10 and 11 (reading on):**

- `crates/cordelia-node/tests/device_entries_e2e.rs`, `a_read_of_a_left_channel_goes_on_from_a_place`, against a stand-in for a relay in the test's own process (no relay process). A read asked from a place hands what follows it, and says the place it reached. Asked under a mark that the relay no longer has, it reads from the start.
- `crates/cordelia-api/src/carrying.rs`, `test_a_read_with_proofs_says_the_place_it_reached_at_each_relay`.
- `recover_cmd.rs`, `test_a_recovery_reads_its_personal_channel_on_until_its_end`, with a read that hands a third of the channel at each round: the command reads three rounds and says "read to its end". Taking the rule out leaves it in part after one.
- `recover_cmd.rs`, `test_a_recovery_stops_reading_on_at_the_bound`, and `test_a_page_that_leaves_the_place_ends_the_reading_as_read_to_its_end`.
- `recover_cmd.rs`, `test_a_phrase_channel_not_read_to_its_end_is_said_again_before_the_yes`: the lines of 3.3 for step 1 before the yes, where another relay held a change. A relay that holds none of it is not said. Today the relay is said only while the command reads.
- `recover_cmd.rs`, `test_a_relay_not_reached_in_a_round_is_not_asked_again`, and that a relay that handed part and then holds none is read in part.
- Real processes, `recover_e2e.rs`, `a_recovery_reads_a_personal_channel_larger_than_one_read_to_its_end`. Devices that count fill the personal channel with about 6 MiB of words, and the desktop's record of a phone is among the last of them. The recovery says that it is reading on, says "read to its end", and asks about the phone. Taking the rule out, the phone has no row. It takes about four minutes.
- Real processes, `recover_e2e.rs`, `a_recovery_whose_personal_channel_stays_read_in_part_goes_on_to_the_look`. One relay, which is stopped during the second round, and is then not asked again: the reading ends within that round. The relay is started again before the yes. The command says what 3.3 says of a read in part, takes the yes, and the look ends and carries what was read. It takes about four minutes. This is the real-process test that today's rule lacks.
- `protocol.rs`: `RECOVERY_READ_ON_MAX_SECS` is 615, from the values it is made of, and `RECOVERY_READ_ON_READS` is 5.
- `recover_cmd.rs`, `test_a_relay_whose_connection_keeps_changing_costs_no_reading_beyond_the_bound`: a relay that says its connection changed from 360 seconds on is read again alone, and only within the bound; the read ends within 615 seconds on a clock where each reading takes two minutes, and another relay is never read twice from the same place.

**Property 12 (the count before a yes):**

- `crates/cordelia-storage/src/at_relays.rs`, `test_what_was_sent_to_no_relay_counts_only_this_devices_own_entries`. On a device that has stopped, entries that another key signed, taken from a relay while something else waited there, are not counted.

**Property 13 (nothing on the wire changes):**

- The tests of the wire in `crates/cordelia-network` are unchanged, and pass unchanged.

**Existing tests that change:**

- `crates/cordelia-api/src/take.rs`, `test_a_flood_of_records_drops_none_that_lets_a_key_add`: what goes beyond the bound goes by the order of 2.2.
- `recover.rs`: `test_a_recovery_shows_at_most_so_many_devices_and_takes_nothing_from_the_rest`, `test_a_recovery_counts_the_keys_whose_record_was_read_and_that_have_no_row` and `test_a_row_says_that_a_record_read_for_its_key_was_not_kept`: which rows are shown, and which records were let go.
- `recover_cmd.rs`: `test_what_is_said_of_a_key_that_only_the_bound_of_64_kept_out` (each label, and the line of what it added), `test_what_is_said_of_the_keys_whose_record_was_read_and_that_have_no_row` (the added sentence), `test_a_recovery_goes_on_with_what_it_could_read_of_the_personal_channel` (the line of a read in part).
- `recover_e2e.rs`: `a_device_that_signs_hundreds_of_records_pushes_no_device_out_of_a_recovery` (the count of keys kept as left out), `a_device_added_since_is_asked_about_where_only_the_bound_of_64_kept_it_out` and `a_device_that_the_64_kept_out_and_was_not_asked_about_is_removed_by_its_key` (the lines of a row).
- `sync.rs`: `test_a_folders_unmapping_does_not_let_go_of_a_name_that_a_carry_holds` and `test_a_name_that_a_carry_holds_with_no_folder_is_let_go`: the check reads the relays.
- `crates/cordelia-api/src/names.rs`, `test_what_was_sent_to_no_relay_is_counted_over_every_name_held`: only the device's own entries.
- `main.rs`: `test_what_unmap_says_of_a_name_that_a_carry_held`, `test_what_unmap_says_of_the_nodes_answer_to_letting_go` and `test_what_unmap_says_of_a_name_that_is_still_held_after_its_folder`: the lines of 4.6.
- `carry_e2e.rs`, `from_holds_a_name_only_once_something_is_taken_and_unmap_lets_go_of_it`: the unmapping waits for the read, and says that each version was held.

## 10. The order of building

Each slice can be reviewed and merged alone. The smallest come first.

1. **The count before a yes counts only this device's entries** (4.5), in `at_relays::sent_to_no_relay` and its callers. Property 12. It needs nothing before it.
2. **The order of keeping** (2.2), in `keep_to_the_bound`: the first group chosen by the time a record says and then its bytes, keys dealt to their adders, and `KEPT_OUT_PER_ADDER` with its check at compile time. Properties 1 and 2, for a reader. It needs nothing before it.
3. **The rows of a recovery** (2.2 to 2.5): their order, each adder's label, an adder that may be in someone else's hands among several, and the lines, with the line of a row that what it added is not shown where it signed a record (2.3). Properties 1 and 3, at a recovery. It needs slice 2.
4. **A read from a place through the carry door** (3.2): `read_left`, `read_with_proofs` and `POST /api/v1/carry/read`, taking and giving a place for each relay. Unit tests only. It needs nothing before it.
5. **A recovery reads the personal channel on** (3.2, 3.3), with `RECOVERY_READ_ON_MAX_SECS`, a relay not reached in a round not asked again, and the line of step 1 before the yes. Properties 10 and 11. It needs slice 4.
6. **A pull of a device's own channel with places of its own** (4.2, item 2): through `take_page`, without `keep_place` and without moving what was sent, kept in memory under an ID, within the pass's budget at each relay, and outside the lock. Unit tests, among them that it does not hold the lock and leaves the stored places as they were. It needs nothing before it.
7. **The read before a carried name is let go** (4.2: the entries this device signed, and held as a slot is read), every let-go bound to its read, **the list of 4.3** (set where a version is brought in), and the line after a folder's unmapping on a device that sends. Properties 6, 7 and 9, for an ordinary let-go. It needs slices 1 and 6.
8. **The `discard`** (section 5), with `LET_GO_READ_STANDS_SECS` on the monotonic clock; a device that has stopped, with the count from its notes under an ID (4.4); the prompts; and the line after a folder's unmapping on a device that has stopped (4.6). Properties 5, 8 and 9, with the `carry_e2e` tests. It needs slice 7. **Slices 7 and 8 ship in one release:** slice 7 alone refuses more than today, and holds more names after their folder goes, with no way out.

## 11. What is put off, and why

- **Reading on the personal channels of the generations before,** which are read for names. There can be eight of them, and ten minutes each is too long for a second source. A name that is missing there is said before the yes, and comes in by `cordelia sync carry <name>`.
- **Reading on in the look of a recovery, and in `cordelia sync carry`.** Each name is read for two minutes. A name read in part is said, and `cordelia sync carry <name>` reads it again. A name's channel is read from the start each time, so a name of more than about 4 MiB stays in part; that is a name near its cap, and is put off with a carry from a place.
- **A share of the personal channel at a relay for each signer.** It would keep a place at the relay for an honest record after a device that counts has filled the channel (section 7). It is a change to every relay, and this record changes none.
- **A mark of which entry a carry made.** It would let the prompt of 5.3 count apart the versions written here. It is a step of the schema, for a count the person can do without: the prompt says that any written here go for good.
- **The notes of what was sent** (4.2): what is offered again, what `cordelia devices` says is still to send, and when a device writes that it has sent what it carried. They keep counting what a relay refused as not checking, and what it holds in another form, as sent. Nothing that lets go of a version rests on them now but on a device that has stopped, where the word is asked. A device that writes that it has sent what it carried when a relay holds another form is worth a review of its own.
- **A label chosen by an adder elsewhere.** The prompt of the next statement and `cordelia devices` show a key added since by the label of the record that counts. That record is the first one kept, and its adder counted; the case of 2.4 is a key that the 64 kept out, which only a recovery asks about.
- **A floor of more than three.** It needs larger bounds of 256, each a cost to every reader (2.6).

## 12. Where to look for faults

Where I am least sure, said plainly.

- **The order of 2.2 against `judge_again`.** A record that the order drops can be one that would have come to count after a later record. The record of 2026-10-04 relies on reading every channel again when a key comes to count or to add. I have read that `take_page` forgets every place when `came_to_count` or `came_to_add` is not 0. I have not checked that every way a record arrives (a hand-over, a recovery's reader, a statement's prompt) does the same.
- **The floor counts adders that may add.** A key can come to add after its records were dealt. Then the deal changes, and what was dropped is gone until it is given again. I believe the reading again closes it; a test should show a key whose adder comes to add after a flood.
- **The floor holds only among what the relays hold.** A device that counts can fill the personal channel at a relay, and then no later record reaches a reader there (section 7). The person sees that the relay is full, and removes the device. Until then, a device added since may be unseen by every reader that reads at that relay.
- **A key that a key the 64 kept out added (2.3)** has no row and is counted nowhere. A person whose real tablet was kept out learns only from the tablet's row that what it added is not shown. I think that is right: no device vouched for it.
- **A read from a place (3.2).** A place means something only with its mark, and a sweep frees places that are not given again (the record of 2026-10-04, section 16). I rely on that for a read that resumes. A relay that drops the channel between two rounds and takes it again under the same mark would hand the start again as what follows; I believe a new holding has a new mark, and did not prove it.
- **The read before a let-go (4.2) is under leave, with places of its own, and runs outside the lock.** It shares the pass's budget at each relay, so a large read slows the pass there while it lasts. It stores what it is handed and marks none of it sent: the next push then offers it to the relay, which answers that it holds it. A name that another device writes to often can move while it is read, and the let-go is then refused and run again.
- **A relay that holds the version for a moment.** "Held" is what a relay handed in that read. A relay that drops it afterwards loses it, and the device has let go. Nothing in this record defends against that, and nothing can short of keeping the version.
- **What was written here (5.2).** The prompt cannot say how many of the versions held by no relay were written on this device since the carry. It says that any such go for good. A person may still read "still at the relays" as covering all of them.
- **The ID of a read for a discard (5.2).** It is in memory, on the monotonic clock. A node that restarts between the read and the word refuses the word, says why, and the person runs the command again.
- **Held as a slot is read (4.2, item 5).** The check reads each slot with what one relay handed, under the statement applied and with who counts. A relay that hands an entry of another device at a higher revision, which this device's own store would not take for a reason the read does not see, would count as moving the slot on. I believe `version::read` with who counts sees every such reason, and did not prove it.
- **The bound of 615 seconds.** It assumes that a relay hands what it may in a minute. A relay that hands less leaves a channel near its cap in part, and the command goes on, as today.

## 13. Questions for the person

1. **Is three enough?** `KEPT_OUT_PER_ADDER` follows from the bounds. Raising it means raising `MAX_NOT_COUNTED_RECORDS` and `RECOVERY_MAX_DEVICES_SHOWN`. **Recommendation:** keep three, and the bounds as they are. It counts keys, not records, and it holds only among the records the relays hold: it does nothing against a personal channel at its cap (section 7).
2. **Should a key that a key the 64 kept out added be shown at a recovery (2.3)?** **Recommendation:** no, as this record has it: it has no row and is counted nowhere, an adder that never counted vouches for nothing, and asking would let any chain of records spend the phrase's removals. The row of the key that added it says that what it added is not shown, where it signed a record.
3. **Should the `discard` need the phrase (5.4)?** **Recommendation:** no. Nothing comes in by it. The check asks about every entry this device signed, one that lost a tie included. What a carry brought is still in the channels it was carried from; the prompt says plainly that what was written here goes from the channel for good, and that a folder that was mapped keeps its files.
4. **Should the check before a let-go need every relay, or one (4.2, item 6)?** **Recommendation:** one, where what was handed is a version as a slot is read, signed by a key that counts, and the read reads on to the channel's end.
5. **Should slices 7 and 8 ship in one release (section 10)?** **Recommendation:** yes. Slice 7 alone refuses more than today, and its list of 4.3 holds more names after their folder goes, with no way out but beginning again. The line for a device that has stopped goes with them.

**Where the code differs from the brief this record was written from.** The code is right about today.

- The brief says a reader keeps 256 records, "the oldest it saw going first". The code keeps besides, and never drops, one record for each key that counts by a record and that a device of the statement also signed (`Counting::lets_add`). So the floor of 2.2 is worked out with up to 63 places taken.
- The brief says a recovery reads records "in the statement's order, signers that are not listed last". The code sorts by the place in the statement, then by key, slot and revision. Under the oldest-first rule, the records that go first at a recovery are those of the device listed first.
- The brief says a recovery shows the record "whose adder has the lowest key among adders that may add". The code shows the record of the lowest-key adder among those whose record fails only for the 64, and the question names another adder where it is asked under one (`for_room_says`), without that adder's label.
- The brief says a device takes 2 MiB a minute, and a channel at its cap takes about 8 minutes. Both are counted with `ENTRY_OVERHEAD_BYTES` for each entry, and a relay keeps `SHOW_ANSWER_ROOM_BYTES` of each minute for the answer to a show: about 8¼ minutes.
- The brief says the read of the personal channel is one read of 120 seconds from the start. Where a connection changed, `read_again_where_changed` reads again from the start, up to `CARRY_PROOFS_MADE_AGAIN` times.
- The brief says the count can overstate on a device that has stopped. On a device that sends, the overstatement lasts only until the next push. And the count that overstates there is the one said before the yes of `init --new-key`, `cordelia phrase` and `cordelia accept` (`waits_in_every_name`): the check before a let-go counts none on such a device (`waits_to_be_sent`).
- The record of 2026-10-04 has no list of later records, so none was added to it.
