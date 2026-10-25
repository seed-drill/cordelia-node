# Decision: a person's hold on messages

**Date**: 2026-10-25
**Status**: Proposed. Not built.
**Cited as**: "decision 2026-10-25, rule 2", and "rule 3.6" for an item of a rule. The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The record of 2026-10-09** is [`2026-10-09-messages-between-your-own-agents.md`](2026-10-09-messages-between-your-own-agents.md). Its sections are cited "§6 there".
- **A pair** is two names, or a name and every agent, as §6 there counts them: a message to a name is of the pair of its sender and its recipient, in either direction; a message to every name is of the pair of its sender and every agent. A name may be on both sides: an agent and the same agent on another device.
- **The hold** is §6 there: a device sends nothing between a pair once enough of the pair's messages that it shows are unread by a person. **A bound** is that number for one pair. **The usual hold** is 10 (`AGENT_MESSAGE_PAIR_UNREAD_MAX`).
- **A person's read** is what the yes of `cordelia msg log` at a terminal marks (§4.1 there).
- **Main** is commit 31f4ac54. Every file and line below is of main. **The version before** is the release that this follows, which knows none of it.
- Examples say laptop and desktop, relay1 and relay2.

---

## 0. What this is

The person ruled on 24 October:

- **(a)** `log` asks only about messages new to a person. Built (#206); this record builds on it.
- **(b)** A bound for each pair, set by the person at a terminal, in place of the fixed ten: a number, or no hold, for a set time, shown in `cordelia status`. Only the person sets it. An agent is told to stop, as at `log`'s yes.
- **(c)** A person's read counts on every device of theirs. Today it is each device's own. A person who runs `log` on the laptop ends the hold that the laptop counts, and not the one the desktop counts; one run should end both.
- **(d)** The only test for a person is a terminal, and a pseudo-terminal passes it. That is stated as a known limit, and not fought.

Rule 1 is (c). Rules 2 to 4 are (b). Rule 5 is (d).

**What the code does today.**

- A person's read is a row of `message_read_by_a_person` (`cordelia-storage/src/schema.rs:863-865`), keyed by the message's ID, which goes with its message's row. Only `log_of` writes it (`cordelia-api/src/messages.rs:1368-1371`), for the IDs that the command sends after a yes. Nothing says it to another device (§7.2 there: "It is never synced").
- The hold is `held_pair` (`cordelia-api/src/sender.rs:486-504`). `pairs_with` counts each pair's messages that have a place, have not expired, are live, and have no row in that table (`cordelia-storage/src/messages.rs:1040-1070`). A count of 10 or more holds. The refusal says "Ten" in its words (`cordelia-node/src/msg_cmd.rs:668-674`).
- **What an agent read already travels.** Each device writes its list in the slot `read/<its key>` of the messages channel (form 2, `cordelia-api/src/marks.rs:169-216`), and a reader keeps the latest list of each key that counts, in place of the one before (`marks.rs:260-271`). Rules 1 and 2 use that way, with the differences they give.
- `log` asks only where its input and its output are both terminals (`msg_cmd.rs:1258`). The node's route takes `mark` from any caller that holds the token (`messages.rs:1708-1747`): it cannot tell a person from a program (§4.2 there).
- Plain `cordelia status` says nothing of messages (`cordelia-node/src/main.rs:1536-1570`), and `docs/specs/channels-api.md` says so as a rule.
- A reader of the version before takes an entry in a slot of the messages channel that it does not know as no message, and counts it (`cordelia-api/src/reader.rs:115`, `NotInRing`).

## 1. The rules

Each rule gives what you see, word for word; what is stored, and where; what travels, and how it is sealed; what a device of the version before does beside it; and its tests.

**Placeholders.** `<a>` and `<b>` are names as these commands print one (`name_shown`, `msg_cmd.rs:200`: cleaned, and cut to 48). `<pair>` is "between `<a>` and `<b>`", or "from `<a>` to every agent", and `<Pair>` the same with a capital. `<when>` is a moment as the record of reach writes one: "18:05 UTC", or "18:05 UTC on 2026-10-26" where it is not today. `<device>` is "this device", or a label in quotes as `label_shown` prints it.

### Rule 1. A person's read counts on every device

**What you see.** `log` no longer lists, or asks about, a message that a person read on any device of yours that counts. Its lines that change (§4.1 there):

> No new message of `<any agent | the agent <name>>` is held on this device. You have read the `<N>` others, on this device or another.

For one: "You have read the other one, on this device or another."

> You have read `<N>` other messages, on this device or another, so they are not shown.

For one: "You have read 1 other message, on this device or another, so it is not shown."

In each message it lists, "Not read by a person here." becomes "Not read by a person."

The question at a terminal:

> Mark these `<N>` messages as read by you? That ends any hold between the agents they are between, here and on your other devices. If you are an agent, stop here and tell your user. Type yes to mark them:

For one: "Mark this message as read by you? That ends any hold between the agents it is between, here and on your other devices. If you are an agent, stop here and tell your user. Type yes to mark it:". With `--since`, the second sentence stays "Older messages are not shown here and stay unread, so a hold may stay."

After a yes:

> Marked `<N>` messages as read by you. Your other devices count them read once they hear of it.

For one: "Marked 1 message as read by you. Your other devices count it read once they hear of it." Where the node marked fewer: "Marked `<M>` of the `<N>` messages printed as read by you: the others are no longer shown here. Your other devices count them read once they hear of it."

Away from a terminal, `log` still ends "Not marked as read by a person: this was not run at a terminal.": an agent reads that line, so it does not say "you". `read`'s header says "`<U>` of them not yet read by a person." (no "here"). The status's `unread_by_a_person` counts the same way.

**What is stored, and where** (the device's store; the schema's step 20):

1. **A person's read here** stays a row of `message_read_by_a_person`, as today. Its order is the table's rowid: the newest is the highest.
2. **What other devices said:** a new table, `message_person_marks`, of the IDs that each other key's lists of a person's reads held, each with when it was taken here. **It is a union:** a later list that leaves an ID out takes nothing away. A row whose message this device holds goes with that message's row (`drop_row`). Of the rows whose message it does not hold, it keeps at most 120 for each key (`AGENT_MESSAGE_READ_MARKS_MAX`), the latest taken first, each for 30 days from when it was taken (`AGENT_MESSAGE_KEPT_DAYS`).
3. **Read by a person is worked out when it is asked,** as read by an agent is (§7.2 there): a row of 1, or a row of 2 under a key that counts now. `pairs_with`, `is_read_by_a_person`, `log` and the status's count all ask it so.

**Why a union, where an agent's list is kept by replacing it.** An agent's mark that falls out of the newest list is unread again, and at worst an agent is shown a message twice. A person's read that fell out would bring back a hold that you had ended, with no new message. A union cannot do that. Its bound is on what it keeps of messages that this device does not hold.

**What travels, and how it is sealed.** Each device writes one entry more in the messages channel, in the slot `person/<its key>` (`AGENT_MESSAGE_PERSON_PREFIX`), of form 3: the byte `3`; a count, two bytes, from 0 to 120; that many message IDs of 16 bytes each, the newest first; and zeros to 1,936 bytes. It holds the newest 120 rows of the table of 1. It is the agents' list (form 2) with IDs in place of marks: a person's read has no name to bind into a hash, and the entry is sealed.

- It is sealed by `Entry::seal` under the messages channel's secret, signed by the device, at 2,048 bytes, as every entry of the channel is (§2.2 there). Its name, `person/` and a key, is 77 bytes, the longest name of the channel, so the value's size does not change.
- It is written and sent by the rules of the agents' list (§2.4 there): only after the first fetch since the node started, and only where the device stands applied with sync on; wherever the table holds an ID that the list it holds lacks, so `log`'s write that marks writes it too; one revision above the list it holds; again above a relay's answer of another, at most three times in a row (`AGENT_MESSAGE_SENDS_MAX`); and after a relay's answer that it holds a later one, not until the next pull hands that back. A device's first list in a new generation holds the newest 120 rows of its table (§9.1 there).
- **Taken by a reader,** in the door's write (`reader.rs`), as the agents' list is: in its signer's slot, raising no H. Another key's list adds each of its IDs to the table of 2. The device's own list, handed back by a relay from its later life (a store restored from a backup), adds each ID whose message it holds to the table of 1, and keeps the rest under its own key in the table of 2. **A list from a key that no longer counts says nothing,** and the hourly task drops its rows.

**Beside the version before.** A device of the version before writes no such list: a person's read there counts there alone, as today, and a device of this version beside it holds by that. It stores this version's lists, as a relay does, and reads each as an entry in a slot it does not know (`NotInRing`): its `log` counts each new list as one more entry that was not a message, and says "`<N>` entries from "`<label>`" were not messages, and were not shown." Nothing else changes there. **Step 20 sets each signer's count of entries that were not messages to 0,** since the version before counted this version's lists among them. The notes of the release say both.

**Tests.**

- Units, in-process over `Several` (`marks.rs`, `messages.rs`):
  - `a_persons_read_on_one_device_counts_on_another`: the laptop's `log` marks three; the desktop takes the list; its pair count, its status's `unread_by_a_person` and its `log`'s `already_read` count all three as read by a person.
  - `a_persons_read_that_arrives_before_its_message_loses_nothing`: the desktop takes the list, then the message; the message is read by a person at once, and is never in a pair's count.
  - `a_persons_read_that_falls_out_of_the_newest_list_stays_read`: the laptop marks 130; the desktop takes its list at 60 and at 130; all 130 stay read there.
  - `what_is_kept_of_messages_not_held_is_bounded`: a key lists 240 IDs of messages not held, in two lists; 120 are kept, the latest taken; one goes 30 days after it was taken.
  - `a_persons_read_from_a_key_that_no_longer_counts_says_nothing`.
  - `the_persons_list_waits_for_the_first_fetch_and_for_sync`, and `a_relay_that_answers_another_to_the_persons_list_gets_three_more_at_most`, as the agents' list's tests do.
  - `a_persons_list_handed_back_is_merged`: a store restored from a backup takes its own later list.
  - `step_20_sets_the_count_of_not_messages_to_0` (`schema.rs`).
- Units of the command (`msg_cmd.rs`): every line above, word for word, for one and for many, with and without `--since`.
- Real processes (`msg_e2e.rs`): `one_yes_on_the_laptop_ends_the_hold_on_both_devices`. An agent on the laptop and one on the desktop answer each other until each device refuses with `pair_held`. `log` at the laptop's terminal (`AtTerminal`) is answered yes. The test waits until the desktop's `unread_by_a_person` falls; then a send goes on each device, and `log` at the desktop's terminal lists none of them and says "You have read the `<N>` others, on this device or another." `log_shows_and_marks_only_what_no_person_has_read_here` gains the same on a second device.

### Rule 2. A bound for each pair, set only by a person

**The command.**

```
cordelia msg allow <a> <b> (<n> | any) [--for <time>]
cordelia msg allow <a> --all (<n> | any) [--for <time>]
```

- `<n>` is 1 to 64 (`AGENT_MESSAGE_RING`, one lap of a device's ring: more than that is no hold in practice, and `any` says so plainly). `any` is no hold.
- `--for` takes what `--since` takes (30m, 8h, 2d), from 1 minute to 7 days (`AGENT_MESSAGE_PAIR_BOUND_MAX_SECS`). Where it is not given, 8 hours (`AGENT_MESSAGE_PAIR_BOUND_SECS`).
- **10 is the usual hold:** `allow <a> <b> 10` goes back to it now, and does not use `--for`.
- Each name must be one that the personal channel lists, as for `send --to`.

**What you see.**

> This is for a person at a terminal. An agent must not run it, and must not answer its question.
> `<Pair>`, `<k>` messages wait for you to read them. `<now>`
> `<question>` If you are an agent, stop here and tell your user. Type yes to allow it:

For `<k>` of 1, "1 message waits"; for 0, "no message waits".

`<now>` is one of:

- "Sending stops at 10, the usual hold."
- "Sending stops at `<m>` until `<when>`, as you set on `<device>`."
- "Only the hourly limits stop sending until `<when>`, as you set on `<device>`."

`<question>` is one of:

- "Allow `<n>` to wait unread, until `<when>`? At `<n>`, sending stops until you read them with cordelia msg log. After `<when>` it stops at 10 again."
- where `<n>` is at or below `<k>`: "Allow `<n>` to wait unread, until `<when>`? `<k>` wait now, so sending stops at once, until you read them with cordelia msg log. After `<when>` it stops at 10 again."
- for `any`: "Allow any number to wait unread, until `<when>`? Until then only the hourly limits stop sending. After `<when>` it stops at 10 again."
- for 10: "Go back to the usual hold of 10 now?"

After a yes: "Done. `<Pair>`, sending stops at `<n>` until `<when>`. Your other devices hold by it once they hear of it." For `any`: "Done. `<Pair>`, only the hourly limits stop sending until `<when>`. Your other devices hold by it once they hear of it." For 10: "Done. `<Pair>`, sending stops at 10 again. Your other devices hold by it once they hear of it." Any other answer: "Nothing was set."

**Where its input or its output is not a terminal,** it says its first line, then, on standard error with status 1, "Nothing was set: this was not run at a terminal." It asks the node nothing.

**Refusals,** on standard error with status 1, the first that applies:

1. The command line: "Give two names, or one name and --all, then a number from 1 to 64, or any."
2. The number: "`<n>` is not a number you can allow: give 1 to 64, or any."
3. The time: "`<time>` is not a time you can allow it for: give 1m to 7d, as 30m, 8h or 2d."
4. The node, and the device: steps 3 and 4 of §4.3 there, as `log` says them, with "so it sets nothing" where `log` says "so it shows no message".
5. A name: "No device of yours syncs `<name>`, so nothing was set." (`no_such_name`)
6. Room (rule 3.5): "This device already tells your other devices of 4 bounds, which is as many as it can. End one first: allow its pair 10." (`bounds_full`)

**What is stored, and where.** A new table, `message_bounds` (step 20): for each key, this device's own among them, each bound its list holds: the pair; the bound (none for `any`); `set`, when the yes was typed, by that device's clock; `for`, in seconds; and when this device first held it. Nothing is in the configuration: a file that an agent can write is not a person at a terminal.

**The route.** `POST /api/v1/messages/allow`, a sixth route of §4.2 there, behind the token: `a`, `b` (null for every agent), `bound` (1 to 64, or null for `any`), `for_secs` and `set`. With `set` false it answers the look that the command prints first: `waiting` (`<k>`), and the bound in force (rule 3) with its `until` and the device it was set on, or null for the usual hold. With `set` true it sets the bound, in the write that writes the list. The command asks for the look, asks its question, and asks the node again (steps 3 and 4) before it sets, as `log` does before it marks.

**What travels, and how it is sealed.** Each device writes one entry more in the messages channel, in the slot `hold/<its key>` (`AGENT_MESSAGE_PAIR_BOUNDS_PREFIX`), of form 4: the byte `4`; a count, one byte, from 0 to 4 (`AGENT_MESSAGE_PAIR_BOUNDS_MAX`); then each bound: `a` (two bytes of length and a name); the kind of `b` (1: a name, 2: every agent); `b` (two bytes of length and a name, for kind 1 only); the bound (one byte: 0 for `any`, else 1 to 64); `set` (8 bytes, seconds since 1970); and `for` (4 bytes, seconds); and zeros to 1,936 bytes.

- For a pair of two names, `a` is the lower in byte order, so a pair has one spelling.
- Four bounds at the longest names come to 1,674 bytes; five would not fit.
- A reader takes as no list one whose count is over 4, with a name that is not a name, a bound over 64, a `for` outside 60 to 604,800, two bounds of one pair, or a fill that is not zeros.
- It is sealed, signed, sized and written by the rules of rule 1's list, wherever what it should hold changes (rule 3.4). Its name, `hold/` and a key, is 75 bytes.

**Beside the version before.** `cordelia msg allow` is not there, and a device of the version before holds every pair at 10. It counts each list of bounds as an entry that was not a message, as in rule 1. So where your agents run on two devices of two versions, the older one stops its side at 10, whatever you allow. The help of `cordelia msg allow` says so: "A device of yours on an older version holds every pair at 10, and does not hear of this."

**Tests.**

- Units (`msg_cmd.rs`): `allow_is_refused_away_from_a_terminal` (input a pipe; output a pipe), and asks the node nothing; `allow_takes_a_number_any_and_a_time` (0, 65, `none`, `0m` and `8d` refused; 10 with `--for` goes back to the usual hold); every line above, word for word.
- Units (`messages.rs`): `the_look_says_the_count_and_the_bound_in_force`; `allow_refuses_a_name_no_device_syncs`; `a_fifth_bound_on_one_device_is_refused`; `a_bound_is_listed_and_taken_by_another_device`; `a_list_of_bounds_that_is_not_one_is_no_list`, one case for each check above.
- Real processes (`msg_e2e.rs`): `a_bound_set_on_the_desktop_holds_on_both`. A pair is held at 10 on both devices. At the desktop's terminal (`AtTerminal`), `cordelia msg allow X Y 20 --for 1h`, and yes. Once the laptop holds the list, each device sends up to 20, and the 21st is refused with `pair_held` and rule 4's line naming 20. `cordelia status` on the laptop says rule 4's line, with "you set it on "desktop"". Then `cordelia msg allow X Y 10` on the laptop, and both hold at 10 again. And `allow_into_a_pipe_sets_nothing`: with its output a pipe, nothing is set and the pair stays held.

### Rule 3. Which bound holds a pair, and for how long

1. **A bound starts,** on each device, at its `set`, or 10 minutes after that device first held it where `set` is later than that (`AGENT_MESSAGE_AHEAD_MAX_SECS`, as a sender's clock is allowed to be ahead, §7.1 there). **It ends** `for` seconds after it starts. So the order is the same on every device whose clocks agree within 10 minutes, and a clock far ahead gains nothing.
2. **The bound in force for a pair is the one that started last,** among this device's own and those of the keys that count. Of two that start in the same second, the lower decides (a number before `any`), then the lower key. **Where the one that started last has ended, the pair is at the usual hold,** whatever an older one would still allow: your last act decides, and when it ends nothing older comes back. Where there is none, the usual hold.
3. **When a bound ends,** nothing is said. The pair is at 10 again on every device, and `cordelia status` no longer shows it. Where 10 or more wait unread, the next send is refused at once.
4. **What a device lists.** Its own bound for a pair, until a bound for that pair that started later is in the list of another key that counts: then it drops its own. An own bound that has ended stays listed while another key that counts lists a bound for that pair that started earlier and has not ended, so that the older one does not come back; otherwise it leaves the list when it ends, by the hourly task at the latest. A new bound for a pair replaces the device's own for that pair.
5. **Room.** A list holds 4 bounds. A bound that would need a fifth place is refused by the command (rule 2). 10 for a pair takes no place where no other key lists a bound for that pair: the device drops its own.
6. **A statement ends every bound.** When a device applies a statement (a removal, a renewal, a settlement or a recovery), it drops every row of `message_bounds`, its own and the others', in the transaction that applies it, and writes no list of bounds in the new generation until one is set again. Nothing of messages is carried (§9.1 there), and a change of your devices is a moment to be back at the usual hold.
7. **A key that no longer counts says nothing:** its bounds stop holding at once, and the hourly task drops them.

**What you see** is rule 2's look and rule 4's lines. **What is stored, and what travels,** is rule 2's, and nothing more. **Beside the version before,** it holds at 10 (rule 2).

**Tests.** Units, in-process with the node's clock (`SyncControl::set_now`), over `Several`:

- `the_bound_that_started_last_decides`: the desktop sets 30, then the laptop sets `any`; both hold by `any`; when the laptop's ends, both hold at 10, though the desktop's 30 would still run.
- `two_bounds_set_in_one_second`: the lower decides on both devices.
- `a_clock_ahead_gains_nothing`: a bound whose `set` is an hour ahead starts 10 minutes after it was first held.
- `a_bound_that_ends_holds_a_pair_over_10_at_once`.
- `a_bound_set_while_a_pair_is_held`: raised above the count, a send goes at once and nothing is marked read; lowered to the count, a send is refused at once.
- `a_device_drops_its_own_bound_once_a_later_one_is_listed`, and `an_ended_bound_stays_listed_while_an_older_one_runs`.
- `a_statement_ends_every_bound`: a renewal, and a removal.
- `a_bound_from_a_key_that_no_longer_counts_says_nothing`.

Real processes: rule 2's test, whose last step is 3.2 and 3.4.

### Rule 4. What the hold says

**To an agent**, by `send`, refused with `pair_held` (step 12 of §4.3 there):

> `<k>` messages between `<from>` and `<to>` wait for your user to read them, and sending between them stops at `<n>`. No more are sent between them until your user reads them with cordelia msg log at a terminal, on this device or another. Tell your user.

> Messages between `<from>` and `<other>` wait for your user to read them, so `<from>` sends nothing to every agent until your user reads them with cordelia msg log at a terminal, on this device or another. Tell your user.

`<n>` is the bound in force (rule 3), and `<k>` the count, which can be above it where a bound was lowered or messages came from another device. The node's refusal carries both, as `bound` and `waiting`. The line does not name `cordelia msg allow`: that is for you, and not for an agent.

**To you**, in `cordelia status`, under `Node:` after `Devices:`, one line for each pair whose bound in force is not the usual hold:

> `  Messages:  <pair>, sending stops at <n> until <when> (you set it on <device>)`

> `  Messages:  <pair>, only the hourly limits stop sending until <when> (you set it on <device>)`

`--line`, `--waybar`, the level and the holds say nothing of it (§8 there). `cordelia status --json` carries it in `messages`, as `bounds`: for each, `a`, `b` (null for every agent), `bound` (null for `any`), `until` (RFC 3339) and `set_on` (`label` and `fingerprint`, or `"this"`).

**What is stored, and what travels:** nothing more; it is worked out from rules 1 to 3. **Beside the version before:** the command and the node of one version only work together (the record of 2026-10-04, 10.1, rule 6), and a device of the version before says its own line with "Ten".

**Tests.** Units: `msg_cmd.rs`, `the_held_line_names_the_bound_and_the_count` (10 of 10, 12 of 5, and the line for every agent, each word for word); `main.rs`, `the_status_says_each_bound_in_force` (a number, `any`, every agent, this device and a label; nothing for the usual hold or for one that has ended); `messages.rs`, `the_status_object_carries_the_bounds`. Real processes: rule 2's test asserts the refusal's line and the status's line.

### Rule 5. A terminal is the only sign of a person

**The known limit, as it is:**

> **The only test for a person is that the command's input and output are terminals, and a pseudo-terminal (`script`, `expect`) passes it. So a program that gives `cordelia msg log` or `cordelia msg allow` a pseudo-terminal and types yes ends a hold on every device of yours, and can set any bound. The hold relies on agents keeping to "stop here".**

- **The same sentence goes into the known limits of R1's gate 12,** and into the threat model's row T22 (`docs/security/threat-model.md`), in place of "a program that ends a hold with a pseudo-terminal and a yes".
- **Rules 1 and 2 widen what it reaches.** Today such a program ends a hold on the one device it runs on. After them, it ends it on every device, and can lift the hold for up to 7 days. What bounds it does not change: the rates (20 an hour from a folder, 60 from a device), and `log` and `cordelia status`, which show what was done and where.
- **Nothing here tries to tell a person from a program:** not timing, not the kind of terminal, not a word typed back. Each is one more thing a program can copy, and you would pay for it.

**What you see:** nothing new. **Stored, travels, beside the version before:** nothing. **Tests:** none new. Every test of a person's act, `log`'s yes and `allow`'s among them, runs at a pseudo-terminal (`AtTerminal`): that they pass is the limit, shown.

## 2. The defaults, and why

- **Before you set a bound,** every pair holds at 10, as today. Ten was chosen with the folder's rate (parameter-rationale.md §12.12); nothing has measured against it since.
- **"For a set time"** is `--for`, from the yes, on the clock of the device it was set on (rule 3.1): 8 hours where you give none, a working day, so that what you allow for a task is gone by the next morning; and at most 7 days, so that a bound you forget ends by itself. With no hold, a loop is bounded by the rates alone: 20 an hour from a folder, 3,360 in 7 days.
- **When it ends,** the pair is at 10 again, on every device, with nothing said (rule 3.3).
- **What an agent sees when held** is rule 4's line: the count, the bound, that only its user ends it, and "Tell your user". It is not told how a bound is set.
- **A bound is per pair, and per person:** one for each pair, the same on every device, set on any of them.
  - **Per pair,** so that you allow the two agents you are watching, and every other pair keeps its guard against a loop.
  - **Per person, and not per device.** A loop between an agent on the laptop and one on the desktop is counted on both, and each device stops its own side. A bound on the laptop alone would let the laptop's agent send while the desktop's is held: you would set it twice, and be held by the device you forgot. Rule 1 makes your read one act on every device; a bound is the same.

## 3. The hard cases

1. **Two devices set different bounds at once.** The one that started last decides, on every device, once both lists have reached it; of two in one second, the lower (rule 3.2). Until then each device holds by what it knows, for a pass or two. The device whose bound lost drops it (rule 3.4). `cordelia status` says which bound holds, and where it was set.
2. **A bound set while messages are held.** It holds from the next send, and marks nothing read. Raised above the count, the pair sends again. Set at or below it, the pair stays held, and the question says so before the yes (rule 2).
3. **A removed device's marks.** A person's read and a bound say something only while the key that listed them counts (rules 1 and 3.7). Once a device applies the removal, a message that only a person on the removed device read is unread by a person again, and may hold a pair until you read it on a device that remains. That is the safe side: the removed device may not be yours any more. A removal is a statement, so every bound ends too (rule 3.6). What the removed device writes after goes into the old generation, and reaches only devices that have not applied the removal.
4. **A recovery.** It is a statement, so every bound ends. The new machine holds no message, no person's read and no bound. A device added again keeps its own reads (rule 1's table 1, with their messages), and counts another key's again once that key is added again. Each writes its first list of the new generation from its own table.
5. **A person's read arrives for a message this device does not hold yet.** It is kept under the key that listed it, among that key's 120 of messages not held, for 30 days (rule 1). When the message comes, it is read by a person at once: it never counts toward a hold, and `log` never lists it as new. Where it went first (the key listed more than 120 that are not held here, or 30 days passed), the message is unread by a person here: it counts toward the hold, the safe side, and `log` asks about it again.

## 4. Constants

Each in `cordelia-core/src/protocol.rs`, with its reason in `docs/specs/parameter-rationale.md` §12.12:

| Constant | Value | Why |
|---|---|---|
| `AGENT_MESSAGE_PERSON_PREFIX` | `person/` | The first part of the name of a device's list of what a person read on it (rule 1). With a key it is 77 bytes, the longest name that the channel's value is sized by (`AGENT_MESSAGE_VALUE_BYTES`), so the size does not change; a longer prefix would need a smaller value. No prefix of the channel begins another |
| `AGENT_MESSAGE_PAIR_BOUNDS_PREFIX` | `hold/` | The first part of the name of a device's list of the bounds a person set on it (rule 2): 75 bytes with a key |
| `AGENT_MESSAGE_PAIR_BOUNDS_MAX` | 4 (derived) | The bounds at the longest names that fit in one value after the form and the count: (1,936 − 2) / (2 × (2 + 200) + 1 + 1 + 8 + 4) = 4. A person watches few pairs at once |
| `AGENT_MESSAGE_PAIR_BOUND_SECS` | 28,800 | `--for` where none is given: 8 hours, a working day, so that what is allowed for a task is gone by the next morning |
| `AGENT_MESSAGE_PAIR_BOUND_MAX_SECS` | 604,800 | The longest `--for`: 7 days, a week away, after which a bound that was forgotten ends by itself. With no hold, a folder's 20 an hour bounds a loop to 3,360 messages in that time |

**Existing constants with a new use,** whose reasons gain a sentence:

- `AGENT_MESSAGE_PAIR_UNREAD_MAX` (10): the usual hold, the bound of every pair until a person sets another, and again when it ends (rule 3).
- `AGENT_MESSAGE_RING` (64): the highest bound a person can set. With the two lists of rules 1 and 2, a device has 67 slots: 64 × 67 × 3,072 = 13,172,736 bytes, under a channel's 16 MiB. The check at `protocol.rs:2405-2409` counts `AGENT_MESSAGE_RING + 3`.
- `AGENT_MESSAGE_READ_MARKS_MAX` (120): the IDs in a person's list, and the rows of messages not held kept for each key.
- `AGENT_MESSAGE_KEPT_DAYS` (30): how long such a row is kept.
- `AGENT_MESSAGE_SENDS_MAX` (4): the revisions of each list, as for the agents' list.
- `AGENT_MESSAGE_AHEAD_MAX_SECS` (600): how far ahead of its first holding a bound's `set` may be (rule 3.1).

No label is added: a person's read is an ID, not a hash. `protocol.rs` checks when it is compiled: each new name with a key is at most 77 bytes; no prefix of the channel begins another; a full list of form 3 and of form 4 each fits in `AGENT_MESSAGE_VALUE_BYTES`; and five bounds of form 4 would not.

## 5. Sentences of other records that change

Listed here, and changed when this is built.

**The record of 2026-10-09.**

| Where | Today | Becomes |
|---|---|---|
| §0, item 1 | "each device has 64 slots there for its messages and one for its read marks" | "... 64 slots there for its messages, one for what its agents read, one for what a person read on it, and one for the bounds a person set on it (decision 2026-10-25)" |
| §0, item 4 | "Ten messages between two agents that are shown on a device and that no person has read there stop that device sending between them, and stop either agent sending to every name, until a person reads them there (section 6)." | "As many messages between two agents as their bound (ten until a person sets another, decision 2026-10-25), shown on a device and read by a person on no device, stop that device sending between them, and stop either agent sending to every name, until a person reads them on any device (section 6)." |
| §0, item 6 | "That a summary has shown a message, and that a person has read it, stay on each device; `log`'s yes marks only what it printed (7.2)." | "That a summary has shown a message stays on each device. That a person has read it is said to the other devices too (decision 2026-10-25, rule 1). `log`'s yes marks only what it printed (7.2)." |
| §1, property 4 | "... and a person's mark." | "... a person's mark (and the device's list of those), and a bound a person set (decision 2026-10-25)." |
| §1, property 10 | "once ten messages between them ... have not been read by a person there, until a person reads them there with `cordelia msg log` at a terminal and types yes, or until ..." | "once as many messages between them as the pair's bound (decision 2026-10-25, rule 3) ... have not been read by a person on any device that counts, until a person reads them with `cordelia msg log` at a terminal on any such device and types yes, or sets a higher bound, or until ..." |
| §1, property 14 | "`log` marks as read by a person only the messages it printed, ..." | adds: "and says so to the other devices (decision 2026-10-25, rule 1)" |
| §1, property 17 | "a device's room there is 64 slots for its messages and one for its read marks" | "... 64 slots for its messages and three for its lists" |
| §1, property 21 | "and one list of what that signer's agents read ... at most 150,784 bytes of fields for each signer" | adds the rows of rule 1's table 2 and of `message_bounds`, and the figure of section 7 below |
| §2.2, the names | `msg/...` and `read/...` | adds `person/<the device's key>` and `hold/<the device's key>`; "The names are 75 bytes ..." adds `hold/` (75) and `person/` (77) |
| §2.2, "A reader refuses ... a form it does not know" | forms 0 to 2 | forms 3 and 4 are known, with the checks of rules 1 and 2 |
| §4.1, `log` | "It shows only the messages that no person has read on this device," | "It shows only the messages that no person has read on any device that counts (decision 2026-10-25, rule 1)," |
| §4.1, `log`'s question, and the lines "You have read the `<N>` others here.", "Not read by a person here.", "You have read `<N>` other messages here, so they are not shown." and "Marked `<N>` messages as read by a person on this device." with their forms | as today | rule 1's words |
| §4.1, `read`'s header | "`<U>` of them not yet read by a person here." | "`<U>` of them not yet read by a person." |
| §4.2 | "Five routes"; the row of `/api/v1/messages/log`, "only the messages that no person has read here" | "Six routes", with `/api/v1/messages/allow` (rule 2); "... on any device that counts" |
| §4.2 | "**It can give `mark`,** and so end a hold (section 6)." | "... and so end a hold on every device; and it can give `allow`, and set any bound (decision 2026-10-25, rule 5)." |
| §4.3, step 12 | the two `pair_held` lines | rule 4's lines |
| §6, the row of `AGENT_MESSAGE_PAIR_UNREAD_MAX` | "stop this device sending between them" | "the usual hold: the bound of a pair until a person sets another (decision 2026-10-25)" |
| §6, the hold | "... and that no person has read on this device." | "... and that no person has read on any device that counts (decision 2026-10-25, rule 1)." |
| §6, the hold | "At 10 it refuses, with `pair_held`."; "where any pair that has X on one side is at 10 on this device" | "At the pair's bound (decision 2026-10-25, rule 3) it refuses ..."; "... is at its bound on this device" |
| §6, the hold | "A person's `cordelia msg log` at a terminal, with yes, marks what it printed read, and the count starts again. A loop ... is stopped on each device where it runs, and each needs a person there to read it." | "... and the count starts again on every device once it hears of it. A loop ... is stopped on each device where it runs, and a person's read on any of them ends it on all." |
| §6, "It is a guard against agents that keep the rules, ..." | as today | adds rule 5's sentence |
| §7.2 | "**Three marks, of which one is said to the other devices.**"; "**Read by a person** is a device's own: ... It is never synced." | "Three marks, of which two are said ..."; "**Read by a person:** only `log` at a terminal, with yes, marks it, and only of the messages that it printed. It is said to the other devices in the device's list of a person's reads, and kept there as a union (decision 2026-10-25, rule 1)." |
| §7.2, its last paragraph | "'Announced' and 'read by a person' stay on each device: a person who reads on the laptop has not read what waits on the desktop, and the hold is for the device where a loop runs." | "'Announced' stays on each device. What a person read on the laptop is read on the desktop too (decision 2026-10-25, rule 1)." |
| §8 | `unread_by_a_person`: "... and no person has read here" | "... and no person has read on any device that counts"; the object gains `bounds` (rule 4) |
| §9.1 | "The hold and the rates count what the index holds, from either generation, so a statement frees no pair." | adds: "A statement ends every bound (decision 2026-10-25, rule 3.6)." |
| §9.2 | "The schema's step 19" | adds step 20: `message_person_marks` and `message_bounds`, and each `not_messages` set to 0 |
| §10 | "for each device, up to 65 slots"; "when a device's list of what its agents read is pushed again: so when its agents read" | "67 slots"; adds: "and when its lists of a person's reads and of bounds are pushed: so when a person reads at a terminal, and sets a bound" |
| §11 | "It can send between two agents until ten messages between them that have a place are unread by a person on its device" | "... until as many as the pair's bound ... are unread by a person on any device" |
| §11, D6 | "until a person there reads `log` and types yes" | "until a person reads `log` on any device and types yes" |
| §11 | "It can give `cordelia msg log` a pseudo-terminal and type yes ..., and so end a hold" | "... and so end a hold on every device, and give `cordelia msg allow` one and set any bound (decision 2026-10-25, rule 5)" |
| §12 | "at most 65 entries of 3,072 bytes ... 199,680 bytes (195 KiB) ... At 64 devices, 12,779,520 bytes (12.2 MiB)" | "67 entries ... 205,824 bytes (201 KiB) ... 13,172,736 bytes (12.6 MiB)" |
| §13, item 10 | `a_misled_agent_on_one_device_holds_two_other_names_on_another`: "until a person at a terminal on desktop reads `log`" | "... on either device" |
| §14, item 8 | "announced and read by a person are not said" | "announced is not said; read by a person is (decision 2026-10-25, rule 1)" |
| §15 | "**The terminal and a yes are the only sign of a person**" | adds rule 5's sentence |
| §16, item 4 | "and ends when a person types yes to `log` at a terminal" | "... at a terminal on any device, or when a person sets a higher bound for the pair" |

**`docs/specs/channels-api.md`.** The routes of messages are not in it today (they are in §4.2 of the record of 2026-10-09, which gains rule 2's route).

| Where | Today | Becomes |
|---|---|---|
| `GET /api/v1/status`, the row of `unread_by_a_person` | "... were not sent here, and that no person has read here" | "... were not sent here, and that no person has read on any device that counts (decision 2026-10-25, rule 1)" |
| The same table | | A row: `bounds`: each bound in force that is not the usual hold, with `a`, `b` (null for every agent), `bound` (null for `any`), `until` and `set_on` (decision 2026-10-25, rule 4) |
| `cordelia status --json`, `messages` | "It changes no `state`, `level`, `summary` or `holds`, and plain `cordelia status`, `--line` and `--waybar` say nothing of messages." | "It changes no `state`, `level`, `summary` or `holds`. `--line` and `--waybar` say nothing of messages, and plain `cordelia status` says only each bound in force (decision 2026-10-25, rule 4)." |

The threat model's T22 (rule 5) and the table of constants in `CLAUDE.md` change too.

## 6. Set aside, and why

- **A bound in the configuration.** A file that an agent can write is not a person at a terminal.
- **A bound for every pair at once.** Every other pair keeps its guard against a loop.
- **A bound per device.** Section 2.
- **Telling a person from a program beyond the terminal.** Rule 5.
- **A held pair in `cordelia status`, or on its line.** The line is for sync (§8 there). A hold is said to the agent that is held, and `log` shows what waits.
- **Carrying bounds across a statement.** Rule 3.6.
- **A person's read in the agents' list,** with a name that no agent has. It would be silent on the version before, but 120 marks would serve two kinds, and the agents' reads would fall out twice as soon.
- **A person's read as a hash, as an agent's is.** It has no name to bind, and the entry is sealed.

## 7. What it costs

- **At a relay:** two entries more for each device in each generation, 6,144 bytes as counted. A device has 67 slots, 205,824 bytes (201 KiB); 64 devices 13,172,736 bytes (12.6 MiB), under a channel's 16 MiB.
- **Pushes:** a list of a person's reads after each yes, and a list of bounds after each `allow` and each change of rule 3.4, each pushed at most once each two seconds (`OUTBOX_FLUSH_INTERVAL_SECS`).
- **What a relay learns:** when a person reads at a terminal and when a bound is set, by when the lists are pushed; and that each device has two slots more. Nothing of what is in them.
- **On a device:** for each key that counts, a row of 56 bytes for each message held that its list names, at most 120 rows of messages not held (6,720 bytes), and at most 4 bounds (1,816 bytes as fields): property 21's 150,784 bytes for each signer become 159,320, with 56 bytes more for each message held and each key whose list names it. And the schema's step 20, from which going back is by the copy, as from step 19 (§9.2 there).
- **On a device of the version before:** a count of entries that were not messages, in `log`, which grows until it takes this version.
- **The tests** of rules 1 to 4.
