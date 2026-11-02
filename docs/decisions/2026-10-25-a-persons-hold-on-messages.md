# Decision: a person's hold on messages

**Date**: 2026-10-25
**Status**: Built. Revised twice after its reviews (section 8).
**Cited as**: "decision 2026-10-25, rule 2", and "rule 3.6" for an item of a rule. The numbers do not change. A number that is not used stays unused.

Words used throughout:

- **The record of 2026-10-09** is [`2026-10-09-messages-between-your-own-agents.md`](2026-10-09-messages-between-your-own-agents.md). Its sections are cited "§6 there".
- **A pair** is two names, or a name and every agent, as §6 there counts them: a message to a name is of the pair of its sender and its recipient, in either direction; a message to every name is of the pair of its sender and every agent. A name may be on both sides: an agent and the same agent on another device (`pairs_with`, `cordelia-storage/src/messages.rs:1061`).
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

And on 25 October, of which bound holds: **your last act decides, on every device, whatever the clocks say and whichever relay is behind.**

Rule 1 is (c). Rules 2 to 4 are (b). Rule 5 is (d).

**What the code does today.**

- A person's read is a row of `message_read_by_a_person` (`cordelia-storage/src/schema.rs:863-865`), keyed by the message's ID, which goes with its message's row. Only `log_of` writes it (`cordelia-api/src/messages.rs:1368-1371`), for the IDs that the command sends after a yes. Nothing says it to another device (§7.2 there: "It is never synced").
- The hold is `held_pair` (`cordelia-api/src/sender.rs:486-504`). `pairs_with` counts each pair's messages that have a place, have not expired, are live, and have no row in that table (`messages.rs:1040-1070` in storage). A count of 10 or more holds. The refusal says "Ten" in its words (`cordelia-node/src/msg_cmd.rs:668-674`).
- **What an agent read already travels.** Each device writes its list in the slot `read/<its key>` of the messages channel (form 2, `cordelia-api/src/marks.rs:169-216`), and a reader keeps the latest list of each key that counts, in place of the one before (`marks.rs:260-271`). Rules 1 and 2 use that way, with the differences they give.
- `log` asks only where its input and its output are both terminals (`msg_cmd.rs:1258`). The node's route takes `mark` from any caller that holds the token (`messages.rs:1708-1747`): it cannot tell a person from a program (§4.2 there).
- Plain `cordelia status` says nothing of messages (`cordelia-node/src/main.rs:1536-1570`), and `docs/specs/channels-api.md` says so as a rule.
- A reader of the version before takes an entry in a slot of the messages channel that it does not know as no message, and counts it (`cordelia-api/src/reader.rs:115`, `NotInRing`). The door reads an entry of the messages channel only where the store keeps it as new (`cordelia-api/src/take.rs:226-232`).

## 1. The rules

Each rule gives what you see, word for word; what is stored, and where; what travels, and how it is sealed; what a device of the version before does beside it; and its tests.

**Placeholders.** `<a>` and `<b>` are names as these commands print one (`name_shown`, `msg_cmd.rs:200`: cleaned, and cut to 48). `<pair>` is "between `<a>` and `<b>`", or "from `<a>` to every agent", and `<Pair>` the same with a capital. `<when>` is a moment as the record of reach writes one: "18:05 UTC", or "18:05 UTC on 2026-10-26" where it is not today. `<device>` is "this device", or a label in quotes as `label_shown` prints it. `<where>` says on which devices you read what is not shown: "on this device", or "on "laptop"", or, where it is more than one, each with its count, this device first and the others in order of label, joined with ", " and " and ": "3 on this device and 7 on "laptop"", "3 on this device, 2 on "desktop" and 5 on "laptop"". A message read here and elsewhere counts as here; one read on two other devices counts under the first label, in order of label.

### Rule 1. A person's read counts on every device

**What you see.** `log` no longer lists, or asks about, a message that a person read on any device of yours that counts, and it says where you read what it does not show. Its lines that change (§4.1 there):

> No new message of `<any agent | the agent <name>>` is held on this device. You have read the `<N>` others, `<where>`.

For one: "You have read the other one, `<where>`."

> You have read `<N>` other messages, `<where>`, so they are not shown.

For one: "You have read 1 other message, `<where>`, so it is not shown." So "You have read 10 other messages, 3 on this device and 7 on "laptop", so they are not shown." tells you whose word hides them (rule 5).

In each message it lists, "Not read by a person here." becomes "Not read by a person."

The question at a terminal:

> Mark these `<N>` messages as read by you? That ends any hold between the agents they are between, here and on your other devices. If you are an agent, stop here and tell your user. Type yes to mark them:

For one: "Mark this message as read by you? That ends any hold between the agents it is between, here and on your other devices. If you are an agent, stop here and tell your user. Type yes to mark it:". With `--since`, the second sentence stays "Older messages are not shown here and stay unread, so a hold may stay."

After a yes:

> Marked `<N>` messages as read by you. Your other devices count them read once they hear of it.

For one: "Marked 1 message as read by you. Your other devices count it read once they hear of it." Where the node marked fewer: "Marked `<M>` of the `<N>` messages printed as read by you: the others are no longer shown here. Your other devices count them read once they hear of it." **Where sync is off,** the second sentence is "Sync is off on this device, so your other devices hear of it once you turn sync on."

Away from a terminal, `log` still ends "Not marked as read by a person: this was not run at a terminal.": an agent reads that line, so it does not say "you". `read`'s header says "`<U>` of them not yet read by a person." (no "here"). The status's `unread_by_a_person` counts the same way.

**What is stored, and where** (the device's store; the schema's step 20):

1. **A person's read here** stays a row of `message_read_by_a_person`, as today. Its order is the table's rowid: the newest is the highest.
2. **What other devices said:** a new table, `message_person_marks`, of the IDs that each other key's lists of a person's reads held, each with when it was taken here. **It is a union:** a later list that leaves an ID out takes nothing away. A row whose message this device holds goes with that message's row (`drop_row`). Of the rows whose message it does not hold, it keeps at most 120 for each key (`AGENT_MESSAGE_READ_MARKS_MAX`), the latest taken first, each for 30 days from when it was taken (`AGENT_MESSAGE_KEPT_DAYS`). **The rows of a key that a statement does not count go in the transaction that applies it,** so a key added again later counts only what it lists from then.
3. **Read by a person is worked out when it is asked,** as read by an agent is (§7.2 there): a row of 1, or a row of 2 under a key that counts now. `pairs_with`, which is SQL, is passed the keys that count; `is_read_by_a_person`, `log` and the status's count ask the same.

**Why a union, where an agent's list is kept by replacing it.** An agent's mark that falls out of the newest list is unread again, and at worst an agent is shown a message twice. A person's read that fell out would bring back a hold that you had ended, with no new message. A union cannot do that. Its bound is on what it keeps of messages that this device does not hold.

**What travels, and how it is sealed.** Each device writes one entry more in the messages channel, in the slot `person/<its key>` (`AGENT_MESSAGE_PERSON_PREFIX`), of form 3: the byte `3`; a count, two bytes, from 0 to 120; that many message IDs of 16 bytes each, the newest first; and zeros to 1,936 bytes. It holds the newest 120 rows of the table of 1. It is the agents' list (form 2) with IDs in place of marks: a person's read has no name to bind into a hash, and the entry is sealed.

- It is sealed by `Entry::seal` under the messages channel's secret, signed by the device, at 2,048 bytes, as every entry of the channel is (§2.2 there). Its name, `person/` and a key, is 77 bytes, the longest name of the channel, so the value's size does not change.
- It is written and sent by the rules of the agents' list (§2.4 there): only after the first fetch since the node started, and only where the device stands applied with sync on; wherever the table holds an ID that the list it holds lacks, so `log`'s write that marks writes it too; one revision above the list it holds; again above a relay's answer of another, at most three times in a row (`AGENT_MESSAGE_SENDS_MAX`), counted apart from the agents' list (`meta::MESSAGES_LIST_AGAIN` is that list's alone, and `marks::answered` matches each of the three slots); and after a relay's answer that it holds a later one, not until the next pull hands that back. A device's first list in a new generation holds the newest 120 rows of its table (§9.1 there).
- **Taken by a reader,** in the door's write (`reader.rs`), as the agents' list is: in its signer's slot, raising no H. Another key's list adds each of its IDs to the table of 2. The device's own list, handed back by a relay from its later life (a store restored from a backup), adds each ID whose message it holds to the table of 1, and keeps the rest under its own key in the table of 2. A list that is not one (a count over 120, a fill that is not zeros) is counted as no message, and takes nothing away. **A list from a key that no longer counts says nothing.**

**Beside the version before.** A device of the version before writes no such list: a person's read there counts there alone, as today, and a device of this version beside it holds by that. It stores this version's lists, as a relay does, and reads each as an entry in a slot it does not know (`NotInRing`): its `log` counts each new list as one more entry that was not a message, and says "`<N>` entries from "`<label>`" were not messages, and were not shown." Nothing else changes there. So "here and on your other devices" is true of your devices of this version: the notes of the release, and the help of `log`, say that a device of yours on an older version does not hear of it.

**When it takes this version,** the door does not read what the store already holds (`take.rs:226-232`), so the lists it stored while it was older would never be read. **Once, after step 20, where the device stands applied,** the node reads through the reader the entry its store holds in `person/<key>` and in `hold/<key>` for each key that counts, as though the store had just kept it, with the time the store kept it as its first holding; sets each signer's count of entries that were not messages to 0; and writes the key of `node_meta` that says it was done: all three in one transaction. It is done at the first start after step 20, before the first pass and before any route of messages answers; where the device does not stand applied then, at its first pass after it does. So it is never marked done unread. The count was of this version's lists; setting it to 0 also clears the count of a device that really wrote what was no message, and the notes of the release say so.

**Tests.**

- Units, in-process over `Several` (`marks.rs`, `messages.rs`):
  - `a_persons_read_on_one_device_counts_on_another`: the laptop's `log` marks three; the desktop takes the list; its pair count, its status's `unread_by_a_person` and its `log`'s `already_read` count all three as read by a person.
  - `log_says_where_you_read_what_it_does_not_show`: 3 read here and 7 by the laptop's list give "3 on this device and 7 on "laptop""; one read both here and there counts as here.
  - `a_persons_read_that_arrives_before_its_message_loses_nothing`: the desktop takes the list, then the message; the message is read by a person at once, and is never in a pair's count.
  - `a_persons_read_that_falls_out_of_the_newest_list_stays_read`: the laptop marks 130; the desktop takes its list at 60 and at 130; all 130 stay read there.
  - `what_is_kept_of_messages_not_held_is_bounded`: a key lists 240 IDs of messages not held, in two lists; 120 are kept, the latest taken; one goes 30 days after it was taken.
  - `a_persons_read_from_a_key_that_no_longer_counts_says_nothing`, and `a_statement_drops_the_rows_of_a_key_it_does_not_count`.
  - `the_persons_list_waits_for_the_first_fetch_and_for_sync`, and `a_relay_that_answers_another_to_the_persons_list_gets_three_more_at_most`, as the agents' list's tests do.
  - `a_persons_list_handed_back_is_merged`: a store restored from a backup takes its own later list.
  - `lists_held_before_the_upgrade_are_read_after_it`: a store stepped from 19 that holds a list of form 3 and one of form 4 reads both at the first start, and its count of entries that were not messages is 0.
- Units of the command (`msg_cmd.rs`): every line above, word for word, for one and for many, with and without `--since`, with sync on and off.
- Real processes (`msg_e2e.rs`): `one_yes_on_the_laptop_ends_the_hold_on_both_devices`. An agent on the laptop and one on the desktop answer each other until each device refuses with `pair_held`. `log` at the laptop's terminal (`AtTerminal`) is answered yes. The test waits until the desktop's `unread_by_a_person` falls; then a send goes on each device, and `log` at the desktop's terminal lists none of them and says "You have read the `<N>` others, on "laptop"." `log_shows_and_marks_only_what_no_person_has_read_here` gains the same on a second device.

### Rule 2. A bound for each pair, set only by a person

**The command.**

```
cordelia msg allow <a> <b> (<n> | any) [--for <time>]
cordelia msg allow <a> --all (<n> | any) [--for <time>]
```

- `<n>` is 1 to 64 (`AGENT_MESSAGE_RING`, one lap of a device's ring: above it, a bound stops no loop between two agents of one device, and `any` says no hold plainly). `any` is no hold.
- `--for` takes what `--since` takes (30m, 8h, 2d), from 1 minute to 7 days (`AGENT_MESSAGE_PAIR_BOUND_MAX_SECS`). Where it is not given, 8 hours (`AGENT_MESSAGE_PAIR_BOUND_SECS`).
- **10 is the usual hold:** `allow <a> <b> 10` goes back to it now. It takes no `--for`: one given is not used.
- Each name must be one that the personal channel lists, as for `send --to`.
- In `cordelia msg --help` its line begins "For a person at a terminal:".

**What you see.**

> This is for a person at a terminal. An agent must not run it, and must not answer its question.
> `<Pair>`, `<k>` messages wait for you to read them. `<now>`
> `<question>` If you are an agent, stop here and tell your user. Type yes to allow it:

For `<k>` of 1, "1 message waits for you to read it."; for 0, "no message waits for you to read.": "Between `<a>` and `<b>`, no message waits for you to read. `<now>`".

`<now>` is one of:

- "Sending stops at 10, the usual hold."
- "Sending stops at `<m>` until `<when>`, as you set on `<device>`."
- "Only the hourly limits stop sending until `<when>`, as you set on `<device>`."

`<question>` is one of:

- "Allow `<n>` to wait unread, until `<when>`? At `<n>`, sending stops until you read them with cordelia msg log. After `<when>` it stops at 10 again."
- where `<n>` is at or below `<k>`: "Allow `<n>` to wait unread, until `<when>`? `<k>` wait now, so sending stops at once, until you read them with cordelia msg log. After `<when>` it stops at 10 again." For `<k>` of 1: "... 1 waits now, so sending stops at once, ..."
- for `any`: "Allow any number to wait unread, until `<when>`? Until then only the hourly limits stop sending. After `<when>` it stops at 10 again."
- for 10: "Go back to the usual hold of 10 now?"

With `--all`, the question ends with one sentence more: "`<a>` still sends nothing to every agent while a pair with `<a>` on one side is held." (§6 there refuses `--all` from `<a>` while any of its pairs is at its bound.)

After a yes: "Done. `<Pair>`, sending stops at `<n>` until `<when>`. Your other devices hold by it once they hear of it." For `any`: "Done. `<Pair>`, only the hourly limits stop sending until `<when>`. Your other devices hold by it once they hear of it." For 10: "Done. `<Pair>`, sending stops at 10 again. Your other devices hold by it once they hear of it." Any other answer: "Nothing was set."

**Where its input or its output is not a terminal,** it says its first line, then, on standard error with status 1, "Nothing was set: this was not run at a terminal." It asks the node nothing.

**Refusals,** on standard error with status 1, the first that applies:

1. The command line: "Give two names, or one name and --all, then a number from 1 to 64, or any."
2. The number: "`<n>` is not a number you can allow: give 1 to 64, or any."
3. The time: "`<time>` is not a time you can allow it for: give 1m to 7d, as 30m, 8h or 2d."
4. The node, the device and sync: steps 3, 4 and 5 of §4.3 there, as `send` says them, with "so it sets nothing" and "nothing was set" where `send` says "so it sends no message" and "nothing was sent".
5. Not fetched (step 8 there): "This device has not yet read its own messages back from a relay since it started, and sets nothing until it has. Try again in a minute." (`not_fetched`) A bound is set only after the device has read what the relays hold, so it is set after what they hold (rule 3.1).
6. A name: "No device of yours syncs `<name>`, so nothing was set." (`no_such_name`)
7. Room (rule 3.6), with each pair the list holds, as `<pair>, until <when>`, under it: "This device's list of bounds is full: it holds what you set here for these pairs, each until 7 days after you set it. You can still set any of them again:" (`bounds_full`)

**What is stored, and where.** A new table, `message_bounds` (step 20): for each key, this device's own among them, each bound its latest list holds: the pair; the bound (none for `any`); `set` and `at` (rule 3.1); `for`, in seconds; and when this device first held it (rule 3.3). Nothing is in the configuration: a file that an agent can write is not a person at a terminal.

**The route.** `POST /api/v1/messages/allow`, a sixth route of §4.2 there, behind the token: `a`, `b` (null for every agent), `bound` (1 to 64, or null for `any`), `for_secs` and `yes`. It checks the names, the bound and `for_secs` again, as the command does. With `yes` false it answers the look that the command prints first: `waiting` (`<k>`), and the bound in force (rule 3) with its `until` and the device it was set on, or null for the usual hold. With `yes` true it sets the bound, in the write that writes the list. The command asks for the look, asks its question, and asks the node again (steps 3 to 5) before it sets, as `log` does before it marks.

**What travels, and how it is sealed.** Each device writes one entry more in the messages channel, in the slot `hold/<its key>` (`AGENT_MESSAGE_PAIR_BOUNDS_PREFIX`), of form 4: the byte `4`; a count, one byte; then each bound, the latest `set` first: `a` (two bytes of length and a name); the kind of `b` (1: a name, 2: every agent); `b` (two bytes of length and a name, for kind 1 only); the bound (one byte: 0 for `any`, else 1 to 64); `set` and `at` (8 bytes each, unsigned, seconds since 1970, rule 3.1); and `for` (4 bytes, seconds); and zeros to 1,936 bytes.

- For a pair of two names, `a` is not above `b` in byte order, so a pair has one spelling; they may be equal.
- **As many bounds as fit:** at the longest names 4 (1,706 bytes; five would need 2,132), at names of 30 bytes 22.
- A reader takes as no list one with a name that is not a name, a kind other than 1 or 2, `a` above `b` for kind 1, a bound over 64, a `for` outside 60 to 604,800, two bounds of one pair, bytes that run past the value, or a fill that is not zeros. **Where a newer list of form 4 is no list, that key's bounds go:** a bound that cannot be read holds nothing, and the pair is at what the others list. The device's own key is the one exception: its own bounds are its person's acts at its terminal, and a list of its own that does not read, handed back by a relay, is a holder of its key's, so they stay. **A form this version does not know leaves that key's bounds as they were,** as a list of what agents read that does not read leaves the marks before it (`reader.rs:167`): so a later version that changes what a list of bounds holds writes it under a new form byte, and this version keeps that key's last bounds of form 4 rather than drop a 10 that holds an older `any` back.
- **The device's own list, handed back by a relay from its later life** (a store restored from a backup), is merged into the device's own rows of `message_bounds`, in the door's write: for each pair, the bound with the later `set` is kept; an own bound that the later list lacks is kept only where it was set since this start (the later life dropped the rest). Its next list goes above it.
- **A relay's answer of another to the device's own list** means that its store went back, or that the relay lies. The device acts on it only where it may write its list, the answer names the revision of the list it holds, and it has written that list again so fewer than three times in a row, as it writes a list again: it first drops those of its own bounds set before this start that allow more than the usual hold (`any`, or a number above 10), which may be ones its later life ended, keeps a 10 or a lower number, the safe side whichever it is, and then writes above. So a restored store brings no ended `any` back, a relay that lies ends no 10 and no lower bound, and the device keeps what you set since it started; what its later life set and no relay it reaches still holds is lost, and the pair is at what the others list.
- It is sealed, signed, sized and written by the rules of rule 1's list, wherever what it lists changes (rule 3.5). Its name, `hold/` and a key, is 75 bytes.

**Beside the version before.** `cordelia msg allow` is not there, and a device of the version before holds every pair at 10. It counts each list of bounds as an entry that was not a message, as in rule 1. So where your agents run on two devices of two versions, the older one stops its side at 10, whatever you allow. The help of `cordelia msg allow` says so: "A device of yours on an older version holds every pair at 10, and does not hear of this." When it takes this version it reads the list it holds (rule 1).

**Tests.**

- Units (`msg_cmd.rs`): `allow_is_refused_away_from_a_terminal` (input a pipe; output a pipe), and asks the node nothing; `allow_takes_a_number_any_and_a_time` (0, 65, `none`, `0m` and `8d` refused; 10 with `--for` is the usual hold); every line above, word for word, `--all`'s among them.
- Units (`messages.rs`): `the_look_says_the_count_and_the_bound_in_force`; `the_allow_route_refuses_what_the_command_refuses` (a bound of 0 or 65, a `for_secs` of 59 or 604,801, a name no device syncs); `allow_is_refused_before_the_first_fetch_and_with_sync_off`; `a_full_list_of_bounds_refuses_a_new_pair_and_takes_one_it_holds`; `a_bound_is_listed_and_taken_by_another_device`; `a_list_of_bounds_that_is_not_one_is_no_list`, one case for each check above, and that it drops that key's bounds, where a form it does not know keeps them; `a_restored_store_takes_its_own_later_bounds`; `a_restored_store_that_reaches_its_later_list_late_keeps_both_lives_last_acts` (the review's two cases: a relay that answers another, and one that answers that it holds a later list).
- Real processes (`msg_e2e.rs`): `a_bound_set_on_the_desktop_holds_on_both`. Two agents, X on the laptop and Y on the desktop, answer each other until the pair is held at 10 on both. At the desktop's terminal (`AtTerminal`), `cordelia msg allow X Y 20 --for 1h`, and yes. Once the laptop holds the list, they answer each other again until the pair counts 20 on both devices (each sends five more, so neither folder nears its 20 an hour), and the next send is refused with `pair_held` and rule 4's line naming 20. `cordelia status` on the laptop says rule 4's line, with "you set it on "desktop"". Then `cordelia msg allow X Y 10` on the laptop, and both hold at 10 again. And `allow_into_a_pipe_sets_nothing`: with its output a pipe, nothing is set and the pair stays held.

### Rule 3. Which bound holds a pair, and for how long

1. **Each bound has two times.** `at` is the clock of the device it is set on when the yes is typed. `set` is `at`, or one second after the latest `set` that device holds for that pair from any key, whichever is later (at the top of its 8 bytes it stays there: two such bounds then tie, and 3.2's tie decides). `set` orders bounds, and nothing else; `at` times them (3.3, 3.5). So a bound set after another was heard of is later than it, whatever the clocks say, and a clock far ahead on one device moves no other device's times.
2. **The bound in force for a pair is the one with the latest `set`,** among this device's own and those of the keys that count. Of two with one `set`, the lower decides (a number before `any`), then the lower key. Every device decides the same from the same lists. **Where that bound has ended, the pair is at the usual hold,** whatever an older one would still allow. With none, the usual hold. **Two acts on two devices, neither of which had heard of the other,** are ordered by those devices' clocks: the one case in which a clock decides. Your devices keep time within seconds (§7.1 there), so it is the order you made them in, unless a clock is wrong.
3. **How long it holds.** A bound holds on a device from when the device holds it. It ends `for` seconds after the earlier of its `at` and when that device first held it, as a message's shown time is worked out (§7.1 there). That first holding is kept for the bound (its key, pair and `set`) across that key's later lists. A 10 carries `for` 604,800. A clock behind shortens its bounds on the other devices, as it does its messages; a clock ahead gains nothing, but where a device first holds a bound late, from a relay that is behind, a bound whose `at` is more than 7 days ahead can hold there for its `for` at most.
4. **When a bound ends** nothing is said. The pair is at 10 again, and `cordelia status` no longer shows it. Where 10 or more wait unread, the next send is refused at once.
5. **What a device lists:** for each pair, the latest bound set on it, a 10 among them, **until 7 days and 10 minutes after its `at`, by its own clock** (`AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS`: the longest an older bound can hold, and a clock's 10 minutes), or until it holds a bound for that pair with a later `set` from another key, which then decides in its place and is listed as long. A new bound for a pair replaces the device's own. So no older bound comes back, from a device that was off or from a relay that is behind: whatever it overrode has ended before it leaves the list.
6. **Room.** A bound for a pair that the list does not hold, and that would not fit, is refused (rule 2, refusal 7). A pair it holds can always be set again, in its place.
7. **A statement ends every bound.** When a device applies a statement (a removal, a renewal, a settlement or a recovery), or moves to one with no phrase (decision 2026-10-24, rule 9: a move is an apply), it drops every row of `message_bounds`, its own and the others', in the transaction that applies it, and writes no list of bounds in the new generation until one is set again. Nothing of messages is carried (§9.1 there), and a change of your devices is a moment to be back at the usual hold.
8. **A key that no longer counts says nothing:** its bounds stop holding at once.

**What you see** is rule 2's look and rule 4's lines. **What is stored, and what travels,** is rule 2's. **Beside the version before,** it holds at 10 (rule 2).

**Tests.** Units, in-process with the node's clock (`SyncControl::set_now`), over `Several`:

- `the_bound_set_last_decides`: the desktop sets 30, then the laptop, having heard of it, sets `any`; both hold by `any`; when the laptop's ends, both hold at 10, though the desktop's 30 would still run.
- `a_later_act_decides_whatever_the_clocks_say`: the desktop's clock 9 minutes ahead sets `any`; the laptop, having heard of it, sets 10; the 10's `set` is a second after the `any`'s, and both hold at 10. And with the laptop's clock an hour behind, the same.
- `a_ten_set_before_an_older_bound_is_heard_of_still_decides`: the desktop, with no relay, sets `any`; an hour later the laptop sets 10; the desktop reaches a relay; both hold at 10, and the desktop no longer lists its `any`.
- `an_older_bound_does_not_come_back_from_a_relay_that_is_behind`: the laptop lists `any`, the desktop then 20 for an hour; relay2 holds only the laptop's first list; a third device pulls from relay2 and from relay1, and holds at 10 once the 20 has ended.
- `two_bounds_set_in_one_second`: the lower decides on both devices.
- `a_clock_ahead_gains_nothing`: a bound whose `at` is an hour ahead ends `for` after it was first held, and does so across that key's next list.
- `a_clock_a_year_ahead_lists_seven_days_and_holds_nothing_new_on_a_device_that_was_off`: the desktop, its clock a year ahead, sets `any`; the laptop, having heard of it, sets 20, whose `set` is a year ahead and whose `at` is now; each is listed 7 days and 10 minutes by its own clock, and a third device that comes back after three weeks holds neither.
- `a_set_at_the_top_of_its_field_ties`: a key lists `any` with `set` at the top; your later 10's `set` stays there, and the 10 decides.
- `a_bound_that_ends_holds_a_pair_over_10_at_once`.
- `a_bound_set_while_a_pair_is_held`: raised above the count, a send goes at once and nothing is marked read; lowered to the count, a send is refused at once.
- `a_bound_stays_listed_for_seven_days_and_ten_minutes`.
- `a_statement_ends_every_bound`: a renewal, and a removal.
- `a_bound_from_a_key_that_no_longer_counts_says_nothing`.

Real processes: rule 2's test, whose last step is 3.1 and 3.2.

### Rule 4. What the hold says

**To an agent**, by `send`, refused with `pair_held` (step 12 of §4.3 there):

> `<k>` messages between `<from>` and `<to>` wait for your user to read them, and sending between them stops at `<n>`. No more are sent between them until your user reads them with cordelia msg log at a terminal, on this device or another, or they expire. Tell your user.

For `<k>` of 1: "1 message between `<from>` and `<to>` waits for your user to read it, and sending between them stops at 1. No more are sent between them until your user reads it with cordelia msg log at a terminal, on this device or another, or it expires. Tell your user."

> Messages between `<from>` and `<other>` wait for your user to read them, so `<from>` sends nothing to every agent until your user reads them with cordelia msg log at a terminal, on this device or another, or they expire. Tell your user.

`<n>` is the bound in force (rule 3), and `<k>` the count, which can be above it where a bound was lowered or messages came from another device. The node's refusal carries both, as `bound` and `waiting`. The line does not name `cordelia msg allow`: that is for you, and not for an agent.

**To you**, in `cordelia status`, under `Node:` after `Devices:`, one line for each pair whose bound in force is not the usual hold (a listed 10 is the usual hold):

> `  Messages:  <pair>, sending stops at <n> until <when> (you set it on <device>)`

> `  Messages:  <pair>, only the hourly limits stop sending until <when> (you set it on <device>)`

`--line`, `--waybar`, the level and the holds say nothing of it (§8 there). `cordelia status --json` carries it in `messages`, as `bounds`: for each, `a`, `b` (null for every agent), `bound` (null for `any`), `until` (RFC 3339) and `set_on` (`label` and `fingerprint`, or `"this"`).

**What is stored, and what travels:** nothing more; it is worked out from rules 1 to 3. **Beside the version before:** the command and the node of one version only work together (the record of 2026-10-04, 10.1, rule 6), and a device of the version before says its own line with "Ten".

**Tests.** Units: `msg_cmd.rs`, `the_held_line_names_the_bound_and_the_count` (10 of 10, 12 of 5, 1 of 1, and the line for every agent, each word for word); `main.rs`, `the_status_says_each_bound_in_force` (a number, `any`, every agent, this device and a label; nothing for the usual hold, a listed 10, or one that has ended); `messages.rs`, `the_status_object_carries_the_bounds`. Real processes: rule 2's test asserts the refusal's line and the status's line.

### Rule 5. A terminal is the only sign of a person

**The known limit, as it is:**

> **The only test for a person is that the command's input and output are terminals, and a pseudo-terminal (`script`, `expect`) passes it. Any program that can read the node's token, as every program you run can, calls the node's routes with no terminal at all. So such a program can mark messages read by you, which ends a hold and hides them from `log` on every device of yours, and can set any bound. The hold relies on agents keeping to "stop here".**

- **The same sentence goes into the known limits of R1's gate 12,** and into the threat model's row T22 (`docs/security/threat-model.md`), in place of "a program that ends a hold with a pseudo-terminal and a yes".
- **Rules 1 and 2 widen what it reaches.** Today such a program ends a hold on the one device it runs on, and cannot hide a message from `log` on any. After them, it ends a hold on every device, hides what it marks from `log` on each, and can lift the hold for up to 7 days. What bounds it does not change: the rates (20 an hour from a folder, 60 from a device). What shows it: `log` says on which device you read each message it does not show (rule 1), and `cordelia status` says each bound and where it was set (rule 4). A device that counts, or a holder of its key, can do the same by its list.
- **Nothing here tries to tell a person from a program:** not timing, not the kind of terminal, not a word typed back. Each is one more thing a program can copy, and you would pay for it.

**What you see:** rule 1's `<where>`. **Stored, travels, beside the version before:** nothing. **Tests:** `the_route_sets_a_bound_with_no_terminal` and `the_route_marks_with_no_terminal` (units, `messages.rs`, named in T22): each shows the limit, and fails where it is no longer so, so that the record is changed with the code. Every test of a person's act, `log`'s yes and `allow`'s among them, runs at a pseudo-terminal (`AtTerminal`).

## 2. The defaults, and why

- **Before you set a bound,** every pair holds at 10, as today. Ten was chosen with the folder's rate (parameter-rationale.md §12.12); nothing has measured against it since.
- **"For a set time"** is `--for`, from the yes (rule 3.3): 8 hours where you give none, a working day, so that what you allow for a task is gone by the next morning; and at most 7 days, so that a bound you forget ends by itself.
- **What `any` lets through:** only the rates. A loop between two folders sends up to 40 an hour, 6,720 in 7 days. And one folder at 20 an hour goes round its device's ring of 64 in about three hours, so the device's other agents' messages can be overwritten before they are read (§2.5 there). That is why `any` has an end.
- **When it ends,** the pair is at 10 again, on every device, with nothing said (rule 3.4).
- **What an agent sees when held** is rule 4's line: the count, the bound, that only its user ends it, and "Tell your user". It is not told how a bound is set.
- **A bound is per pair, and per person:** one for each pair, the same on every device, set on any of them.
  - **Per pair,** so that you allow the two agents you are watching, and every other pair keeps its guard against a loop.
  - **Per person, and not per device.** A loop between an agent on the laptop and one on the desktop is counted on both, and each device stops its own side. A bound on the laptop alone would let the laptop's agent send while the desktop's is held: you would set it twice, and be held by the device you forgot. Rule 1 makes your read one act on every device; a bound is the same.

## 3. The hard cases

1. **Two devices set different bounds.** The later act decides, on every device, once both lists have reached it: one set after the other was heard of is later whatever the clocks say (rule 3.1); two that neither had heard of go by their clocks, and in one second the lower decides (rule 3.2). Until a list has reached a device, that device holds by what it knows. A bound stays listed until whatever it overrode has ended (rule 3.5), so a device that was off, or a relay that is behind, brings no older one back. `cordelia status` says which bound holds, and where it was set.
2. **A bound set while messages are held.** It holds from the next send, and marks nothing read. Raised above the count, the pair sends again. Set at or below it, the pair stays held, and the question says so before the yes (rule 2).
3. **A removed device's marks.** A person's read and a bound say something only while the key that listed them counts (rules 1 and 3.8), and that key's rows say nothing from the moment a device knows of the removal, on any branch (decision 2026-10-24, rule 6: from then the key counts for nothing there); the transaction that applies the removal drops them. A message that only a person on the removed device read is then unread by a person again, and may hold a pair until you read it on a device that remains. That is the safe side: the removed device may not be yours any more. A removal is a statement, so every bound ends too (rule 3.7). What the removed device writes after goes into the old generation, and reaches only devices that do not know of it.
4. **A recovery.** It is a statement, so every bound ends. The new machine holds no message, no person's read and no bound. A device added again keeps its own reads (rule 1's table 1, with their messages). It dropped the rows of each other key when it applied the recovery's statement, so it counts that key's reads again only from that key's first list in the new generation, its newest 120. What is not in it is unread by a person there, the safe side.
5. **A person's read arrives for a message this device does not hold yet.** It is kept under the key that listed it, among that key's 120 of messages not held, for 30 days (rule 1). When the message comes, it is read by a person at once: it never counts toward a hold, and `log` never lists it as new. Where it went first (the key listed more than 120 that are not held here, or 30 days passed), the message is unread by a person here: it counts toward the hold, the safe side, and `log` asks about it again.

## 4. Constants

Each in `cordelia-core/src/protocol.rs`, with its reason in `docs/specs/parameter-rationale.md` §12.12:

| Constant | Value | Why |
|---|---|---|
| `AGENT_MESSAGE_PERSON_PREFIX` | `person/` | The first part of the name of a device's list of what a person read on it (rule 1). With a key it is 77 bytes, the longest name that the channel's value is sized by (`AGENT_MESSAGE_VALUE_BYTES`), so the size does not change; a longer prefix would need a smaller value. No prefix of the channel begins another |
| `AGENT_MESSAGE_PAIR_BOUNDS_PREFIX` | `hold/` | The first part of the name of a device's list of the bounds a person set on it (rule 2): 75 bytes with a key |
| `AGENT_MESSAGE_PAIR_BOUND_SECS` | 28,800 | `--for` where none is given: 8 hours, a working day, so that what is allowed for a task is gone by the next morning |
| `AGENT_MESSAGE_PAIR_BOUND_MAX_SECS` | 604,800 | The longest `--for`, and the `for` of a 10: 7 days, a week away, after which a bound that was forgotten ends by itself. Under `any`, two folders' 20 an hour bound a loop to 6,720 messages in that time |
| `AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS` | 605,400 (derived) | `AGENT_MESSAGE_PAIR_BOUND_MAX_SECS` and `AGENT_MESSAGE_AHEAD_MAX_SECS`: how long after its `at`, by its own clock, a device lists the latest bound it set for a pair (rule 3.5), so that every bound it overrode has ended first, with a clock's 10 minutes |

**Existing constants with a new use,** whose reasons gain a sentence:

- `AGENT_MESSAGE_PAIR_UNREAD_MAX` (10): the usual hold, the bound of every pair until a person sets another, and again when it ends (rule 3).
- `AGENT_MESSAGE_RING` (64): the highest bound a person can set. With the two lists of rules 1 and 2, a device has 67 slots: 64 × 67 × 3,072 = 13,172,736 bytes, under a channel's 16 MiB. The check at `protocol.rs:2405-2409` counts `AGENT_MESSAGE_RING + 3`.
- `AGENT_MESSAGE_READ_MARKS_MAX` (120): the IDs in a person's list, and the rows of messages not held kept for each key.
- `AGENT_MESSAGE_KEPT_DAYS` (30): how long such a row is kept.
- `AGENT_MESSAGE_SENDS_MAX` (4): the revisions of each list, as for the agents' list.
- `AGENT_MESSAGE_AHEAD_MAX_SECS` (600): the clock's margin in `AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS`.

No label is added: a person's read is an ID, not a hash. `protocol.rs` checks when it is compiled: each new name with a key is at most 77 bytes; no prefix of the channel begins another; a full list of form 3 fits in `AGENT_MESSAGE_VALUE_BYTES`, and so do four bounds of form 4 at the longest names.

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
| §1, property 21 | "and one list of what that signer's agents read ... at most 150,784 bytes of fields for each signer"; "its list of read marks never does" | adds the rows of rule 1's table 2 and of `message_bounds`, the figure of section 7, and "nor do its lists of a person's reads and of bounds" |
| §2.2 | "The messages channel holds three forms of entry" | "five forms of entry" (forms 3 and 4, decision 2026-10-25) |
| §2.2, the names | `msg/...` and `read/...` | adds `person/<the device's key>` and `hold/<the device's key>`; "The names are 75 bytes ..." adds `hold/` (75) and `person/` (77) |
| §2.2, "A reader refuses ... a form it does not know" | forms 0 to 2 | forms 3 and 4 are known, with the checks of rules 1 and 2 |
| §2.3 | "**So the channel never holds more than 65 entries for each device that has written in it.**" | "67 entries" |
| §2.5 | "No other entry of K raises H ...: not one in another slot, and least of all its list of read marks" | "... least of all its lists (of read marks, of a person's reads and of bounds)" |
| §4.1, `log` | "It shows only the messages that no person has read on this device," | "It shows only the messages that no person has read on any device that counts (decision 2026-10-25, rule 1)," |
| §4.1, `log`'s question, and the lines "You have read the `<N>` others here.", "Not read by a person here.", "You have read `<N>` other messages here, so they are not shown." and "Marked `<N>` messages as read by a person on this device." with their forms | as today | rule 1's words |
| §4.1, `read`'s header | "`<U>` of them not yet read by a person here." | "`<U>` of them not yet read by a person." |
| §4.2 | "Five routes"; the row of `/api/v1/messages/log`, "only the messages that no person has read here" | "Six routes", with `/api/v1/messages/allow` (rule 2); "... on any device that counts" |
| §4.2 | "**It can give `mark`,** and so end a hold (section 6)." | "... and so end a hold, and hide what it marks from `log`, on every device; and it can give `allow`, and set any bound (decision 2026-10-25, rule 5)." |
| §4.3, step 12 | the two `pair_held` lines | rule 4's lines |
| §6, the table, `AGENT_MESSAGE_RING` | "With its list, 65 slots of 3,072 bytes: ... 12.2 MiB" | "With its three lists, 67 slots ...: 12.6 MiB" |
| §6, the table, `AGENT_MESSAGE_PAIR_UNREAD_MAX` | "stop this device sending between them" | "the usual hold: the bound of a pair until a person sets another (decision 2026-10-25)" |
| §6, after the table | "that 64 devices' 65 slots of 3,072 bytes are within `MAX_ENTRY_CHANNEL_BYTES_AT_RELAY`" | "67 slots" |
| §6, the hold | "... and that no person has read on this device." | "... and that no person has read on any device that counts (decision 2026-10-25, rule 1)." |
| §6, the hold | "At 10 it refuses, with `pair_held`."; "where any pair that has X on one side is at 10 on this device" | "At the pair's bound (decision 2026-10-25, rule 3) it refuses ..."; "... is at its bound on this device" |
| §6, the hold | "A person's `cordelia msg log` at a terminal, with yes, marks what it printed read, and the count starts again. A loop ... is stopped on each device where it runs, and each needs a person there to read it." | "... and the count starts again on every device once it hears of it. A loop ... is stopped on each device where it runs, and a person's read on any of them ends it on all." |
| §6, "It is a guard against agents that keep the rules, ..." | as today | adds rule 5's sentence |
| §7.2 | "**Three marks, of which one is said to the other devices.**"; "**Read by a person** is a device's own: ... It is never synced." | "Three marks, of which two are said ..."; "**Read by a person:** only `log` at a terminal, with yes, marks it, and only of the messages that it printed. It is said to the other devices in the device's list of a person's reads, and kept there as a union (decision 2026-10-25, rule 1)." |
| §7.2, what a device that lies in its list can do | "It cannot hide them from `log`, which shows every message that no person has read here, with the devices whose lists say it was read." | "It cannot hide them from `log` by that list. By its list of a person's reads it can: `log` then says on which device you read each one it does not show (decision 2026-10-25, rules 1 and 5)." |
| §7.2, its last paragraph | "'Announced' and 'read by a person' stay on each device: a person who reads on the laptop has not read what waits on the desktop, and the hold is for the device where a loop runs." | "'Announced' stays on each device. What a person read on the laptop is read on the desktop too (decision 2026-10-25, rule 1)." |
| §8 | `unread_by_a_person`: "... and no person has read here" | "... and no person has read on any device that counts"; the object gains `bounds` (rule 4) |
| §9.1 | "The hold and the rates count what the index holds, from either generation, so a statement frees no pair." | adds: "A statement ends every bound (decision 2026-10-25, rule 3.7)." |
| §9.2 | "The schema's step 19"; "There is no first-start step: no row of the version before means anything to messages." | adds step 20: `message_person_marks` and `message_bounds`; and "Step 20 has one: the lists held before it are read once, and each `not_messages` is set to 0 (decision 2026-10-25, rule 1)." |
| §10 | "for each device, up to 65 slots"; "when a device's list of what its agents read is pushed again: so when its agents read" | "67 slots"; adds: "and when its lists of a person's reads and of bounds are pushed: so when a person reads at a terminal, and sets a bound" |
| §11 | "It can send between two agents until ten messages between them that have a place are unread by a person on its device" | "... until as many as the pair's bound ... are unread by a person on any device" |
| §11, D6 | "until a person there reads `log` and types yes" | "until a person reads `log` on any device and types yes" |
| §11 | "It can give `cordelia msg log` a pseudo-terminal and type yes ..., and so end a hold" | "... and so end a hold, and hide what it marks from `log`, on every device, and give `cordelia msg allow` one and set any bound (decision 2026-10-25, rule 5)" |
| §11, a holder of the device's key | "list in its list of what was read messages that nobody read (7.2)" | adds: "and list in its list of a person's reads messages that no person read, which ends their hold and hides them from `log` on every device but says whose word it is; and list any bound (decision 2026-10-25)" |
| §12 | "at most 65 entries of 3,072 bytes ... 199,680 bytes (195 KiB) ... At 64 devices, 12,779,520 bytes (12.2 MiB)" | "67 entries ... 205,824 bytes (201 KiB) ... 13,172,736 bytes (12.6 MiB)" |
| §12, a reader's rows | "That is 132,672 + 5,120 + 4,096 + 3,072 + 5,760 + 64 = 150,784 bytes for each signer, and 9,650,176 bytes (9.2 MiB) for 64 signers, however much they write." | adds 6,720 for the person's reads not held and 5,014 for the bounds: "... = 162,518 bytes for each signer, and 10,401,152 bytes (9.9 MiB) for 64 signers", with 56 bytes for each message held and each key whose list of a person's reads names it (decision 2026-10-25, section 7) |
| §13 | `a_device_never_has_more_than_sixty_five_slots`: "leave 65 of its entries in the channel" | `..._sixty_seven_slots`, with a person's reads and a bound among what it does: "67" |
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

**Elsewhere.** The threat model's T22: rule 5's sentence; and "and not from `log` or `read`" becomes "and not from `read`; from `log` only by its list of a person's reads, which `log` names". The table of constants in `CLAUDE.md` gains section 4's rows.

## 6. Set aside, and why

- **A bound in the configuration.** A file that an agent can write is not a person at a terminal.
- **A bound for every pair at once.** Every other pair keeps its guard against a loop.
- **A bound per device.** Section 2.
- **Telling a person from a program beyond the terminal.** Rule 5.
- **Listing again what another device says you read.** `log` names the device and the count (rule 1); a way to show those messages can follow.
- **A held pair in `cordelia status`, or on its line.** The line is for sync (§8 there). A hold is said to the agent that is held, and `log` shows what waits.
- **Carrying bounds across a statement.** Rule 3.7.
- **A pair as a hash in the list of bounds,** which would fit about 52. A reader would have to find the names to say a bound in `cordelia status`. Names fit 4 at the longest and 22 at names of 30 bytes, and a full list names its pairs (rule 2).
- **A number for each bound, one above the highest held for its pair** (the review's way). Two acts that had not heard of each other would then go by their numbers, not their times, so an act made later could lose. Rule 3.1's `set` orders by what was heard first and by the clock after.
- **A person's read in the agents' list,** with a name that no agent has. It would be silent on the version before, but 120 marks would serve two kinds, and the agents' reads would fall out twice as soon.
- **A person's read as a hash, as an agent's is.** It has no name to bind, and the entry is sealed.

## 7. What it costs

- **At a relay:** two entries more for each device in each generation, 6,144 bytes as counted. A device has 67 slots, 205,824 bytes (201 KiB); 64 devices 13,172,736 bytes (12.6 MiB), under a channel's 16 MiB.
- **Pushes:** a list of a person's reads after each yes, and a list of bounds after each `allow` and each change of rule 3.5, each pushed at most once each two seconds (`OUTBOX_FLUSH_INTERVAL_SECS`).
- **What a relay learns:** when a person reads at a terminal and when a bound is set, by when the lists are pushed; and that each device has two slots more. Nothing of what is in them.
- **On a device:** for each key that counts, a row of 56 bytes for each message held that its list names; at most 120 rows of messages not held (6,720 bytes); and its bounds, at most one list's 1,934 bytes and 40 for each bound's key and first holding, 77 at the most (5,014 bytes). Property 21's 150,784 bytes for each signer become 162,518, and 10,401,152 bytes (9.9 MiB) for 64 signers, with 56 bytes more for each message held and each key whose list names it. A list of bounds is listed 7 days and 10 minutes, so a device holds the pairs set in the last week.
- **The schema's step 20,** and one read of the lists held, at the first start after it. Going back from it is by the copy, as from step 19 (§9.2 there).
- **On a device of the version before:** a count of entries that were not messages, in `log`, which grows until it takes this version.
- **The tests** of rules 1 to 5.

## 8. After its review

The first form (commit 2160a7f3, pull request #212) had one independent review: one high, six medium and eleven low findings. The high and every medium were settled; the lows were taken where they were right.

| # | Level | Finding | Settled |
|---|---|---|---|
| H1 | high | A 10 could lose to an older bound that it had not heard of; an older bound could come back from a relay that was behind | Settled with M1. `allow` is refused before the first fetch (refusal 5) and with sync off. Every bound a device sets, a 10 among them, is listed for 7 days and 10 minutes after its `set`, or until a later one for its pair is held (rule 3.5, `AGENT_MESSAGE_PAIR_BOUND_LISTED_SECS`). A listed 10 is the usual hold in the look and the status. Room: a list holds as many as fit, and a full one names its pairs (rule 2). Both tests added (rule 3) |
| M1 | medium | The order was by the clock, so a later act could lose; a bound whose start was ahead was unclear | `set` is the clock, or one second after the latest `set` held for that pair: what was heard of first is ordered first, whatever the clocks say; only two acts that neither had heard of go by the clocks, as said (rule 3.1, 3.2). A bound holds from when it is held, and its end alone uses the first holding (rule 3.3). The review's numbers were weighed and set aside (section 6) |
| M2 | medium | A restored store's own later list of bounds was not said | It replaces the device's own rows, in the door's write; nothing is set before the first fetch (rule 2). Test added |
| M3 | medium | A device's list of a person's reads hides messages from `log` on every device; the record of 2026-10-09 and T22 say it cannot | Said in rule 5; `log` names on which device you read what it does not show (`<where>`, rule 1); the sentences of §7.2, §11 and T22 listed (section 5). Test added |
| M4 | medium | The limit named a pseudo-terminal, not the routes, which need none | Rule 5's sentence names the token and the routes; tests `the_route_sets_a_bound_with_no_terminal` and `the_route_marks_with_no_terminal` |
| M5 | medium | Lists stored by the version before are never read after the upgrade (`take.rs:226-232`) | Read once at the first start after step 20, before the count is set to 0; the notes say that 0 clears a real count too (rule 1). Test added |
| M6 | medium | `allow X --all any` says only the hourly limits stop sending, but X's other held pairs still stop `--all`; `allow X Y any` does not free X's `--all` | The first is right: the question for `--all` says so (rule 2). The second is not: the words for X and Y speak of sending between X and Y, which they free, and X's `--all` is the pair of X and every agent |
| L1 | low | First holding stamped again at each list lets a bound run twice its time | Kept for each bound across later lists (rule 3.3); test extended |
| L2 | low | Form 4's checks: `a` and `b` order, the kind, a kind 2 with a `b`, a bad newer list | Taken, but `a` equal to `b` is a pair (`pairs_with`, `messages.rs:1061` in storage), so only `a` above `b` is refused; a kind 2 has no `b` field to carry, and bytes past its end fail the checks. A bad newer list drops that key's bounds (rule 2) |
| L3 | low | The `for` of a 10, and `10 --for`, unstated | A 10 carries 604,800; `--for` with 10 is not used, as rule 2 said (rule 3.3) |
| L4 | low | "1 messages"; "until your user reads them" untrue where they expire; `allow` in the help | The singular, ", or they expire" (rule 4); `allow`'s help line begins "For a person at a terminal:" (rule 2). A lower bound that ends is your act, and is left unsaid |
| L5 | low | With sync off, or beside the version before, the words are untrue | `allow` is refused with sync off; `log` says that sync is off (rule 1); the help and the notes say what an older device does not hear |
| L6 | low | Ended bounds take places unseen; "allow its pair 10" frees nothing | The full list's refusal names each pair and when it leaves, and a pair held can be set again in its place (rule 2, rule 3.6) |
| L7 | low | 64, and 3,360, were overstated or one-sided; `any` overwrites the ring | The reason for 64 is said rightly; 6,720 for two folders; the ring in three hours (rule 2, section 2, section 4) |
| L8 | low | A key's rows came back or not by when the hourly task ran | Dropped in the statement's transaction (rule 1, hard cases 3 and 4) |
| L9 | low | Rule 2's real-process test could not pass as written | The pair's count across both devices; each side sends five, under the folder's rate (rule 2) |
| L10 | low | §5 missed sentences of the record of 2026-10-09 | Added: three forms, 65 entries, H and the lists, 65 slots twice, §7.2's `log`, §11's holder of the key, the test of 65 slots, §9.2's first-start step, T22 |
| L11 | low | For the build: `set` named twice; one count of lists sent again; `marks::answered`; `pairs_with` needs the keys; the route's own checks | The route's field is `yes`; each list counts apart and `answered` matches its slot (rule 1); `pairs_with` is passed the keys (rule 1); the route checks again, with its test (rule 2) |

**The check of the revision** (commit 58c57c3d) found every finding above settled, and no new way to end or raise a hold beyond rule 5. It found two medium and five low findings, each an edge, each taken at its least change.

| # | Level | Finding | Settled |
|---|---|---|---|
| 1 | medium | A restored store could still bring back an `any` it had ended, where a relay answered another to its list, or lose what you set after the restore, where its later list came late | Its own later list is merged by pair, the later `set` kept, and an own bound the later list lacks is kept only where it was set since this start; at a relay's answer of another, the device first drops its own bounds set before this start (rule 2). Test added |
| 2 | medium | A clock far ahead made a bound hold longer, and the one second spread it to every later bound of the pair | Each bound carries `at`, its device's clock at the yes, beside `set`: `set` orders, `at` times its end and its listing, by the device's own clock (rule 3.1, 3.3, 3.5); 4 bounds at the longest names still fit (1,706 bytes). What is left is said: a bound whose `at` is more than 7 days ahead can hold, for its `for` at most, on a device that first gets it late from a relay that is behind. Test added. The first case as written does not arise, since the setter counts its 7 days by its own clock; the second, and a device that holds it late, do |
| 3 | low | `set` signed or unsigned, and its one second at the top | Unsigned; the one second stops at the top, where two tie and 3.2's tie decides, so your 10 beats an `any` there (rule 3.1). Test added. A `set` far ahead is not refused: it orders and times nothing else now, and only a holder of a key writes one at the top |
| 4 | low | The first-start read could be marked done unread, on a device that does not stand applied | Done where it stands applied, or at its first pass after it does; the read, the 0 and the key of `node_meta` in one transaction, before any route of messages answers (rule 1) |
| 5 | low | A later version that changed form 4 would have this version drop its 10s | A change takes a new form byte, and a form this version does not know leaves that key's bounds as they were; a form 4 that fails its checks still drops them (rule 2) |
| 6 | low | How `<where>` joins three or more | This device first, the rest in order of label, joined with ", " and " and " (section 1) |
| 7 | low | §5 missed §12's figure of a reader's rows | Added, with the figure of section 7 (162,518 for each signer) |

**The review of the build** (pull request #215) found one medium and four low findings (rows 2 to 5 are its lows 1 to 4).

| # | Level | Finding | Settled |
|---|---|---|---|
| 1 | medium | A relay that answers another could end a 10: the device dropped every own bound of before its start, whatever revision the answer named, however often, and even where it then wrote nothing; another device's older `any` then held everywhere | It acts only on an answer to the list it holds, within its three, where it may write; and of its own bounds of before the start it drops only those that allow more than the usual hold (rule 2). Test `a_relay_that_answers_another_cannot_end_a_ten` |
| 2 | low | A bad list of the device's own key left its own bounds, though the record said that key's bounds go | Kept, and said: the device's own bounds are its person's acts (rule 2) |
| 3 | low | Four rules had no test that caught them undone: a person's read of another device going with its message's row; the device's own key in the answer of another; the tie by key; the list of bounds counting its writes again apart | A test for each |
| 4 | low | The look for 0 and 1, the question's "1 wait now", and a `--for` given with 10, which the command refused for its time | The words are said in full (rule 2), "1 waits now" in both, and a `--for` given with 10 is not read |
| 5 | low | The status could count before the lists held from before step 20 were read | Left: the status writes nothing of its own (its test, `test_a_devices_status_identity_and_metrics_count_nothing_of_the_older_kind`), and the node reads the lists at its start, before its server answers, and at each pass, before it writes a list |
