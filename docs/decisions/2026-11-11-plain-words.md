# Decision: plain words in the command line

**Date**: 2026-11-11
**Status**: Proposed. The owner asked for plain words, and chose "reset", on 11 November. Not built: the slices of section 6 build it.
**Cited as**: "decision 2026-11-11 (plain words), rule 3".

## 0. Why

The owner, after clearing the warning `Shared: 1 shared channel not made anew since a removal: make each anew once with cordelia shared anew <name>`: "the language we use is very hard to understand still ... It feels like it could be much simpler".

The cause: the records' own terms leaked into what a person reads. Key, labelled, made anew, applied change 4, holds, keep or out, sealed, a removal, the six or four words: each is exact in a record, and hard at a prompt. The "say less" pass (#338) cut how much is said. This pass changes the words.

## 1. The rules

**Rule 1. Use everyday words a person already knows.** Device, not key. Named, not labelled. Up to date, not "applied change 4". Reset, not made anew. Section 2 gives each word.

**Rule 2. Name the thing.** Say the channel and the device by their names ("your old MacBook"), not by a count or by six words. Where a line would count several, name each, up to a few, then "and 3 more".

**Rule 3. Say what is wrong in plain terms, then give one command.** For example: `design-review: your old MacBook can still read it. To lock it out: cordelia shared reset design-review`.

**Rule 4. Fingerprint words, change numbers, relays' addresses and counts show only with `-v`.** The exception is where a person checks them to decide or to choose: the six words read back before you trust a device, and the words that tell apart two devices, or two channels, with one name. Where they are the only name a thing has, they are its name (rule 2): a relay's address in a line that warns of that relay, and the words of a device you have not named. A command that moves a fact behind `-v` and has no `-v` gets one.

**Rule 5. A question asks yes or no about one named thing.** `Keep "old MacBook" in design-review? Type yes or no.` Where a list is long, `no to the rest` answers no to this one and every one after it, as `out for the rest` did. No answer is suggested.

**Rule 6. Nothing a person must know is lost.** A limit (a reader you cannot see), a risk, or what a yes does stays. If plain words would hide a fact, keep the fact and say it simply.

## 2. The glossary

The old term may stay in code, in the records' rule text, in `--json` field names and machine values, and in the node's log. It goes from every line a person reads.

| Old | Plain |
|---|---|
| key (a device) | device; the string that `cordelia id` prints is the device ID |
| a key this device shows | a device this one knows |
| label, labelled, no label of yours | name, named by you, not named by you |
| make anew, made anew | reset; the channel it makes is the new channel |
| not clean | not reset since you removed (the device) |
| has applied change N, has sent what it held | up to date |
| change N, the last change | the last change to your devices; its number only with `-v` |
| holds, held (a device or relay) | has, keeps |
| held up (the node) | paused |
| a hold (of agents) | your agents wait for you |
| keep or out, out for the rest | yes or no, no to the rest |
| sealed to | only (those devices) can read it |
| a removal, since a removal | removing (the device), since you removed (the device) |
| six words, four words | fingerprint words: rule 4 |
| hand, hands over, handed | share, send |
| taken, nothing was taken | received, copied in, nothing changed |
| carry, carried | copy over, copied over |
| follows (a phrase, a change) | has, is on |
| made apart, set aside | made at the same time, ignored |
| past a bound | over the limit (say which limit) |
| generation | before the change of (its date) |
| let go | removed from this device |
| cleared (a notice) | confirmed |
| statement, slot, revision, chain, change entry, the personal channel, the look, a word (of a device, of the phrase) | never shown; say what it means for you |

A relay's key in the configuration file stays "key": it is the name of the setting.

## 3. The renames

- **`cordelia shared anew` becomes `cordelia shared reset`.** `anew` works as a hidden alias for one release, then goes. The local API's route (`/api/v1/shared/anew`) does not change.
- **The answers `keep`, `out` and `out for the rest` become `yes`, `no` and `no to the rest`.** The old answers still work for one release.
- No other command or flag is renamed in this pass: `label`, `renew`, `settle`, `sync carry`, `--words`, `--new-key` and `--clear` stay. The words around them change.

## 4. How the records change

Records' wording is checked by tests (CLAUDE.md, engineering rule 5). **When a line changes, the record's quoted line changes in the same commit,** and so does each test that quotes it. The rule text around the quote may keep its old terms. A record that quotes a line no test checks changes too, so that it stays true. Each record that changes adds to its Status line: "Its quoted lines amended by decision 2026-11-11 (plain words)." README, TESTING and the threat model change in the same slice where they quote a changed line.

## 5. `--json`

**Field names do not change:** the panels read them. Machine values do not change either (`what`, `state`, `level`, `stands`). Only the words a person reads change, among them the values of `summary`, `says` and `short`. A slice may add a field where a line must name a thing the node does not give yet, such as the name alone of the removed device; it never removes or renames one.

## 6. The slices

Most-seen first. Each slice is one pull request, with its records, tests and docs. The inventory of lines, kept outside the repository, is the working list.

1. **The status and its warnings:** `cordelia status` and its `Memory:`, `Shared:`, `Messages:`, `Devices:` and `Following:` lines, the status bar, and the lines the node says of your devices and relays.
2. **Devices, phrase and removal:** `devices`, `id`, `phrase`, `add-device`, `accept`, `remove-device`, `renew`, `settle`, `recover`, and `sync carry` after a removal.
3. **Sharing:** `shared list`, `share`, `accept --channel`, `shared reset` (with the rename and the yes or no), `shared move`, `shared seen`, `label`, `subscribe` and `.cordelia/members`.
4. **Messages:** `msg send`, `read`, `summary` and their refusals.
5. **Setup and help text:** `init`, `start`, `sync map`, `unmap` and `status`, `history`, `restore`, and every `--help`.

## 7. What does not change

- What a command does, and what it asks a yes for.
- Failures stay as loud as they are (#338).
- The six-word check before you trust a device.
- The wire, the schema, the log, and code names.

## 8. The test that holds it

Each slice adds its lines to one test, `the_plain_lines_use_no_old_words`. It renders the lines of its commands without `-v`, and checks that none says anew, labelled, applied change, holds, held, sealed, keep or out, out for the rest, or a removal. A word the glossary keeps for a reason is not on that list.
