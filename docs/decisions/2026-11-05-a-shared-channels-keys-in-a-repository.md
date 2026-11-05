# Decision: a shared channel's keys in a repository

**Date**: 2026-11-05
**Status**: Proposed. Not built: after R1. To be reviewed before it is built.
**Cited as**: "decision 2026-11-05 (members), rule 3". The numbers do not change.

Words used throughout:

- **The shared channels record** is [`2026-10-10-a-shared-channel-for-messages.md`](2026-10-10-a-shared-channel-for-messages.md). Its sections are cited "§7 there".
- **A member** is a device that holds the shared channel. **The person** is the one who runs the command, at a terminal.
- **The list** is the file of rule 1. **The table** is a device's table of the keys of a channel (§6.3 there): the keys it has held an entry of, with when it first held one.
- **Main** is commit 2007aee6 (`v0.2.0-alpha.18`). Examples say laptop and desktop, and `github.com/example/project`.

---

## 0. What this is, in one page

The person asked, on 5 November, for the way a team joins a shared channel: anyone raises a pull request against a repository to have their keys added, and once it is merged they are in. The shared channels record put this off to a later record (§14 there, item 16, S17). This is that record, in the simplest form that sits on what `v0.2.0-alpha.18` already has.

- **The list is a file in the repository,** `.cordelia/members`: one line for each device, its key and a label.
- **Joining is a pull request** that adds your lines. **Merging it is the yes.** Whoever can merge to that branch decides who is in: the repository's own rules (required review, CODEOWNERS on `.cordelia/`) are the channel's.
- **A member carries the list out with one command,** at a terminal, in a clone: `cordelia shared members <name>`. It hands the channel to each listed key that is not in it yet, and makes the channel anew without each key in it that the list no longer names. Both are what `cordelia share` and `cordelia shared anew` do today. Nothing changes on the wire, at a relay, or in what a reader shows.
- **For a key the list names, the list takes the place of the six-word check** of `share` (§3.2 there).
- **Nothing happens by itself.** The node never reads a repository, and the command never fetches. A change to the list takes effect when a member runs the command.

Until it is built, the same flow works by hand: a pull request adds the lines, and once it is merged a member runs `cordelia share <name> <key>` for each new key.

---

## 1. The file

```
# The devices whose agents share this repository's channel.
repository github.com/example/project
branch main

cordelia_pk1...   alice-laptop
cordelia_pk1...   alice-desktop
cordelia_pk1...   bob-laptop
```

- **Its place:** `.cordelia/members`, at the root of the repository.
- **Its form:** ASCII and line feeds only, at most 16 KiB. A line that starts with `#`, and an empty line, are skipped.
  - One `repository` line: the host, owner and name, as `host/owner/name`.
  - One `branch` line: the branch's short name.
  - Then one line for each device: its key as `cordelia id` prints it, one or more spaces, and a label of 1 to 32 characters of `a-z`, `0-9`, `.`, `_` and `-`.
- **Keys are unique, and so are labels.** At most 64 keys (`SHARED_MAX_KEYS`): a channel shows no more (§2.4 there).
- **A file that does not parse does nothing:** the command names the line and stops.
- **List every device that will write,** not one for each person. Each device signs with its own key, and a person's devices all hold their shared channels (§3.4 there).
- **A label is the person's word and should not name a machine.** A list may be public, and a host name is a detail people keep to themselves.

## 2. Where the command reads it

- **Only from what git has fetched,** never from the working tree, a local branch or `HEAD`. The command runs `git` with fixed settings: no fetch, no prompt, no pager, no replaced objects, no hooks.
- **Which remote.** It takes each remote of the clone whose address has one of three forms: `https://<host>/<owner>/<name>`, `ssh://git@<host>/<owner>/<name>` or `git@<host>:<owner>/<name>`, with or without `.git`. It reads nothing else: no port, no other user, no query. It compares `host/owner/name` in lower case. A remote whose address has another form counts for nothing.
- **Which commit.** For each such remote, the branch is the one the clone recorded as the remote's default (`refs/remotes/<remote>/HEAD`). The command reads the file at that remote branch, and takes it only where the file's `repository` line names that remote's address and its `branch` line names that branch.
  - So a fork, a mirror or another branch counts for nothing, whatever the clone calls it.
  - Two remotes that both give the file must give the same commit, or the command stops and says so.
  - With none, it says so, and names `git remote set-head <remote> --auto`.
- **It shows the commit** it read: its hash, its date and its subject. The person can check it against the host.

## 3. What the command does

```
alice@laptop$ cd ~/Work/project
alice@laptop$ cordelia shared members design-review
```

It runs at a terminal, with one yes, for a shared channel the person holds under that name. `--repo <folder>` names the clone where it is not the folder it runs in.

1. **It reads the list** by rule 2.
2. **It leaves the person's own devices alone,** listed or not. They hold the channel whatever the list says (§3.4 there).
3. **To hand it to:** each listed key that is not in the table.
4. **To leave out:** each key in the table that the list does not name.
5. **It shows both lists,** each key with its label from the file (marked as the file's), the first words of its key and the six words of `share`. It shows the commit, and says: `These keys come from <host/owner/name>, branch <branch>, at <commit>. Whoever can merge to that branch decides who is in.` Then it asks its yes.
6. **After the yes:**
   - it hands the channel to each key of step 3, as `share` does. Nobody reads six words to anyone: the list is the check;
   - it labels each listed key that has no label of the person's, with the file's label, as `cordelia label` does, so members are shown first and framed by name (§2.4 there);
   - where step 4 found any key, it makes the channel anew, as `shared anew` does: every listed key in the table stays, with the person's own devices, and every other key is left out. The answers come from the list, not typed key by key. Those who stay move as they do today.
7. **Where both lists are empty,** it says so and asks nothing.

## 4. A clone that is behind

A member whose clone has not fetched the latest list must not undo what a newer list did. The command compares the commit's date with what this device saw itself, with ten minutes' margin for clocks:

- **A key that a making anew left out after the commit** is not handed the channel from that list.
- **A key that this device first held an entry of after the commit** is not left out by that list.

Each such key is shown with `Your clone is older than what happened here: run git fetch, then this again.` The rest of the plan goes ahead.

## 5. Joining, and leaving

- **Joining.** The new member runs `cordelia id` on each device that will write, and raises a pull request that adds a line for each. Once it is merged, a member runs the command. The new member then runs `cordelia accept <key> --channel <name>` on the device that was handed it, with that member's key from the file. `accept` checks that the share is signed by the key typed (§3.2 there), and the file is where the key came from.
- **Leaving.** A pull request deletes the lines. Once it is merged, a member runs the command, and the channel is made anew without them. Until a member does, they still read and write.
- **One device of a person who stays cannot be left out this way.** That person's other devices hold the new channel, and their own devices share what they hold (§7 there). The device goes when that person removes it from their own devices.

## 6. What it does not do, and what comes later

- **The node does not read the list by itself.** The first design (1 October) had the node carry the list out on its own, with an hour's wait before a new key got in, and a record in the channel of who let whom in. That waits until this is in use.
- **`accept` does not read the list.** Later, `accept --channel <name>` could take a share from any key the list names.
- **`subscribe` does not print this device's line.**
- **One list for each repository.** Later, `.cordelia/channels/<name>` could hold a narrower list, with its own rules on who may change it.
- **A channel stays flat.** A member can still hand it by hand to a key the list does not name. The next run of the command by any member makes it anew without that key.

## 7. Who can do what

- **Whoever can merge to the branch** admits any key, and removes any. That is the point: the repository decides. A stolen account with merge rights is the same.
- **The host** decides what the branch is. A member who fetches takes it.
- **A program that runs as a member** can rewrite what git records as fetched, and so the list the command reads. It can already run `share` with a yes (the README's security section). The commit shown is the person's check.
- **A list in a public repository** shows its keys and labels. It does not let anyone read the channel: that still needs a member to hand it over.
- **Labels from the file** are shown as the file's, beside the start of each key.

## 8. Tests, when it is built

- A list read only from the remote branch: an edit in the working tree, a local branch or a fork's remote is not read.
- An address of another form, a `repository` or `branch` line that does not match, two remotes on different commits: each stops, and says why.
- A file over 16 KiB, over 64 keys, with a key or label twice, or a line that does not parse: nothing is done, and the line is named.
- A new key is handed the channel; an unlisted key is left out by a making anew; the person's own devices are neither.
- A clone behind a removal does not hand the key back; a clone behind an admission does not leave the key out.
- The yes names the commit, and nothing happens without it; the command refuses without a terminal.

## 9. Questions for the person

1. **Labels at the yes** (rule 3, step 6). Proposed: yes, so members are shown by name. The other way, a person labels each key by hand.
2. **Is the file's name right?** `.cordelia/members`, one for each repository, as the first design had it.
