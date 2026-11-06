# Decision: joining a repository's shared channel by pull request

**Date**: 2026-11-06
**Status**: Proposed, for review. Revised once after its first review (section 13). For `v0.2.0-alpha.19`: the person ruled on 6 November that it comes now, not after R1 (issue #293). It needs #291 (#296) first.
**Cited as**: "decision 2026-11-06 (joining), rule 4". The numbers do not change.

Words used throughout:

- **The shared channels record** is [`2026-10-10-a-shared-channel-for-messages.md`](2026-10-10-a-shared-channel-for-messages.md), cited "§7 there".
- **The members record** is [`2026-11-05-a-shared-channels-keys-in-a-repository.md`](2026-11-05-a-shared-channels-keys-in-a-repository.md). This record keeps the idea of its file, adds one line to it, and replaces its command: `cordelia shared members` is not built.
- **The list** is a repository's `.cordelia/members`. **A repository channel** is the shared channel that a list names.
- **A member** is a device that holds the channel. **In the channel**, for a key, means: in this device's table of the channel's keys, or not moved yet (#291).
- **A read** is one reading of the list by a device that follows the repository (rule 3).
- **Main** is commit 89b2397f. Examples say laptop and desktop, Alice and Bob, and `github.com/example/project`.

---

## 0. What this is, in one page

The person's rule: **a merged pull request is the whole join.** No `share`, no `accept`, no hour to hit, and no wait that does not say what it waits for.

**The list names the channel and its members:**
```
channel 9f2c...e41a cordelia_pk1... cordelia_pk1...
cordelia_pk1...   alice-laptop
cordelia_pk1...   bob-laptop
```

**What a person does:**
- **To start a team's channel, once:** `cordelia subscribe --new` in a clone. It makes the channel and prints the `channel` line. A pull request adds that line and the maker's devices.
- **To join:** a pull request that adds a line for each of your devices. Once it is merged, run `cordelia subscribe` in your clone, once, and type yes.

**What the nodes then do, with no one asked.** Each device that follows the repository reads the list every ten minutes.
- A member's node hands the named channel to each listed key that is not in it.
- The new member's node takes the named channel from any listed key.
- Each join shows on every follower's status, with its label and commit, until a person clears it.

**Leaving stays by hand for now.** A pull request deletes the lines. Then a member runs `cordelia shared anew <name>`, which leaves the dropped keys out. A pull request then puts the new channel's line in the list. Until it is merged, nobody hands the new channel to anyone.

**Nothing new on the wire or at a relay.** A hand-over is today's share, and a take is today's `accept --channel`, each run by the node in place of a person.

---

## 1. The list

- **Its place:** `.cordelia/members`, at the root of the repository, on its default branch.
- **Its form:** ASCII and line feeds only, at most 16 KiB. `#` lines and empty lines are skipped.
- **One `channel` line:** `channel`, the channel's ID in hex, then the key of each of its relays, one or two (a card's relays, §8 there). A list without one names members and no channel: followers wait, and say so.
- **Then one line for each device:** its key as `cordelia id` prints it, then a label of 1 to 32 characters of `a-z`, `0-9`, `.`, `_` and `-`.
- **Keys are unique, and so are labels.**
- **At most 64 keys,** less the person's own devices that the list does not name.
- **A file that does not parse does nothing:** the last list read stands, and the status names the line.
- **List every device you have.** Every device of yours holds your shared channels and writes in each (§3.4 there).

## 2. Following a repository: `cordelia subscribe` in a clone

```
bob@laptop$ cd ~/Work/project
bob@laptop$ cordelia subscribe
```

**With no name, in a folder of a git repository, `subscribe` follows that repository.** It needs a terminal and one yes. The folder must be mapped, as for any agent: otherwise it says to run `cordelia sync map .`, and does nothing.

1. **The repository's identity** is `host/owner/name`, in lower case, from a remote of the clone. The remote's address must have one of four forms:
   - `https://<host>/<owner>/<name>`
   - `ssh://git@<host>/<owner>/<name>`
   - `ssh://<host>/<owner>/<name>`
   - `git@<host>:<owner>/<name>`

   With or without `.git`; nothing else, and no port.
   - With one such remote, it is the one.
   - With several that differ (a fork's `origin` and the repository's `upstream`), `--remote <name>` chooses. Without it, the command names them and does nothing.
   - The host must be reachable as HTTPS. An SSH alias such as `github.com-work` is refused, with a line that says why.
2. **It reads the list** by rule 3, and shows:
   - the identity and the commit;
   - the channel the list names;
   - whether this device's key is on the list.
3. **Then one of these:**
   - **The person holds the channel the list names:** it follows the repository and subscribes this folder's agent.
   - **They do not, and the list names this device:** it follows the repository and waits to be handed the channel (rule 4). The yes says: `This follows <identity>. A member's device hands you its channel once it reads the list. cordelia status shows how it goes.`
   - **The list does not name this device:** `Your key is not on the list of <identity> at <commit>. Add it with a pull request, then run this again.` Nothing is done.
   - **The person dropped that channel:** the yes also says `You dropped this channel. This takes it back.`, and the drop that is kept for it goes (§3.4 there).
4. **`cordelia subscribe --new`** makes the channel for the team, once, at the person's relays, as `shared new` does. It is filed under the repository's `owner/name` (or `--as <name>`). It prints the line to add, and the person's own keys and labels:

   ```
   Add these lines to .cordelia/members in a pull request:
   channel 9f2c...e41a cordelia_pk1...
   cordelia_pk1...   <label>
   ```

   It is refused where the list names a channel already.
5. **What the device keeps** is a row of its own: the identity and the clone's path. It is keyed by the identity, not by a channel's name. The list says which channel the repository's is, so a rename, a making anew or a move changes nothing in the row. `shared drop` of the channel the list names stops the follow. A device that leaves its person deletes every row.
6. **One device of the person's that follows is enough.** Every follower, of every person, does the work of rule 4 for the team. Each device of yours that should read the list for you runs `subscribe` in a clone once.

## 3. Reading the list

**The node reads the clone's own copy of the default branch, and fetches a public repository itself.**

- **From the clone, read only.** It reads `refs/remotes/<remote>/<branch>`, the default branch as the person's own git last fetched it. `<branch>` is the one that `refs/remotes/<remote>/HEAD` names, and the remote must still have an address that names the identity. It reads the file with `git cat-file blob`, and never touches the working tree, a local branch, the clone's refs or its files.
- **Fetching, for a repository anyone can read.** Every ten minutes (`MEMBERS_READ_INTERVAL_SECS`), and at the node's start, the node fetches `HEAD` of `https://<host>/<owner>/<name>` into a repository of its own, `~/.cordelia/repos/<host>/<owner>/<name>.git`. It uses `--depth 1 --filter=blob:none`, then reads the one file.
- **No setting of the person's reaches it, so nothing can ask:**
  - git runs with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_ALLOW_PROTOCOL=https`;
  - there is no credential helper, so no keychain, keyring, Git Credential Manager or browser is ever asked;
  - with no `insteadOf`, a fetch is never made SSH;
  - `http.followRedirects=false`;
  - `GIT_TERMINAL_PROMPT=0`, and no askpass;
  - hooks, `gc` and maintenance are off;
  - git is stopped after sixty seconds (`MEMBERS_FETCH_MAX_SECS`), by TERM, and the node clears its own repository's locks.
- **A private repository is not fetched by the node.** It needs credentials, and every way to give them can ask. Its list comes from the clone, as the person's own `git fetch` or `git pull` brings it. The status says how old it is: `list of <identity> read from your clone, fetched 2 hours ago`.
- **A redirect** (a repository renamed or moved) ends the fetch. The status says `<identity> has moved: run cordelia subscribe in a clone of it again`.
- **A read never goes back.** A list counts only where its commit is the last commit read, or comes after it: `git merge-base --is-ancestor`, run in the node's repository or in the clone. A clone left behind, or a history rewritten, gives no new list, and the status says so.

## 4. What a node does with the list

At each read, each device that follows the repository does the following, with no one asked.

1. **It acts only for the channel the list names, and only where it holds that channel and writes there:** not paused, clean, and not moved from (§7 there). Otherwise it hands over nothing and takes nothing, and says why (rule 5).
2. **Hands over.** Listed keys not in the channel, not the person's own devices, and not keys the person removed, are handed the channel, as `share` does. They go **eight at a time, in turns** (`MAX_TYPED_KEYS`):
   - each read first deletes the shares this device left at the last read;
   - it then hands over to the next eight such keys, in the list's order, starting after the last one handed;
   - so a device that is off for days holds no place.
3. **Deletes the shares to keys the list no longer names,** whether the node made them or a person did.
4. **Takes.** A follower whose person does not hold the named channel looks for a share from each listed key, at each read.
   - It types each listed key again for that read, under a count of its own, so the person's own `accept --channel` keeps its eight places.
   - It takes only the named channel, from a listed key, once the list names this device.
   - It takes only a share made within the hour of the latest read (`PAIR_KEY_TYPED_SECS`), so a share left at a relay long ago is not taken.
   - It files the channel on every device of the person's, as `accept --channel` does.
5. **Says a key joined.** A key that first writes in the channel while the list names it shows amber: `<label> joined <name> from the list at <commit>`. It stays until a person clears it on that device with `cordelia shared seen <name>`.
6. **Says a key was dropped.** A key in the channel that an earlier read named and the latest does not shows amber: `<label> is no longer on the list of <name>: make it anew with cordelia shared anew <name>`.
7. **Says a key is not listed.** A key in the channel that no read named, such as a device a member added later and did not list, shows on a line of its own, not amber: `<form> writes in <name> and is not on its list`. `cordelia shared seen <name>` clears it.

## 5. Making a repository channel anew

**`cordelia shared anew <name>` on a repository channel refuses to leave out a key the list names:** `<label> is still on the list: delete its line in a pull request first`. It leaves out only keys the list does not name. Its yes ends with the line to put in place of the old one:
```
Put this line in place of the channel line of .cordelia/members, in a pull request:
channel <new ID> <relay keys>
```

**Until that pull request is merged, the list names the old channel:**
- followers that moved hand over nothing (rule 4.1);
- followers that have not moved hand over only the old channel, which every key it was shared with could read already.

**So a key left out is never handed the new channel.** That holds where a member made it anew before the pull request that drops the key. It holds too where a removal made it anew without a stolen device that is still listed.

**A removal** makes each shared channel anew as today (§3.5 there). For each repository channel it shows amber until the list catches up: `<name> was made anew at a removal: put its new channel line in .cordelia/members, and delete the removed device's line`, with the line.

## 6. No silent waits

Every wait says what it waits for, in `cordelia status` and `cordelia shared list`. Each line is the word that today's command would refuse with, put plainly.

| Who | It says |
|---|---|
| A follower not on the list | `Your key is not on the list of <identity> at <commit>.` |
| A follower, the list naming no channel | `The list of <identity> names no channel yet.` |
| On the list, not yet handed it | `Waiting for a member's device to hand you <name>. Your list was read <when>.` |
| The channel's relays not among the person's own | `<name> is at <relay>, which is not one of your relays: add it to your configuration.` |
| No room for one more channel, or its name taken | `You hold 16 shared channels, the most there can be`, or `You file another channel as <name>: run cordelia subscribe --as <other>.` |
| A member handing over | `Handing <name> to <label>: waiting for that device to take it.` |
| A member who cannot | `<name> is paused`, `not clean`, `not reached at its relays`, or `full`: `nothing is handed over until then.` |
| A member who moved | `The list names the channel you moved from: put the new channel line in .cordelia/members.` |
| The list, from the clone | rule 3's line, with how old it is |
| Nobody of yours follows | `No device of yours reads the list of <name>: run cordelia subscribe in a clone of <identity>.` |

## 7. What `cordelia status` shows

For each repository channel:
- **its name and identity;**
- **when the list was read,** where from, and the commit;
- **the members, by the list's labels,** each in or not yet;
- **what waits:** messages unread by the person and by an agent;
- **any line of rules 4 to 6.**

The notices of rules 4.5 to 4.7 show only on devices that follow the repository. The fingerprint words show only with `-v` (#228).

## 8. An agent that is not in a clone

**One kind of agent: a mapped folder.**
- **A session in any folder of the clone** is the repository's agent, and sees the channel once `subscribe` has run there.
- **Any other agent** subscribes with `cordelia subscribe <name>`, as today: a workspace above several clones, home, or a folder kept for the purpose. It must be a mapped folder.

**Turned down: a mailbox folder that Cordelia makes for each channel** (`~/.cordelia/shared/<channel>`), with hooks that name the channel.
- It would be a second kind of agent, with no folder that a session runs in.
- Its hooks would name channels instead of folders.
- Mapping a folder already gives an agent, and a mapped folder's memory goes only to the person's own devices, never into a channel (§0 there).

## 9. What comes over from today

- **Nothing is carried over.** A channel made by `shared new` stays as it is, shared by hand. A repository channel is made with `subscribe --new`, and its first members join by the list.
- **`share` and `accept --channel` stay** for a channel shared by hand, with their six words.
- **The members record's command is not built.** Its leaving half is rule 5.

## 10. Who can do what

- **Whoever can merge to the default branch** admits any key, at once, and names the channel. That is the person's rule: the repository decides. Each join shows on every follower's status (rule 4.5), and a stolen account with merge rights is the same as its owner.
- **The host** decides what the branch is. A public repository is reached over TLS. A private one is reached by the person's own git.
- **A program that runs as a member** can change the clone or the node's own repository, and so the list. It can already run `share` with a yes (the README's security section). Each join's notice names the commit, for the person to check.
- **A list in a public repository** shows the channel's ID, its relays, its keys and their labels. None of it lets anyone read the channel: that needs a member to hand it over.
- **A member can still hand the channel to a key that is not listed,** by hand: a channel stays flat. Rule 4.7 shows that key on every follower.
- **The reader shows listed keys as it shows any other key** (§2.4 there). They are not labelled for the person, and share the hour and the room of keys the person does not know (§6.3 there), until the person labels them.

## 11. Constants

| Name | Value | Why |
|---|---|---|
| `MEMBERS_READ_INTERVAL_SECS` | 600 | As `RELAY_ASK_AGAIN_SECS`: a join waits about ten minutes on each side once the list is read |
| `MEMBERS_FETCH_MAX_SECS` | 60 | A fetch that has not ended by then is stopped |
| `MEMBERS_FILE_MAX_BYTES` | 16,384 | The members record, rule 1 |

## 12. Tests

Real-process tests, with a git repository served over HTTPS on loopback, and a clone of it:

**The join itself**
- **Two people, the whole join.**
  - Bob runs `subscribe --new`, and its lines are merged.
  - Alice's line is merged, and she runs `subscribe`.
  - Within two reads, Alice holds the channel and sends a message that Bob reads.
  - Bob's status shows `alice-laptop joined ...` until `shared seen`.
  - Nobody runs `share` or `accept`.
- **Order does not matter.** Alice subscribes before the merge, and waits, saying so. Then the merge comes, and she joins.
- **A private repository.** No fetch is made: the list comes from the clone, and the status says how old it is.

**Never asked, and never back**
- **Nothing asks.** The person's git configuration is set to ask in each way: a credential helper that would ask, an `insteadOf` to SSH, askpass, and a redirect. Each fetch either goes over HTTPS without asking or fails, and no prompt opens.
- **Identity.**
  - A remote changed to a fork is not read.
  - With two remotes, `--remote` is needed.
  - A list in the working tree or on a local branch is not read.
- **A read never goes back.** A clone behind the last commit read gives no new list.

**Who gets the channel**
- **Only the named channel.**
  - A share of another channel from a listed key is not taken.
  - A share from an unlisted key, or one older than the hour of the latest read, is not taken.
  - A key not on the list is never handed the channel.
- **Leaving.**
  - A key dropped by a merge shows amber on every follower.
  - `shared anew` refuses while its line stays, then leaves it out and prints the new line.
  - Before that line is merged, nobody hands the new channel to anyone.
  - After a removal, a removed device that is still listed is never handed the new channel.
- **Turns.**
  - Nine new keys, with eight of them off: the ninth is handed the channel at the next read.
  - The taker's typings leave the person's eight places free.

**What it says**
- **Waits.** Each line of rule 6 appears where it should.

## 13. The review, and what changed

The first review, of commit 9bfd6647, found three high findings, eight medium and four low. Each was checked in the code before it was taken.

| # | Finding | What changed |
|---|---|---|
| H1 | A share holds only a card: "the first card taken is the repository's channel" could take another channel | The list names the channel and its relays (rules 1, 2.4); nodes hand over and take only that ID |
| H2 | A key that a making anew left out, before the PR that drops it, could be handed the new channel by a member who did not see the offer | `shared anew` refuses to leave out a listed key; nodes hand over only the channel the list names, so a new channel goes to nobody until its line is merged (rules 4.1, 5) |
| H3 | git reads the person's settings: `insteadOf` makes SSH, and credential helpers can open windows; WSL2 never passes `GCM_INTERACTIVE` | git runs with none of the person's settings, no helper and HTTPS alone; a private repository is read from the clone only (rule 3) |
| M1 | Eight places held by devices that are off; the taker's typings took the person's places | Hand over in turns, deleting the last read's shares; the taker types under a count of its own (rule 4) |
| M2 | Reads every ten minutes made the hour cover any wait | Take only a share made within the hour of the latest read (rule 4.4) |
| M3 | A clone behind could undo a newer list | A list counts only at or after the last commit read; shares to unlisted keys are deleted (rules 3, 4.3) |
| M4 | The joiner asks only at its own relays | The `channel` line names the relays; a wait for a relay not of the person's says so (rule 6) |
| M5 | Today's refusals left waits that said something false | Each wait carries today's word (rule 6); `subscribe` takes back a dropped channel |
| M6 | An unlisted device of a member's showed amber for ever | Amber only for a key an earlier read named; an unlisted key has its own line, cleared by `shared seen` (rules 4.6, 4.7) |
| M7 | A row keyed by a name went wrong at a rename or a drop | Keyed by the identity; the list names the channel (rule 2.5) |
| M8 | A redirect could follow a name someone else then took | No redirects (rule 3) |
| L1 | Reading FETCH_HEAD downloads the whole tree each time; a killed fetch leaves a lock | `HEAD` into a ref of its own with `--filter=blob:none`; TERM, then the node clears its own locks |
| L2 | A fork clone and SSH host aliases | `--remote`; an alias is refused, with why (rule 2.1) |
| L3 | Listed keys are strangers to the reader | Said (rule 10) |
| L4 | Notices show only on followers | Said (rule 7) |

## 14. Questions for the person

1. **`cordelia shared seen <name>`** clears the notices of rules 4.5 and 4.7, on each device: is the word right?
2. **The default name `owner/name`:** right?
3. **A private repository's list comes only from the person's own fetches,** because every way of giving the node credentials can ask. A read-only token in the node's configuration would let it fetch a private repository itself. Leave that for later?
