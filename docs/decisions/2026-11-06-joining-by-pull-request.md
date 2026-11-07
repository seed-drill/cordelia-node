# Decision: joining a repository's shared channel by pull request

**Date**: 2026-11-06
**Status**: Accepted by the person on 6 November ("go, yes to all three, leave the token for later"). Revised five times after its reviews (section 13). Amended on 7 November by the person's rulings: the node reads the clone only, and a channel follows one repository (section 14). Amended in building slice 7 and after its review: when rule 5's "from then on" starts, the end of its amber at `shared seen <name> <label>`, rule 6's line of a device that follows no list, the bound of 16 follows (rule 2.7), and a removal's drop past a bound (rule 5). To be built: a reviewed plan first. For `v0.2.0-alpha.19`: the person ruled on 6 November that it comes now, not after R1 (issue #293). It needs #291 (#296) first.
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
channel 9f2c...e41a cordelia_pk1... cordelia_pk1... without 0
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

**Leaving stays by hand for now.** A pull request deletes the lines. Then a member runs `cordelia shared anew <name>`, which leaves the dropped keys out and prints the new channel line, naming who it left out (`without ...`). A pull request then puts that line in the list. Until it is merged, nobody hands the new channel to anyone, and nobody ever hands it to a key the line names after `without`.

**Nothing new on the wire or at a relay.** A hand-over is today's share, and a take is today's `accept --channel`, each run by the node in place of a person.

---

## 1. The list

- **Its place:** `.cordelia/members`, at the root of the repository, on its default branch.
- **Its form:** ASCII and line feeds only, at most 16 KiB. `#` lines and empty lines are skipped.
- **One `channel` line:** `channel`, the channel's ID in hex, then the key of each of its relays, one or two (a card's relays, §8 there). It always ends with `without`, the number of keys that follow, and those keys: the keys a making anew left out (rule 5), or `without 0` for a new channel. A line whose number does not match its keys does not parse, so a line cut short does nothing. These keys do not count among the list's 64. A list without a `channel` line names members and no channel: followers wait, and say so.
- **A list that names a key as a member, and after `without`, while that key is not in the channel, names no channel for now.** Followers hand over nothing, and show rule 4.7's line, until that key's line is deleted, or until the key writes in the channel, as a device of a person who stays does when it is next on. So a key left out cannot stay listed. Bringing it back is a pull request that adds its line and takes it off `without`. A device that does not hold the channel cannot see who is in it, so the gate binds only those who hand over; a joiner still takes nothing while its own key is after `without`.
- **Then one line for each device:** its key as `cordelia id` prints it, then a label of 1 to 32 characters of `a-z`, `0-9`, `.`, `_` and `-`.
- **Keys are unique, and so are labels.**
- **At most 64 keys.** A channel that would hold more says so where it is handed over (`channel_full`).
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
   - **The person dropped that channel:** it says so and does nothing, as `accept --channel` refuses today (§3.4 there): `You dropped <name>, and a dropped channel is not taken again.`
4. **`cordelia subscribe --new`** makes the channel for the team, once, at the person's relays, as `shared new` does. It is filed under the repository's `owner/name`. It prints the line to add, and the person's own keys and labels:

   ```
   Add these lines to .cordelia/members in a pull request:
   channel 9f2c...e41a cordelia_pk1... without 0
   cordelia_pk1...   <label>
   ```

   It is refused where the list names a channel already.
5. **What the device keeps** is a row of its own: the identity, the clone's path, the last commit read, and the keys that read named. It is keyed by the identity, not by a channel's name. Running `subscribe` again, with a yes that names the commit, starts the row afresh, for a history that was rewritten. The list says which channel the repository's is, so a rename, a making anew or a move changes nothing in the row. `shared drop` of the channel the list names stops the follow. So does `cordelia unsubscribe` with no name, in a clone, with no yes: `This device follows <identity> no more.` It unsubscribes no agent and drops no channel, and `subscribe` there follows again. A device that leaves its person deletes every row. **A channel follows one repository.** Subscribing in a clone of another repository whose list names that channel replaces the follow, with a yes that says so: `This stops following <identity>, whose list names <name> too: a channel follows one repository.` A read of a list that names another follow's channel counts for nothing, and the last list stands.
6. **One device of the person's that follows is enough.** Every follower, of every person, does the work of rule 4 for the team. Each device of yours that should read the list for you runs `subscribe` in a clone once.
7. **A device follows 16 repositories at most,** as many as the shared channels it can hold (`SHARED_MAX_CHANNELS`). `subscribe` refuses one more: `This device follows 16 repositories, the most it can. To follow another, first run cordelia unsubscribe in a clone of one it follows. Nothing was done.`

## 3. Reading the list

**The node reads the clone's own copy of the default branch, and nothing else.** No git command of the node's reaches the network (the person, 7 November).

- **From the clone, read only.** It reads `refs/remotes/<remote>/<branch>`, the default branch as the person's own git last fetched it. `<branch>` is the one that `refs/remotes/<remote>/HEAD` names, and the remote must still have an address that names the identity. Where that ref is missing, as after a default branch is renamed, the status says to run `git remote set-head <remote> --auto`. It reads the file with `git cat-file blob`, and never touches the working tree, a local branch, the clone's refs or its files.
- **When.** Every ten minutes (`MEMBERS_READ_INTERVAL_SECS`), at the node's start, and when a person follows, the node reads each clone it follows.
- **The list is as fresh as the clone,** for a public repository as for a private one. It comes from the person's own `git fetch` or `git pull`. The status says how old it is: `list of <identity> read from your clone, fetched 2 hours ago`, or that the age is not known. So a join waits until a member's clone has the merged list: a member runs `git pull` there.
- **Nothing of the person's reaches git, so nothing can ask.** Every git command the node runs, reads of the clone included, runs in a cleared environment:
  - only `PATH` is kept, and the variables of a proxy and of a company's own certificate authority (`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `GIT_SSL_CAINFO`), which never ask;
  - `HOME` and `XDG_CONFIG_HOME` are an empty folder of the node's, so no global setting is read, on any version of git;
  - `GIT_CONFIG_NOSYSTEM=1`, and `-c credential.helper=`, which empties the list a clone's own configuration may set;
  - `GIT_ALLOW_PROTOCOL=https`, so nothing goes over SSH and no agent is asked;
  - `GIT_NO_LAZY_FETCH=1`, so a read of a partial clone never fetches, and a partial clone is not read with a git older than 2.44, which ignores it;
  - `GIT_NO_REPLACE_OBJECTS=1` and `GIT_GRAFT_FILE=/dev/null`, so a replace ref or a graft in the clone cannot swap the list or fake never-back;
  - `GIT_TERMINAL_PROMPT=0` and an empty `GIT_ASKPASS`, with `SSH_ASKPASS` gone with the rest;
  - `http.followRedirects=false`;
  - hooks, `gc` and maintenance are off;
  - `-c safe.directory=<clone>` for a read of the clone;
  - git is stopped by TERM at its deadline (`STREAM_TIMEOUT_SECS` for a read, twice that for all of `subscribe`'s), and killed `MEMBERS_GIT_TERM_SECS` later.
- **What the clone holds stands.** A program that runs as the person can change it (rule 10).
- **A read of the clone never goes back.** It counts only where the clone's commit is the last commit read, or comes after it: `git merge-base --is-ancestor`, run in the clone. A clone left behind gives no new list, and the status says so. The last commit read is kept in the row, so a restart does not forget it.

## 4. What a node does with the list

At each read, each device that follows the repository does the following, with no one asked.

1. **It hands over only the channel the list names, and only where it holds that channel and writes there:** not paused, clean, and not moved from (§7 there). Where any of these fails, it hands over nothing, and says why (rule 6). When it takes is rule 4.4.
   - **It hands over nothing in a channel in which it has read an offer that pauses this person:** one that seals to them and leaves out a key, whether the person then moved, stayed or is still paused (§7 there). That channel was made anew. An offer "without you", or one that is a fault, does not count.
2. **Hands over.** Listed keys not in the channel, not named after `without`, not the person's own devices, and not keys the person removed, are handed the channel, as `share` does. The node's shares are counted apart from the person's own, so a person's `share` by hand keeps its places. They go **four at a time, in turns:**
   - each share lives for two reads, then is deleted, and its key waits out the read at which it goes;
   - each read hands over to the next four such keys, in the list's order, starting after the last one handed;
   - so at most eight wait at once (`MAX_TYPED_KEYS`), and a device that is off for days holds no place;
   - a key that a share of any channel waits for, the person's or the node's, is passed over: a share of one channel deletes another's for the same key (`make_share`).
3. **Deletes the shares to keys the list no longer names,** whether the node made them or a person did.
4. **Takes.** A follower whose person does not hold the named channel looks for a share from each listed key, at each read.
   - It types each listed key again for that read, under a count of its own, so the person's own `accept --channel` keeps its eight places. It asks the relays once for each listed key at each read, not at every pass: 64 keys are 128 requests every ten minutes, well within what a relay allows (§8.4 there).
   - It takes only the named channel, from a listed key, once the list names this device's key as `cordelia id` prints it and its `channel` line does not name it after `without`. Rule 1's gate does not hold it back: it cannot see who is in the channel, and the members keep the gate.
   - It takes nothing while the person holds the channel the named one was made anew from: rule 6 says to move.
   - It takes only a share made within the hour of the latest read (`PAIR_KEY_TYPED_SECS`), so a share left at a relay long ago is not taken.
   - It files the channel on every device of the person's, as `accept --channel` does.
5. **Says a key joined.** A key that first writes in the channel while the list names it shows amber: `<label> joined <name> from the list at <commit>`. It names the channel the key joined, and stays until a person clears it on that device with `cordelia shared seen <name>`, which says each line it clears.
6. **Says a key was dropped.** A key in the channel that an earlier read named and the latest does not shows amber: `<label> is no longer on the list of <name>: make it anew with cordelia shared anew <name>`.
7. **Says a listed key was left out.** A key the list names, that its `channel` line names after `without`, and that is not in the channel, shows once, on each follower that holds the channel and so sees who is in it: `<label> is on the list of <name> but was left out of it: delete its line in a pull request, or wait for that device to write in the channel`. A follower that does not hold the channel cannot tell, and shows nothing. Until it goes, the list names no channel (rule 1). A key that is in the channel, as a device of a person who stays is (§7 there), is not shown.

## 5. Making a repository channel anew

**`cordelia shared anew <name>`, on any channel, prints the new channel line,** naming after `without` each key it left out that the list names, where this device follows the repository. A device that follows also keeps the current line's `without` keys that the list still names, so a later making anew never frees a key left out before. A device that does not follow names every key it left out, and the person may cut those that are not listed. It cannot know the current line's `without` keys: where one is still listed, the person carries it over, and the device that made the earlier making anew shows amber until it is there (below). Every making anew prints it, so no device can make a channel anew without a line that says who was left out:
```
If this channel follows a repository's list, put this line in place of its channel line, in a pull request:
channel <new ID> <relay keys> without 2 <key> <key>
```

**Until that pull request is merged, the list names the old channel, and nobody hands anything over:** a device hands over nothing in a channel in which it has read an offer (rule 4.1), whether it moved, is paused or stayed.

**Once it is merged, the line itself says who was left out,** to every follower: one that was off, and one that joined later, included. No device has to have read the offer. While a key it names is still listed and not in the channel, the list names no channel (rule 1), so nobody is handed anything until that key's line goes. Then the key is not listed, and is never handed the channel. That holds where a member made it anew before the pull request that drops the key, and where a removal made it anew without a stolen device that is still listed.

**The device that made it anew shows the line until the list names the new channel,** amber: `<name> was made anew here: put its new channel line in .cordelia/members, in a pull request`, with the line. From then on, while a key it left out is still listed, it shows amber whenever the list's `channel` line does not name that key after `without`, at this making anew or any later one: `<label> was left out of <name>, and its channel line does not say so: add it after without, or delete its line`.
- **"Then"** is the first read of a list that this device follows whose `channel` line names the new channel, or one made anew from it, as this device knows its moves. The device keeps when that was, with the making anew.
- **That amber of a key ends only at `cordelia shared seen <name> <label>` on that device,** for a key brought back on purpose (rule 1): the making anew counts that key as left out no more, and nothing else is cleared. Otherwise it would never end. `cordelia shared seen <name>` alone does not end it, and says it is still shown: a key left out comes back in the list with a changed channel line, and clearing that notice must not clear this one, while this device hands the new channel to the key.

**Keys that cannot be named:** a key whose row the table let go, and anyone who wrote in a channel past a bound (§6.3 and §7 there). Where such a key is listed, it is handed the new channel. That errs toward the list, which decides.

**A removal** makes each shared channel anew as today (§3.5 there), and prints each new channel line, with the removed device after `without`. The keys a removal leaves out only for room or because they had not moved are not named, and the list decides for them, as for keys that cannot be named. For each repository channel it shows amber until the list names the new channel: `<name> was made anew at a removal: put its new channel line in .cordelia/members`, with the line. A channel past its bound that a removal makes anew is dropped by the removal's own act (§3.5 there): on the device that made the removal, that drop counts as a move, so the follow goes on and shows the line. The person's other devices see a drop, and stop following (rule 2.5): that is rare, and `subscribe` in a clone follows again.

## 6. No silent waits

Every wait says what it waits for, in `cordelia status` and `cordelia shared list`. Each line is the word that today's command would refuse with, put plainly.

| Who | It says |
|---|---|
| A follower not on the list | `Your key is not on the list of <identity> at <commit>.` |
| A follower, the list naming no channel | `The list of <identity> names no channel yet.` |
| On the list, not yet handed it | `Waiting for a member's device to hand you <name>. Your list was read <when>. A member's device hands it over once a member's clone has the merged list: a member runs git pull there.` |
| Holding another channel of this repository, one the named channel was made anew from | `Run cordelia shared move <name>: the list names the channel it was made anew as.` |
| The list naming a channel that no device of the person's holds or can move to | amber: `The list of <identity> at <commit> names channel <words>, which no device of yours holds or can move to.` |
| The channel's relays not among the person's own | `<name> is at <relay>, which is not one of your relays: add it to your configuration.` |
| No room for one more channel, or its name taken | `You hold 16 shared channels, the most there can be`, or `You file another channel as <name>: rename it with cordelia shared rename.` |
| A member handing over | `Handing <name> to <label>: waiting for that device to take it.` |
| A member who cannot | `<name> is paused`, `not clean`, `not reached at its relays`, or `full`: `nothing is handed over until then.` |
| A member who moved | `The list names the channel you moved from. The device that made it anew shows its new channel line: put that line in .cordelia/members.` |
| An offer read in the named channel | `<name> was made anew by <label>: nothing is handed over until the list names the new channel.` |
| The gate of rule 1 | amber, rule 4.7's line, once, on a device that holds the channel: `<label> is on the list of <name> but was left out of it: delete its line in a pull request, or wait for that device to write in the channel`. Nothing is handed over until then. |
| The list, from the clone | rule 3's line, with how old it is |
| A list naming a channel that another follow names | `The list of <identity> names <name>, which this device follows from <other identity>: run cordelia subscribe in a clone of the one it should follow.` |
| This device follows no list of the channel | `This device follows no repository whose channel is <name>.` Said by `cordelia shared seen <name>`. Only a device that follows a repository knows that a channel is its, and another device's follows are its own. |
| The channel line changed | amber, as a join is: `The list of <identity> names a new channel for <name> at <commit>.` Cleared by `cordelia shared seen <name>`. |

## 7. What `cordelia status` shows

For each repository channel:
- **its name and identity;**
- **when the list was read,** where from, and the commit;
- **the members, by the list's labels,** each in or not yet;
- **what waits:** messages unread by the person and by an agent;
- **any line of rules 4 to 6.**

The notices of rules 4.5 to 4.7 show only on devices that follow the repository. Rule 1's gate shows as rule 4.7's line, once, on a device that holds the channel: a joiner cannot see who is in it, and shows nothing of it. Commits show by their first twelve characters (`MEMBERS_COMMIT_SHOWN_CHARS`), and the plain status names the first six members (`MEMBERS_LABELS_SHOWN`) and how many more; `--json` gives the whole commit and every member. The fingerprint words show only with `-v` (#228).

**The ambers set the status's level** (the person's ruling of 6 November): a join (4.5), a key dropped (4.6), rule 1's gate (4.7), a changed channel line and a device of yours left out (rule 6), and the three of rule 5. They overturn property 16 of the shared channels record, "nothing about a shared channel sets a level". Nothing else of a shared channel sets one.

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
- **The host** decides what the branch is, as the person's own git fetches it. The node itself reaches no host.
- **A program that runs as a member** can change the clone, and so the list, for example with `git update-ref`. It can already run `share` with a yes (the README's security section). Each join's notice names the commit, for the person to check.
- **A list in a public repository** shows the channel's ID, its relays, its keys and their labels. None of it lets anyone read the channel: that needs a member to hand it over. Nor can a stranger with the channel's ID and relays write there, or fill its room at a relay. A relay hands a channel only on a proof made with its secret, and takes an entry only where it is signed by the channel's own key, which comes from the seed (§2.1 and §10 there; decision 2026-10-04 §2.4).
- **A member can still hand the channel to a key that is not listed,** by hand: a channel stays flat. `log` shows that key, with no label of the person's.
- **A known limit:** a device that does not follow the repository, making its channel anew, cannot carry the current line's `without` keys. Nor can any device carry what another device's making anew left out, before that line is merged. Where one of those keys is still listed and the person does not carry it over, it is let back in once the new line is merged. The device that left it out shows amber until the line names it again (rule 5). So merge the lines in order.
- **The reader shows listed keys as it shows any other key** (§2.4 there). They are not labelled for the person, and share the hour and the room of keys the person does not know (§6.3 there), until the person labels them.

## 11. Constants

| Name | Value | Why |
|---|---|---|
| `MEMBERS_READ_INTERVAL_SECS` | 600 | As `RELAY_ASK_AGAIN_SECS`: a join waits about ten minutes on each side once the list is read |
| `MEMBERS_HANDED_AT_ONCE` | 4 | Derived: half of `MAX_TYPED_KEYS`, as a share lives for two reads (rule 4.2) |
| `MEMBERS_ASKED_PER_PASS` | 32 | The node's typings asked of the relays in one pass, across every follow, so the shared pass stays within its requests (rule 4.4) |
| `MEMBERS_FILE_MAX_BYTES` | 16,384 | The members record, rule 1 |
| `MEMBERS_LABEL_MAX_CHARS` | 32 | Rule 1 |
| `MEMBERS_GIT_TERM_SECS` | 2 | After TERM, before git is killed (rule 3) |

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
- **From the clone only.** No git of the node's reaches the network: the list comes from the clone, and the status says how old it is.

**Never asked, and never back**
- **Nothing asks.** The person's git configuration and environment are set to ask in each way: a credential helper, globally and in the clone's own configuration, that would ask; an `insteadOf` to SSH; `SSH_ASKPASS`; and a partial clone whose read would fetch. Each git command either goes over HTTPS without asking or fails, and no prompt opens.
- **Identity.**
  - A remote changed to a fork is not read.
  - With two remotes, `--remote` is needed.
  - A list in the working tree or on a local branch is not read.
- **A read of the clone never goes back.** A clone behind the last commit read gives no new list, across a restart too.

**Who gets the channel**
- **Only the named channel.**
  - A share of another channel from a listed key is not taken.
  - A share from an unlisted key, or one older than the hour of the latest read, is not taken.
  - A key not on the list is never handed the channel.
- **Leaving.**
  - A key dropped by a merge shows amber on every follower.
  - `shared anew` leaves it out and prints the new line, with the key after `without`.
  - Before that line is merged, nobody hands the new channel to anyone.
  - After a removal, a removed device that is still listed is never handed the new channel, even where the new channel line is merged and the device's line is not, by any follower: one that was off, and one that joined after the removal, included.
  - A list that names a left-out key both as a member and after `without` names no channel until the key's line goes.
  - A pull request that adds a key's line and takes it off `without` lets it back in.
  - After a second making anew, a key left out at the first, whose line went, is not handed the newest channel.
- **Turns.**
  - Nine new keys, with eight of them off: the ninth is handed the channel at the third read, twenty minutes after the first, as the shares of the first four go.
  - The taker's typings leave the person's eight places free.
  - The node's shares leave the person's own `share` its places.

**What it says**
- **Waits.** Each line of rule 6 appears where it should.

## 13. The reviews, and what they changed

Five reviews, each checked in the code before its findings were taken. Each round's findings and what changed are on pull request #297. What changed most:
- **The list names the channel** (`channel <ID> <relays>`). A share holds only a card, so nothing else said which channel was the repository's (first review).
- **Nothing of the person's reaches git.** Their settings, helpers, `insteadOf` rules and environment could each make something ask (first and second reviews).
- **A private repository is read from the clone,** never fetched. Every way of giving the node credentials can ask (first review).
- **A left-out key is named in the `channel` line (`without`),** and a list that still lists it names no channel. An earlier rule needed every device to have read the offer itself, which a device that was off, or one that joined later, had not (second to fourth reviews).
- **Every `channel` line ends with `without` and a count,** so a line cut short does not parse, and a following device's making anew carries the current `without` keys over (fifth review).
- **Hand-overs go in turns, and takes come only within the hour of the latest read.** Eight places held by devices that were off, and a stale share, had each blocked or misled a join (first and second reviews).
- **The node reads the clone only** (the person, 7 November). Its own fetch of a public repository drew findings in three rounds of slice 2's review: it fetched a whole tree; a git older than 2.44 fetches lazily; and a host sends a blob asked for by its ID whatever the filter says, so a size bound needed a watch on the fetch.
- **A channel follows one repository, and a key waits while any share of it does** (rules 2.5, 4.2 and 6). Two lists that named one channel, or one key, wrote over each other's shares (the review of slice 5a).
- **Rule 1's gate binds only those who hand over** (rules 1, 4.1 and 4.4). A joiner holds no row of the channel, so every listed key after `without` looked out of it to the joiner, and kept it out for good, while the members saw that key write and handed the channel over (the review of slice 5b).

## 14. The person's answers (6 and 7 November)

1. **`cordelia shared seen <name>`** clears the notice of a join (rule 4.5) and of a changed channel line (rule 6), on each device: yes. Rule 5's amber of a key left out has an act of its own, `cordelia shared seen <name> <label>` (slice 7's review).
2. **The default name is the repository's `owner/name`:** yes.
3. **A private repository's list comes only from the person's own fetches.** A read-only token in the node's configuration is left for later: yes.
4. **The node reads the clone only,** with no git of its own that reaches the network (7 November): yes. Its own fetch of a public repository was built and taken out (section 13).
5. **A channel follows one repository** (7 November): kept.
