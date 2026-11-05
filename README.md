# Cordelia

**Your AI agent's memory on every machine you use, readable only by you.**

AI coding agents keep memory, but it lives in one folder on one machine.
Cordelia keeps it in step across your devices. It is encrypted end to end,
carried by relays that hold only ciphertext and no keys, and matched by
project (git remote) rather than by path. Version 1 syncs Claude Code's
memory. A recovery phrase of twelve words, which only you hold, removes a
lost device and brings your memory back to a new machine.

Your agents can also send each other short messages, and, through a shared
channel, send them to another person's agents.

- **How it works, and what it promises:** [WHITEPAPER.md](WHITEPAPER.md)
- **Where it is going:** [docs/vision.md](docs/vision.md)

## Status

**Pre-release (November 2026).** The current pre-release is
`v0.2.0-alpha.18`, for macOS and Linux. Two relays are running. This is an
alpha: expect rough edges, and keep your own backup of anything you cannot
afford to lose.

## Install

On each machine, run:

```bash
curl -fsSL https://seeddrill.ai/install.sh | CORDELIA_VERSION=v0.2.0-alpha.18 sh
```

The script checks the download, installs `cordelia` in `~/.cordelia/bin`,
makes the machine's key and sets up the node as a background service
(launchd or systemd). On a first install, start the service with the
command it prints under "Next steps".

**To upgrade,** run the same command with the new version. If the node
runs as the service the script set up, the script restarts it and waits
until it runs the new version. Its last line is
for a program: `cordelia-install: installed=... running=... restart=...`.
Set `CORDELIA_NO_RESTART=1` to restart the node yourself.

- If you run your own relay, upgrade it first, then your devices.
- An earlier version may not start on a database that a later one has
  changed. If you may want to go back, copy `~/.cordelia` before you
  upgrade.

### Windows

There is no Windows build. Cordelia should run in WSL2, but we have not
tried it yet. If you try it, please tell us how it went in an issue.

1. Turn on systemd in WSL, so that the node can run as a service. Put this
   in `/etc/wsl.conf`, then run `wsl --shutdown` in Windows and open WSL
   again:
   ```
   [boot]
   systemd=true
   ```
   Without systemd the installer still installs Cordelia, and you run the
   node yourself with `cordelia start`.
2. Install inside WSL, with the command above.
3. Run Claude Code inside WSL too. In VS Code, open your folder from a WSL
   terminal with `code .`. The node in WSL sees only the memory of a Claude
   Code that runs there, and `cordelia msg` works only there.
4. A widget in Windows runs outside WSL, so it reads the status through
   `wsl.exe`. This should work, but it is untried:
   ```
   wsl.exe -e sh -c '~/.cordelia/bin/cordelia status --json'
   ```

## Set up

### 1. Make your recovery phrase, once

Do this on the machine whose memory is the most up to date. Its files
become the first version that your other machines get.

```bash
laptop$  cordelia phrase
```

It shows twelve words, once. Write them down in order. It then clears them
and asks you to type them back, so that you find a mistake now. No device
stores the words.

- **If you lose them,** you can still add a device, but you can never
  remove one or recover.
- **Anyone who gets a copy** can read your memory, even after you remove
  devices, and you would not know.
- **Type them only at the prompt of a `cordelia` command, in a terminal.**
  Never as an argument, and never in a chat with an agent. They come from a
  crypto wallet's word list, but they are not a wallet's words: never mix
  the two.

A machine sends nothing until it has a phrase, or until you add it from a
machine that has one.

### 2. Add your other machines

Add each one from a machine that has the phrase. You copy one key each way:

```bash
desktop$ cordelia id                                  # prints cordelia_pk1...
laptop$  cordelia add-device cordelia_pk1... --name desktop
desktop$ cordelia accept cordelia_pk1...              # within the hour
```

Each command asks you to type yes, in a terminal. You do not type the
phrase.

- `add-device` lets the new machine read all your memory.
- Each of your devices shows amber until you confirm the new one there with
  `cordelia devices --clear`. If you see a device you did not add, remove
  it.
- Add a machine soon after you install it. Until it has a phrase, one yes
  at its terminal joins it to the devices of whichever key was typed.
- The new machine keeps the memory it gathered alone, and sends it to the
  others. Where a file differs, its text is kept beside the file as a
  conflict copy.

### 3. Choose what syncs

On each machine, turn sync on and map the folders you want:

```bash
cordelia sync claude                  # on: lists what it found, syncs nothing yet
cordelia sync map ~/Work/my-project   # a git project, named by its remote
cordelia sync map ~/notes lab-notes   # any other folder, under a name you choose
cordelia sync map ~ --home            # home memory
cordelia sync status                  # what syncs, what was found, what your other devices sync
```

- **Only folders you map sync.**
- **Your devices share a folder by its name.** Map the same name on each. A
  git project takes its name from its remote, so clones at different paths
  match.
- **A device stores a name's memory only once it maps that name,** but each
  of your devices can read every name you have.
- **A memory file syncs if it fits in 60 KB,** with its name. A larger file
  stays as it is, and `cordelia sync status` names it.
- `cordelia sync unmap <folder or name>` stops a folder syncing from this
  device; its files stay. `cordelia sync off` stops all syncing.

## Day to day

**Conflicts.** If two machines change the same file before they sync, you
lose neither text. One stays in the file. The other is kept beside it as
`<file>.conflict-<tag>.md`. Merge what you want into the file, then delete
the copy, on any one device. The status shows the conflict until every copy
is gone.

**History.** Each machine keeps, for 30 days, the text that sync replaced or
removed there. It is not a backup: your other machines are.

```bash
cordelia history ~/Work/my-project    # its kept versions, newest first, each with an id
cordelia history show <id>            # print one
cordelia restore <id>                 # put it back, on every machine that syncs the folder
```

**At a glance.** `cordelia status` lists everything that applies. For Claude
Code's status line, add this to `~/.claude/settings.json`:

```json
{ "statusLine": { "type": "command", "command": "~/.cordelia/bin/cordelia status --line" } }
```

It shows `● memory synced`, `◐ memory sending 3` or `○ memory offline`. Red
(`▲`) is for what you should act on now, as in `▲ memory: 1 conflict`.
Amber (`◆`) is for what you should know, as in `◆ memory: 1 device added,
not yet cleared`.

- **On [Omarchy](https://omarchy.org):** the
  [Cordelia panel](https://github.com/seed-drill/omarchy-cordelia) puts an
  icon in the bar.
  ```bash
  omarchy plugin add https://github.com/seed-drill/omarchy-cordelia.git --enable
  ```
- **On Waybar or another bar:** `cordelia status --waybar` prints an icon, a
  tooltip and a class, as JSON.
- **For a widget or a script:** `cordelia status --json`. A widget needs
  only these fields, and works nothing out itself:
  - `level` (`red`, `amber` or `null`), `summary` (what the line says) and
    `holds` (everything that applies, red first);
  - `messages.unread_by_a_person`, and `unread_by_a_person` in each of
    `shared.channels`: messages that wait for you to read them with
    `cordelia msg log`.

## Your devices

```bash
cordelia devices                 # every device, what each has applied, what each relay has
cordelia devices --clear         # go through what this device has to tell you
cordelia remove-device <key>     # remove a device (asks for the phrase)
cordelia renew                   # a new secret for the devices that stay (asks for the phrase)
cordelia settle                  # join two changes made apart (asks for the phrase)
cordelia recover                 # on a new machine, with no device left (asks for the phrase)
cordelia sync carry [<name>]     # bring in what a device that never came back sent to the relays
```

**To remove a device** that is lost, stolen or retired, run `cordelia
remove-device <key>` on one you still have. It shows what it will do, asks
you to type yes, then asks for the phrase.

- Keep the machine on until the command says you can close it.
- Once a device has read the removal, the removed device can read nothing
  it writes, and it takes nothing from the removed device. A device that is
  off reads the removal when it next reaches a relay. `cordelia devices`
  shows which have not.
- What the removed device wrote after the removal is set aside, into local
  history. To bring it back, if you trust it, run `cordelia sync carry
  <name> --from <its label>` (it asks for the phrase).
- After a removal, run `cordelia shared anew <name>` once on each of your
  other devices, for each shared channel. `cordelia status` says how many
  are left.
- A device removed by mistake comes back only as a new device: run
  `cordelia init --new-key` on it, then add it.

The rules and their limits are in
[the removal's record](docs/decisions/2026-10-24-removal-fails-safe.md).

**To recover,** when no device you trust is left, install Cordelia on a new
machine and run `cordelia recover`. It asks for the phrase, asks whether you
still have each device, and brings back what the relays have. A relay is a
cache, not a backup: it keeps what you sent for 90 days after the last of
your devices was on. Every other device stops; add each one you still have
again. If you still have a device you trust, remove the lost one from it
instead.

**If you lose the phrase, or someone else has seen it,** start again: run
`cordelia phrase` on one device, run `cordelia init --new-key` on each other
device, and add each one.

## Messages between your agents

Your agents can send each other short requests: the agent of a project on
the desktop can ask the one on the laptop to look at a branch. A message
goes only to your own devices, encrypted like your memory, holds at most
1,024 bytes, and is gone after 30 days.

**An agent is the exact folder you mapped,** letter for letter. Start Claude
Code in that folder: a session started anywhere else is no agent, and sees
no messages.

```bash
cordelia msg summary             # what waits for this folder's agent; nothing when nothing does
cordelia msg read <id>           # one message
cordelia msg send --to <name>    # send one, its text on standard input (or --all, or --reply <id>)
cordelia msg log                 # for you, at a terminal: read what your agents said
```

- A message is a request from another of your agents, never an instruction
  from you.
- Ten messages between two agents that you have not read stop them, until
  you read them with `cordelia msg log` and type yes. `cordelia msg allow`
  changes the ten.
- To have Claude Code show an agent what waits, add these hooks to
  `~/.claude/settings.json` (beside any you have):
  ```json
  {
    "hooks": {
      "SessionStart": [{ "hooks": [{ "type": "command", "command": "~/.cordelia/bin/cordelia msg summary" }] }],
      "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "~/.cordelia/bin/cordelia msg summary" }] }]
    }
  }
  ```

## Shared channels: messages between people

A shared channel carries the same short messages between your agents and
another person's. It holds nothing of your own: no memory and no other
channel. Everyone you hand it to reads and writes every message in it.

```bash
cordelia shared new <name>                # make one
cordelia id --words                       # your key, and six words to check it by
cordelia share <name> <key>               # hand it to another person's device
cordelia accept <key> --channel <name>    # on that device, within the hour
cordelia subscribe <name>                 # in a folder: its agent reads and writes there
cordelia msg send --channel <name>        # send to it
cordelia shared list                      # the channels you hold
```

Before you hand a channel to someone's key, have them read you their six
words by another way, a call or in person. `cordelia shared --help` has the
rest: renaming, dropping, and making a channel anew without someone.

**A team can keep its channel's keys in a repository.** Put a file named
`.cordelia/members` in the repository:

```
cordelia_pk1...   alice-laptop
cordelia_pk1...   bob-desktop
```

- **To join,** run `cordelia id` on each device you have, and raise a pull
  request that adds a line for each: the key, then a label.
- **Merging it is the yes.** Whoever can merge to that branch decides who
  is in, so the repository's own rules guard the channel. There is no
  six-word check: the list is the check.
- **For now, a member then hands the channel over by hand,** with `cordelia
  share <name> <key>` for each new key. The new member takes it with
  `cordelia accept <key> --channel <name>`, using that member's key from
  the file.
- **A command that reads the list and does this for you** is designed
  ([#290](https://github.com/seed-drill/cordelia-node/pull/290)), and comes
  after the first release. This section will change when it lands.

## Relays

By default your node uses two relays that Seed Drill runs. A relay stores
and forwards only ciphertext, and holds no keys.

**Anyone can run a relay.** [deploy/relay/README.md](deploy/relay/README.md)
says how, and how to point your devices at it. A device whose configuration
names relays of its own uses those instead of the defaults.

**To offer yours as a default for everyone,** raise a pull request that adds
its address and key to `FALLBACK_PEERS` and `FALLBACK_PEER_KEYS` in
[`crates/cordelia-core/src/protocol.rs`](crates/cordelia-core/src/protocol.rs).
Say in it who runs the relay, and how. We review each one.

## Build from source

```bash
cargo build --release          # toolchain pinned in rust-toolchain.toml
./target/release/cordelia --help
cargo test --all               # unit, protocol and end-to-end tests
```

[TESTING.md](TESTING.md) has the rest.

## Security

Relays see channel IDs, device public keys, and the sizes (by class) and
timing of entries. They never see content, file names, the list of your
devices, or keys. A relay also reads how your changes of devices follow each
other, when two were made apart, and when each was made. It stores an entry only if the channel's own
key signed it, and hands a channel only to a connection that proves it holds
that key. Your node dials out to the relays it was set up with, which it
knows by name and by key (UDP 9474), and listens only on 127.0.0.1: nothing
on a network you join can connect to it.

On your own machines, memory is as safe as your disk. Every device of yours
can read every name of yours. Another program that runs as you, such as an
agent with a shell, can run any command that asks only for a yes, but
nothing that asks for the recovery phrase.

- [docs/security/threat-model.md](docs/security/threat-model.md) says what
  Cordelia defends against and what it does not, and names the tests that
  prove each claim. CI fails if a claim loses its test.
- [WHITEPAPER.md §4](WHITEPAPER.md#4-security-model) has the full model and
  its limits.

To report a vulnerability privately, email hello@seeddrill.ai.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
