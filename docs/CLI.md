# NeoNet CLI reference

Run `neonet --help` or `neonet <command> --help` at any time — this
document is a walkthrough with real examples, not a replacement for that.

## State directory

NeoNet stores its identity key, device list, and bootstrap config under
`~/.neonet` by default. Override with `NEONET_HOME=/some/path`.

```
~/.neonet/
├── identity/identity.key   # this device's Ed25519 private key (generated on first run)
├── devices.json            # aliases for `neonet connect` — you create this
├── bootstrap.json          # core node(s) an edge dials into — you create this
├── storage.key             # XChaCha20 key for `neonet store` (generated on first use)
├── revoke.epoch            # monotonic counter that makes each revoke broadcast unique
├── paired.json             # flash-pairing ledger (established pairings)
├── pair.json               # active single-use pairing token (while `neonet pair` is live)
├── rendezvous.json         # live registrations the rendezvous service knows about
├── lobbies/                # member-side lobby roster + decrypted post logs
├── channel/                # per-peer private channel logs (decrypted)
├── incoming/               # inbound `neonet send` transfers land here
├── forked/                 # `neonet fork` copies of Burrow files land here
├── shell/                  # shell command history (history)
└── blobs/                  # per-core: encrypted chunks, manifests, ACLs, revocations
```

Nothing here is created automatically except `identity/identity.key`. If
`devices.json` or `bootstrap.json` don't exist yet, the relevant commands
will tell you so and point back here — they won't crash with a raw
"file not found" error.

## Commands

### `neonet whoami`

Prints this device's identity fingerprint, public key, and the path to its
key file. Run this first — every other device needs your public key to
grant you access.

```
$ neonet whoami
NeoNet 0.1.0
identity fingerprint: 3f9a...
public key: 8c21...
identity key: /home/you/.neonet/identity/identity.key
```

### `neonet devices`

Lists the aliases in `devices.json`. Empty until you create the file.

### `neonet connect <device_id>`

Resolves `device_id` (an alias from `devices.json`) to a host and hands off
to your system's real `ssh` binary. NeoNet does not reimplement SSH — this
is a thin resolver, nothing more. If `device_id` isn't found, you'll get a
message telling you to check `neonet devices` or the file itself, not a raw
`NotFound` OS error.

### `neonet nsh <device_id> [command ...]`

The same resolution through the local `ssh` binary, with optional remote
command words passed through verbatim:

```
$ neonet nsh myserver               # interactive shell
$ neonet nsh myserver journalctl -u neonet   # one-shot remote command
```

Like `connect`, this is an SSH redirector, not a shell protocol.

#### `devices.json` format

```json
{
  "devices": {
    "myserver": "3f9a7c1b8e2d4f6a9c0b1e3d5f7a9c2b4e6d8f0a1c3e5b7d9f2a4c6e8b0d2f4a"
  }
}
```
Key = alias you type, value = the target's full fingerprint (from its own
`neonet whoami`). Exact key names may differ slightly by version — run
`neonet devices` against an empty file first if you're unsure, it will
tell you the expected shape.

### `neonet send <device_id> <file> [--bootstrap <file>]`

Streams `file` to `<device_id>` (an alias or fingerprint from
`devices.json`) over authenticated messages, chunk by chunk, waiting until
the peer confirms a complete verified copy. Both devices must be on the
same mesh. The peer's copy lands in its
`NEONET_HOME/incoming/<transfer-id>/`.

```
$ neonet send myserver ./backup.tar
sent ./backup.tar to myserver: 12 of 12 chunks verified in 14s
```

`neonet transfers` lists this device's inbound transfers and their
resume state; re-running `send` for the same file resumes where a partial
transfer left off.

### `neonet browse <device_id> [path] [--bootstrap <file>]`

Lists a peer's Burrow share — a read-only directory the host publishes.
Metadata only: filenames, types (`/` directory, `@` symlink), and sizes.
The host's Burrow service is read-only by design; there is no write
primitive on the wire.

### `neonet fork <device_id> <path> [--bootstrap <file>]`

Pulls a full local copy of one file out of a peer's Burrow share into
`NEONET_HOME/forked/<path>`. Symlinked and out-of-tree paths are refused.

### `neonet store push <device_id> <file> [--bootstrap <file>]`

Encrypts `file` locally (XChaCha20-Poly1305, key in `storage.key`) and
pushes the opaque chunks to the storing core. The core can never decrypt
what it holds — this is encrypted storage tunneling, not an encrypted
conduit to a plaintext store.

```
$ neonet store push myserver ./secrets.bin
stored ./secrets.bin on myserver (file id 2e617f...)
```

### `neonet store pull <device_id> <file_id> [output] [--bootstrap <file>]`

Fetches the chunks from the storing core, decrypts them locally, and
reconstructs the original file:

```
$ neonet store pull myserver 2e617f...
restored 2e617f... from myserver to secrets.bin
```

The core never sees the key or the plaintext. Chunks are fetched page by
page (`FetchChunks` is offset-paged server-side), so even multi-gigabyte
files stay under the transport's 1 MiB message cap; the server-side ACL
gates who a file belongs to.

### `neonet replicate <src> <dst> <file_id> [--bootstrap <file>]`

Copies a stored file from one core to another so it survives losing
either. The operator device reads the opaque chunks out of `src` and
pushes them into `dst`; neither core ever sees plaintext. `dst` must be
reachable through the same mesh as `src` — in a reference deployment every
core dials the others.

```
$ neonet replicate core-a core-b 2e617f...
replicated 2e617f... (12 chunks) from core-a to core-b
```

### `neonet revoke <device_id> <public_key_hex> [--bootstrap <file>]`

Broadcasts a signed revocation for a peer to a core. The core applies it
only if this device is in that core's operator set — an empty operator set
fails closed (nobody can revoke). A per-device monotonic epoch is included
in the signature so a replayed broadcast is rejected.

```
$ neonet revoke core-a 8c21f4a9b6d3e0c7f1a5b9d2e6c0a4f8...
core-a acknowledged revocation epoch 1
```

Revocation is applied *per core*: run it once per core you want to update.
A revoked identity is refused at the store's gates (both store and fetch)
on every core where the revocation has been applied.

### `neonet operator add <public_key_hex>` / `neonet operator list`

Manages this node's operator set (`NEONET_HOME/operators.json`) — the
allow-list for who may issue effective revocations through it. Run it on
the core's own machine/`NEONET_HOME`:

```
$ neonet operator add 8c21f4a9b6d3e0c7f1a5b9d2e6c0a4f8...
added 3f9a7c1b... to the operator set at .../operators.json
$ neonet operator list
3f9a7c1b8e2d4f6a9c0b1e3d5f7a9c2b4e6d8f0a1c3e5b7d9f2a4c6e8b0d2f4a
```

### `neonet core --listen <addr> [--allow-file <file>]`

Runs this device as a core node: an always-on machine that accepts
connections from edge devices, relays messages, and stores shared files.
`serve` is an identical alias for this command.

```
$ neonet core --listen 0.0.0.0:7000
```

**`--allow-file` is how you restrict who can connect.** It must be a JSON
array of *full* 64-hex public keys — a bare fingerprint is a one-way hash
and can't be turned back into something verifiable, so fingerprints are
rejected rather than silently ignored. If you omit `--allow-file`, the node
accepts any authenticated peer, which is fine for local development and
wrong for anything reachable from the open internet. The CLI prints a loud
warning every time you do this so it's never silently open.

### `neonet edge --bootstrap <file>`

Runs this device as an edge node: dials out to the core node(s) listed in
`<file>`, using pinned public keys so a spoofed address can't silently
replace your real core.

```
$ neonet edge --bootstrap ~/.neonet/bootstrap.json
```

#### `bootstrap.json` format

```json
[
  {
    "address": "192.0.2.10:7000",
    "pinned_public_key": "8c21f4a9b6d3e0c7f1a5b9d2e6c0a4f8b3d7e1c5a9f2b6d0e4c8a1f5b9d3e7c0"
  }
]
```
`pinned_public_key` is the *core's* full public key (from that core's own
`neonet whoami`), hex-encoded — not a fingerprint. This is the physical/
out-of-band trust anchor: as long as this value came from a channel you
trust (typed in by hand, delivered on a USB stick, read over a phone call),
a compromised DNS entry or a spoofed IP can't trick your edge into trusting
an impostor core.

### `neonet register <device_id> --addr <host:port> [--ttl <secs>] [--bootstrap <file>]`

Publishes this device's current address to the rendezvous node
(`<device_id>`), so other nodes can find it. Without this, nothing knows
where you are.

```
$ neonet register alice --addr "192.0.2.30:7000"
```

- `--ttl` sets how long the registration stays live (60 s – 24 h,
  default 6 hours). The rendezvous tracks the *latest* registration per
  device; a stale address is dropped when a newer one overwrites it.
- Registrations are strictly self-signed: the rendezvous accepts an
  address **only** when the message is authenticated by the device's own
  key. Nobody can register an address on someone else's behalf.
- The rendezvous only advertises live registrations — an expired one
  falls out of `neonet scan` on its own.

### `neonet scan <device_id> [filter] [--active] [--bootstrap <file>]`

Asks the rendezvous which devices are currently registered, optionally
narrowing to fingerprints/addresses containing `filter`.

```
$ neonet scan alice            # everything live
$ neonet scan alice e9d4       # fingerprints/addresses containing "e9d4"
$ neonet scan alice --active   # also probe each hit to confirm it's alive now
```

`--active` reopens a connection to every hit and only reports the ones
that answer — the difference between "announced recently" and "up right
now".

Design note: `scan` is LAN-minded today. A pubcode alone cannot turn into
a TCP address without a rendezvous step, so `scan` is exactly that step —
but it only knows the addresses devices *chose to register*, and only
ones registered under their own identity. See the automation design doc
(`Downloads/NEONET_AUTOMATION_DESIGN_QUESTIONS.md`) for the alternatives
deliberately not built yet.

### `neonet pair [--ttl <secs>] [--bootstrap <file>]`

Runs this device as the **acceptor** for a flash pairing. It publishes a
single-use pairing token, prints it once, and stays online until a device
redeems it (or the window closes).

```
$ neonet pair
pairing token: a1b2c3d4e5f6a7b8...  (single use; 120s; presented with `neonet flash <device> <token>`)
```

- The token lives only for `--ttl` seconds (default 120, max 600) — the
  "plugged-in moment." After one redemption it's dead forever, so a
  lost/stolen token is a dead file, never a standing key.
- Whoever redeems it is added to this device's pairing ledger
  (`paired.json`). See `neonet pairs` for the ledger, including building
  an allow-list from it.
- Why not silently auto-trust? Auto-trusting on first contact is the
  autorun-malware pattern. The *active* `neonet pair` run is the "person
  at the target machine saying yes once."

### `neonet flash <device_id> <token> [--bootstrap <file>]`

Presents an acceptor's single-use pairing token — the "insert." The
device running this is the one being trusted.

```
$ neonet flash gateway a1b2c3d4e5f6a7b8...
gateway paired 3f2a...
```

Fails loudly (`gateway refused the token: ...`) if the token is bogus,
expired, or already consumed. Retrying with the same token always fails —
one drive, one insertion.

### `neonet pairs [--as-allow]`

Shows this device's pairing ledger.

```
$ neonet pairs
3f2a...  64 bytes of hex...  1756432000
```

`--as-allow` prints the ledger as a `allow.json`-format JSON array of
public keys, ready to install as a core's `--allow-file`:

```
$ neonet pairs --as-allow > allow.json
$ neonet core --listen 0.0.0.0:7000 --allow-file allow.json
```

Pairing records trust; the transport gate stays a deliberate operator
decision. (The accept gate deliberately is not auto-opened by a pairing —
that would recreate the silent-first-hookup behavior pairing exists to
avoid.)

### `neonet flasher` — pair two machines from a USB drive

The flasher is the same physical idea as `pair`/`flash`, but carried on an
actual drive: a directory (usually a mounted USB stick) that can hold a
bundled `neonet` binary and an identity+token bundle written by the machine
it was flashed *from*. It turns "plug the drive in on each machine" into a
pair-and-trust without typing keys, codes, or pins.

Build a drive, then author it on machine A, then adopt it on machine B:

```
# 1. build the drive once (wraps the current release binary + a README)
./flasher-install.sh /media/usb

# 2. on the machine you are flashing FROM
neonet flasher author --dir /media/usb        # writes bin/ + flashed.json (identity + token)

# 3. on the target machine (may not have neonet installed)
neonet flasher ensure --dir /media/usb        # install neonet if missing
neonet flasher adopt  --dir /media/usb        # confirm, then pair & trust the source
```

Three operations, each honest about what it does offline:

#### `neonet flasher ensure [--dir <drive>]`

The installed?-checker. If `neonet` is already installed it says so and does
nothing. Otherwise it installs it, preferring a bundled binary on the drive
(`<drive>/bin/neonet` — no toolchain needed), then falling back to a source
build (`install.sh`-style) when cargo/rustc are present. Errors clearly if
neither is available.

#### `neonet flasher author --dir <drive>`

Runs on the machine being flashed from. It issues a fresh single-use pairing
token (short window, exactly like `neonet pair`) and writes `flashed.json`
into the drive: that machine's public identity + fingerprint + the token.
The drive is now "flashed from" this machine. Re-running replaces the bundle.

#### `neonet flasher adopt --dir <drive>` / `--yes`

Runs on the target machine. It reads `flashed.json` from the drive, then
**always asks for explicit confirmation** before trusting anything:

```
This drive was flashed from flashed-from (c8195f61...). Trust it and pair with it? [y/N]
```

Only an explicit `y`/`yes` records the flashed-from device in this machine's
pairing ledger (`paired.json`) **and** saves it as a known device
(`devices.json`), so it can be reached through the mesh. `--yes` skips the
prompt (automation/tests only — not recommended on a live machine).

> **Why the confirmation?** A drive that silently installed software *and*
> silently trusted its origin on plug-in is exactly the autorun-malware
> pattern every OS fights. The explicit confirmation is the "person at the
> target machine saying yes once" guard — the same reason `neonet pair` is an
> active decision rather than silent first-contact trust.
>
> **Network note.** On Linux `ensure`/`author`/`adopt` are fully offline — the
> drive itself carries identity + token. Making the *source* record the target
> in return (and actually reaching it) still needs the two machines to share a
> mesh path, exactly as with `pair`/`flash`; the flasher does the out-of-band
> carry so no keys or pins cross the network.

### `neonet host <lobby_name> [--bootstrap <file>] [--title <text>] [--welcome <text>] [--max-members <n>]`

Runs this device as a lobby **host** and prints the lobby key once.
While this process stays online, members who present that key are
admitted and their posts relayed to the other members.

The lobby's customization is fixed **before** it starts — there is no
post-start mutation:

- `--title <text>` — display title members see on admission (defaults to
  the lobby name);
- `--welcome <text>` — a message shown to each member once, as they join;
- `--max-members <n>` — hard cap on simultaneous members (the host itself
  does not count; further joins are refused).

```
$ neonet host retreat --title "The Lagoon" --welcome "welcome to the fire drill" --max-members 16
hosting lobby 'retreat' (The Lagoon) — give members this key and they will be admitted when presented:
  3f2a9b... (64 hex chars)
welcome message: welcome to the fire drill
seat cap: 16 members (the host does not count)
members run: neonet join "retreat" <host-fingerprint> 3f2a9b...
[... waits; prints membership events and posts to this terminal ...]
```

The lobby dies when the host stops — no leader election, by design (see
`docs/LOBBY_DESIGN.md`). The key doubles as the channel's encryption key:
relay cores see membership, never content, while the host itself always
can read (it authored the code).

### `neonet join <lobby_name> <host_device_id> <lobby_key> [--bootstrap <file>]`

Joins a lobby, presenting the host's printed key. Out-of-band key
distribution, same caution as any shared secret (a Zoom code, a key in a
text message).

Whether the host set them or not, the admission reply carries the lobby's
title and welcome, which `neonet join` prints (`joined lobby 'retreat'
(The Lagoon)` + the welcome message) and caches in the roster.

```
$ neonet join retreat alice 3f2a9b...
joined lobby 'retreat' (The Lagoon)
welcome to the fire drill
```

The join is recorded in `NEONET_HOME/lobbies/roster.json`, which is what
the `neonet lobby` subcommands read. If the lobby honors a seat cap and it
is full, the host refuses the key with "lobby is at its member cap".

### `neonet lobby`

Member-side lobby subcommands:

```
neonet lobby post <lobby_name> <message>        # post one encrypted message
neonet lobby log  <lobby_name>                  # decrypted posts you received
neonet lobby members <lobby_name>               # who's in right now (host answers)
```

```
$ neonet lobby post retreat "fire drill at the lagoon"
posted to 'retreat' (relayed to 2 member(s)).
$ neonet lobby log retreat
1756432010  3f2a...   fire drill at the lagoon
$ neonet lobby members retreat
d1c4...
3f2a...
```

Posts are encrypted under the lobby key end-to-end through the relay, and
decrypted into your own `lobbies/<name>.log`.

### `neonet channel <device_id> [<message>] [--bootstrap <file>]`

Private 1:1 text to any device that's active on the network — separate
from lobby group messaging. Sends ride the encrypted transport and are
written into the *recipient's* per-peer channel log. With no message, it
shows this device's received channel log from that peer.

```
$ neonet channel alice "the keys are under the mat"
channel message to 3f2a... acked at 1756432010.
$ neonet channel bob          # show what bob has sent me
1756432010  9c77...   see you at dusk
```

Channels are identity-addressed and authenticated end to end. Burrow
remains the file-exhange face of the same connections (`browse`/`fork`).

### The shell (bare `neonet`)

Running `neonet` with no subcommand opens the shell — the platform on which
every NeoNet tool lives. There is no separate "desktop" to navigate into:
whoami, devices, connect, nsh, send, browse, fork, store, channel, lobby,
pairing, rendezvous and daemon tools are all commands at the prompt.

```
$ neonet                # boot splash -> prompt, all tools at hand
```

There is no virtual filesystem and no `cd`/`ls`/`mkdir`/`cat`/`edit`/`grep`
drive layer, and no `mount`/`get`/`put` remote-drive notion in v1 — the shell
is a pure tool surface. Each tool carries its own arguments, exactly as the
standalone `neonet <command>` forms do.

System commands:

```
help, echo TEXT, clear, clock, history
sysinfo                    host OS, kernel, RAM, battery
whoami                     this device's mesh identity
devices                    known device aliases (devices.json)
update [--repo R] [--branch B] [--release]
reboot                     re-boot the shell screens
quit | exit                leave the shell
```

Mesh & file tools:

```
nsh ALIAS [CMD...]         SSH redirector passthrough
connect ALIAS              interactive session via your ssh binary
browse ALIAS [PATH]        list a peer's shared directory (one-shot)
fork ALIAS PATH            pull a local copy into NEONET_HOME/forked/
send ALIAS FILE            send a file to any device (resumable)
channel ALIAS MSG          private 1:1 message (or `channel ALIAS` to view log)
transfers                  inbound file transfers and resume state
store push ALIAS FILE      encrypt + store chunks (prints a file id)
store pull ALIAS ID [OUT]  fetch, decrypt, reconstruct
replicate SRC DST ID       copy a stored file between two cores
```

Services & pairing:

```
register ALIAS ADDR [TTL]       publish your address at a rendezvous node
scan ALIAS [FILTER] [--active]  list registered devices
pair [TTL]                      issue a single-use pairing token (this shell accepts)
flash ALIAS TOKEN               redeem an acceptor's pairing token
pairs [--as-allow]              show the pairing ledger (or an allow-list)
flasher ensure|author|adopt     USB drive pairing (+ installed?-checker / auto-install)
revoke DEVICE HEX               broadcast a signed revocation
operator add HEX | operator list
```

Lobby & messaging:

```
host LOBBY [--title T] [--welcome W] [--max-members N]
join LOBBY HOST_KEY_ALIAS LOBBY_KEY
say TEXT                 post to the most recently joined lobby
post LOBBY TEXT         post to a specific lobby
lobby log [NAME] / lobby members [NAME] / lobby leave [NAME]
```

Daemons:

```
core --listen ADDR [--allow-file FILE]   launch a relay core in background
serve --listen ADDR [--allow-file FILE]  alias of core
edge --bootstrap FILE                    launch an edge daemon in background
daemons / stop PID
```

The shell holds one persistent mesh session while it is open, so it can host
lobbies, accept pairings, and receive channel relays live at the prompt.
`Ctrl-C` prints "use 'quit' to exit" instead of killing the session; `Ctrl-D`
(EOF) leaves the shell.

#### A friendlier prompt

The prompt is a simple arrow (`⟫`) — the old `NEONET L:/` "drive" marker is
gone in v1 since there is no virtual drive. Typing at the prompt is a real
line editor (rustyline):

- **Arrow keys** move and edit the cursor on the current line.
- **Up/Down** walk through your command history (also shown by `history`).
- **Tab** completes a partially-typed command (e.g. `wh<Tab>` → `whoami`).
- **`help`** on its own prints a short welcome with topic names.
- **`help <topic>`** drills into detail: `devices`, `files`, `messages`,
  `chat`, `pair`, `mesh`, `system`.

`whoami` shows a short human-friendly device id (first 12 hex characters)
instead of the full raw fingerprint; the full id is printed underneath.

### `neonet update`

Pull the newest code from your git remote and rebuild the binary. Manual on
purpose — nothing self-updates or force-resets, so a bad push can never wedge
your local checkout. Only ever `git fetch` + `git pull --ff-only`; if the
update would overwrite uncommitted changes git refuses and the command stops
with instructions.

```
$ neonet update                              # from origin / current branch
$ neonet update --repo https://git.example/neonet --branch main
$ neonet update --release                    # rebuild a release binary
```

The repo/branch to follow come from, in order: `--repo`/`--branch` flags, the
`NEONET_UPDATE_REPO`/`NEONET_UPDATE_BRANCH` environment variables, and the
checkout's git `origin`/current branch. The command locates the checkout by
walking up from the running binary and from the current directory.
`neonet update` is also available as `/update` inside the demo script
(`lobby-demo.sh`).

## Access control

Inbound connections complete the authenticated handshake, then the accepting
node checks the peer's **full public key** against the allow-list file you
pass to `--allow-file` (or `neonet core`/`serve`). Format:

```json
[
  "8c21f4a9b6d3e0c7f1a5b9d2e6c0a4f8b3d7e1c5a9f2b6d0e4c8a1f5b9d3e7c0",
  "6f6e6c9c4ca16975187e85c39a0c476fa119957be442bc415642e7c8eb5332dc"
]
```

These are the **public key** lines from each allowed peer's own
`neonet whoami` — never fingerprints (a one-way hash can't be turned back
into a key to verify a signature against, which is why fingerprint-based
`--allow` flags are refused outright). An empty file is refused too: it
would silently make the node unreachable by anybody.

Without `--allow-file`, the node accepts any authenticated peer. That is
fine locally and wrong publicly; the CLI says so at every startup. The
installer (`installer/install-linux.sh`) accepts an allow-list file as its
third argument and wires it into the systemd unit.

## Common errors and what they mean

| You see | What's actually happening |
|---|---|
| `could not resolve or connect to '<id>'` | That alias isn't in `devices.json`. Run `neonet devices` to see what's known. |
| `<file> is not valid device-directory JSON` | The file exists but doesn't parse — check it against the format above. |
| `--allow-file <file> is not valid allow-list JSON...` | The file exists but doesn't parse — check it against the access-control format above. |
| `could not connect to any configured core node` | Every core in your bootstrap file refused the connection or wasn't reachable — check the address and that the core is actually running `neonet core --listen ...`. |
