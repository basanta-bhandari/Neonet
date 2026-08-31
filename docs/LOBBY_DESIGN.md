# NeoNet Lobbies — Design Notes (`neonet host` / `neonet join`)

*Group messaging is the first genuinely new subsystem in NeoNet — current
messaging is strictly 1:1, identity-addressed. This short doc exists so
the two load-bearing questions ("who's authoritative when the host
disappears" and "is lobby content end-to-end encrypted") get a decision in
writing before any code, per the project's standing process. No code
depends on this yet.*

## What lobbies are

A lobby is an ephemeral group channel: a set of devices exchanging short
text messages, addressed by a name the members share. It is **not** a
persistent room, **not** a broadcast medium for unknown devices, and
**not** a channel over anything but the existing core relay. It is the
group-messaging analog of `neonet send` — text instead of files.

The **lobby key** is a random 32-byte secret the host publishes like a
conference code. It does double duty:

1. It is what a joiner proves to the host to be admitted ("I know the
   code" = "I'm expected"). This is the Zoom model, and its secrecy
   depends entirely on how carefully the host shares it — named, not
   hidden.
2. It is the encryption key for every message in the lobby
   (XChaCha20-Poly1305). Possession of the key is possession of the
   channel.

## Decisions, in writing

### 1. Who's authoritative for membership?

**The host — while it is online.** The host admits joiners (by the key,
which stays a live thing the host can close by rotating it), relays every
post, and is the only member that answers `Members` queries.

**When the host disconnects, the lobby pauses and then dies.** No
designated-successor/paxos: lobbies are casual; the honest failure mode
for "the host's node is gone" is "the channel goes quiet and its members
start a new one." Making membership survive host death is a replication
problem (core-replication's, at smaller scale) and buying that for casual
rooms is exactly the over-build this project names-and-defers. If a
retreat room turns out to need true durability, that's a named follow-up,
not an improvised default buried in a PR.

### 2. Is lobby content end-to-end encrypted?

**Symmetric, shared-secret encryption — end-to-encrypted-end, with the
host as a fully-privileged member.**

Every post is XChaCha20-Poly1305 under the lobby key. The core relay
nodes carrying the traffic see *that* a lobby exists and *which members*
are in it (membership metadata), but not the message contents — the host
relays ciphertext only. The exception is the host itself: the host holds
the key (it is the code's author), so the host *can* read everything.

That is the honest tradeoff, in writing:

| Observer | Sees post contents? | Sees membership? |
|---|---|---|
| Core relay operator | **No** (ciphertext only) | Yes |
| Lobby host | Yes (holds the key) | Yes |
| Other members | Yes | Partially (host's `Members`) |

Per-member keying (so even the host can't read) is real extra work with
real key-distribution machinery; for casual rooms it is deferred. Named,
not faked.

### 3. Routing

Lobby traffic rides the existing core relay: members address the host,
the host relays posts to the other members. No new transport, no new
trust surface. The relay sees membership metadata (decision #2), which is
the one new privacy tradeoff this whole feature introduces, and it's
accepted here deliberately.

## Frames

```text
LobbyFrame {
  Join    { lobby_name, key }          member -> host
  Joined  { lobby_name, title, welcome }       host -> member   (admission carries the lobby's customization)
  Refuse  { message }                  host    -> member   (wrong key / unknown lobby / at member cap)
  Post    { lobby_name, key, nonce, ciphertext }   member -> host
  Posted  { lobby_name, relayed }      host    -> member   (accepted; relayed to N)
  Relay   { lobby_name, nonce, ciphertext }   host -> members  (ciphertext untouched)
  Leave   { lobby_name }               member -> host
  Left    { lobby_name }               host    -> member
  Members { lobby_name }               member -> host
  MemberList { fingerprints }          host    -> member
}
```

Per-lobby state lives in memory on the host: `{ name, key_hash,
members: set of fingerprints, posts }`. Nothing about lobbies is written
to disk except each member's own decrypted post log
(`NEONET_HOME/lobbies/<name>.log`) — and a member can always throw that
away.

## What the host can choose before starting

The host fixes a lobby's customization **at creation**, deliberately not
via a config file/parser the host would cruft up: three plain flags on
`neonet host`.

- `--title <text>`: a display title (defaults to the lobby name). The
  admission reply (`Joined`) carries it, and `neonet join` shows it and
  caches it in the member's roster (`NEONET_HOME/lobbies/roster.json`).
- `--welcome <text>`: one message shown to each member at admission.
- `--max-members <n>`: a hard seat cap. The host itself does not count;
  a join when full gets `Refuse { "lobby is at its member cap" }`.

There is deliberately no post-start mutation — a host that wants
different walls/capacity starts a new room. This matches lobbies being
ephemeral by design (they die with the host) and keeps "options" from
growing a Turing-complete little config language.

## Who can't do what

- A device that isn't the host **cannot** relay an `Relay` — it's dropped
  unless `sender == host` (the same nesting rule the rest of the app uses).
- A `Post` whose `key` doesn't verify (host compares a key hash to the
  one stored at creation) is dropped.
- Known-stale devices are pruned from host memory when their `Leave`
  arrives or their connection drops.

## CLI surface

```text
neonet host  <lobby_name> [--title <text>] [--welcome <text>] [--max-members <n>]
neonet join  <lobby_name> <host_device_id> <lobby_key>   # admitted by the key
neonet lobby post    <lobby_name> <message>
neonet lobby log     <lobby_name>             # decrypted posts this member received
neonet lobby members <lobby_name>             # host answers; members get the list
neonet channel <device_id> [<message>]        # private 1:1 text to an active device
```

Everything else an actual lobby chat would want — moderation, history
before you join, encrypted files in a lobby, room persistence — is out of
scope for now and stays out.