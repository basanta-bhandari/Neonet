# NeoNet v1 development bundle

This bundle is the corrected runnable-node milestone, not a claim that every v1 feature is production complete.

## Runnable node

Build with Rust/Cargo:

```text
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- whoami
```

Start a core:

```text
cargo run -- core --listen 0.0.0.0:4242
```

Start an edge with a bootstrap trust file:

```text
cargo run -- edge --bootstrap ~/.neonet/bootstrap.json
```

The node performs the authenticated Ed25519 handshake, validates bootstrap pinning on outbound connections, accepts authenticated inbound connections, pumps framed messaging, and exposes local message delivery. `node.rs` is intentionally a wiring layer over the existing identity, transport, bootstrap, and messaging modules.

## Current milestone boundary

Implemented and wired:

- persistent Ed25519 identity;
- bootstrap address + pinned public key;
- protocol negotiation and mutual signed challenge;
- real TCP listener/client;
- authenticated inbound/outbound messaging;
- bounded per-identity offline queues;
- core/edge node process entry points;
- platform service installers that can be run from an installer USB and can carry bootstrap trust data;
- file transfer (`send`/`transfers`/`browse`/`fork`), Burrow file exchange;
- encrypted storage tunnel (`store push`/`pull`, chunk-batch paged);
- core replication + signed revocation (`replicate`/`revoke`), operator allow-list (`--allow-file`, `operator`);
- rendezvous service (`register`/`scan`);
- flash pairing, single-use active-confirmation token (`pair`/`flash`/`pairs`);
- lobbies and channels (`host`/`join`/`lobby`/`channel`) per `docs/LOBBY_DESIGN.md`;
  hosts pick each lobby's title, welcome message, and member cap at creation;
- SSH Redirector (`nsh`);
- the interactive DOS-style shell (`neonet shell`): a persistent virtual drive
  plus a mountable remote drive reading any device's Burrow share, rewritten
  in Rust from the pydos concept (no Python, no pip, no bundled interpreter).

Full command reference: `docs/CLI.md`. Shell behavior and persistence are
described in the `neonet shell` section there.

## Debugging order

1. `cargo test`
2. run a core locally;
3. inspect its fingerprint/public key;
4. create a bootstrap file pinning that key;
5. run an edge against that bootstrap;
6. test a deliberately wrong pinned key and confirm rejection;
7. exercise messaging (and `channel`) before moving on to distributed file/Burrow/storage/lobby protocols.
