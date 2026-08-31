# Implementation notes

## Foundation

Identity is generated on first run and stored locally. Bootstrap trust is an
address plus pinned public key. The protocol handshake negotiates a common
major/minor version and the intersection of feature flags. The challenge
signature covers the complete Hello plus the challenge nonce, binding identity,
session, version, and features to the proof.

## Messaging

The transport authenticates the connection; the application envelope repeats
the sender identity and the receiver checks equality with the authenticated
identity. This prevents a connected peer from claiming to be another device.
Offline messages are bounded per recipient identity and delivered FIFO on
reconnect. A next-hop table is provided for core relay.

## File transfer

A sender chunks a file and computes BLAKE3 for every chunk. The manifest contains
ordered hashes and total size and is signed by the sender identity. A receiver
verifies each chunk independently and tracks verified chunks so a dropped
transfer can resume. The retry coordinator tries alternate sources up to a
fixed budget and records chunks that remain unavailable as lost.

## Burrow

The reference API performs metadata-only listings and explicit reads/forks. Path
resolution is rooted and rejects traversal outside the configured share. The
server API contains no write primitive. A platform-specific filesystem mount is
an adapter concern; the security boundary remains the read-only share API.

## SSH Redirector

The resolution directory maps alias or public-key fingerprint to host, port,
and known-hosts file. The implementation then invokes `ssh`; it does not parse,
implement, or tunnel the SSH protocol itself.

## Encrypted storage

Plaintext chunks are encrypted with XChaCha20-Poly1305 before transfer. The
nonce is unique per encrypted chunk and the chunk index is authenticated as
AAD. Core storage receives only the serialized opaque encrypted chunk. The
local key store is intentionally client-only.

## Core consistency

Immutable chunk data uses content addressing, so reconciliation is a missing-
chunk copy operation rather than a consensus protocol. ACL checks happen at
the core that serves the request. Revocation is represented separately because
it is the live/strong-consistency exception in the architecture.
