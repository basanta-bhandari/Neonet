# Runnable node milestone

`src/node.rs` is the bridge between the previously isolated libraries and an actual TCP process.

## Inbound

`Node::serve()` binds a TCP listener. Each accepted connection gets an authenticated handshake. The remote public identity is then checked against an optional allow-list before the connection is promoted to a messaging route.

## Outbound

`Node::dial()` connects to configured bootstrap addresses and calls the bootstrap-aware handshake. The remote public key must equal the pinned key for the actual peer address.

## Messaging

After authentication, the connection is split into reader/writer tasks. The reader rejects application messages whose claimed sender does not equal the authenticated remote identity. The router then chooses local delivery, a configured next hop, or bounded offline storage.

## Important boundary

This milestone establishes a real networked node. It does not silently claim that every higher-level v1 protocol has been wired to the network. Distributed file transfer, Burrow, encrypted storage replication, and core-to-core reconciliation remain separate milestones.
