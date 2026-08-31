# Debugging checklist

1. Run `cargo fmt --check` and `cargo test`.
2. Run `cargo clippy --all-targets --all-features -- -D warnings`.
3. Start two local processes with separate `NEONET_HOME` directories.
4. Confirm each identity fingerprint is stable across restart.
5. Exchange bootstrap entries containing the peer's real public key.
6. Exercise a TCP handshake and verify a wrong pin is rejected.
7. Send a message with a deliberately mismatched sender identity and verify it
   is rejected.
8. Fill an offline queue beyond capacity and confirm the oldest message is the
   one evicted.
9. Build a file manifest, mutate a chunk, and confirm verification fails.
10. Interrupt a transfer and resume from the recorded verified chunk set.
11. Encrypt a chunk, confirm its ciphertext differs from plaintext, then
    decrypt locally and verify the original BLAKE3 hash.
12. Attempt Burrow traversal such as `../outside` and confirm rejection.
13. Attempt to fork a symlink and confirm rejection.
14. Configure SSH resolution and verify NeoNet only constructs an OpenSSH
    command; inspect known_hosts handling before connecting to real machines.

## Known fixes in build-v3

- `Burrow::list(".")` now correctly addresses the share root. The previous
  path guard canonicalized `candidate.parent()`, which is the parent of the
  share root for `.` and incorrectly rejected the request.
- Burrow path validation now rejects absolute paths and lexical `..`
  components before resolving the filesystem parent, while preserving
  `symlink_metadata` behavior for the final component.
- The TCP node integration test waits for the authenticated next-hop route
  instead of sleeping for a fixed 50ms. This removes a scheduling race where
  the test could send before the handshake had installed the route.
- Removed the unused mutable CLI variable warning.

Run locally:

    cargo check
    cargo test
    cargo clippy --all-targets --all-features -- -D warnings
