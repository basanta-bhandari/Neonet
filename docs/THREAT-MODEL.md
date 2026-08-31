# v1 security boundary

NeoNet authenticates devices by persistent Ed25519 identity rather than IP,
hostname, or MAC address. Bootstrap trust is out-of-band and pins public keys.

Relay nodes are not implicitly trusted for file content: receivers hash-check
chunks. For encrypted storage, relay/core operators cannot decrypt the client-
encrypted blobs because the decryption key remains on the client.

This does not protect against a compromised client, theft of the client's
private/storage keys, or a user explicitly granting access through ACLs. The
architecture treats revocation as the mechanism for removing access, not as a
property of the encryption layer.
