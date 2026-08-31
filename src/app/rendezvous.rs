//! Wire frames for the rendezvous service.
//!
//! A core node with the `rendezvous/1` feature can hold live identity ->
//! address records. Registration is **signed by the device's own identity**, so
//! nobody can claim an address for someone else's public key — this is the
//! answer to "who may register a mapping." Lookup returns candidates and the
//! connecting party still verifies the pinned public key after dialing, so a
//! rendezvous can suggest but never impersonate.

use super::{reply, AppFrame, Handling};
use crate::{identity::PublicIdentity, messaging::Message, node::Node};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointRecord {
    pub identity: PublicIdentity,
    pub address: String,
    pub last_seen: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RendezvousFrame {
    /// Edge -> rendezvous: "I am at this address" (signed by the claimed
    /// identity; `ttl_secs` bounds how long the record lives).
    Register {
        address: String,
        ttl_secs: u32,
        #[serde(with = "serde_big_array::BigArray")]
        signature: [u8; 64],
    },
    /// Rendezvous -> edge: record accepted.
    Registered,
    /// Client -> rendezvous: "who is currently at this fingerprint?"
    Lookup {
        fingerprint: String,
    },
    /// Rendezvous -> client: current candidates (never more than the peer's
    /// own claim; the client still pin-verifies on connect).
    LookupResult {
        fingerprint: String,
        candidates: Vec<EndpointRecord>,
    },
    /// Client -> rendezvous: "enumerate every live record" (`neonet scan`).
    List,
    /// Rendezvous -> client: all non-expired records.
    ListResult {
        records: Vec<EndpointRecord>,
    },
    /// Client -> rendezvous: is this peer live right now? (`scan -active`).
    Probe {
        fingerprint: String,
    },
    /// Rendezvous -> client: probe result.
    ProbeResult {
        fingerprint: String,
        alive: bool,
    },
    Error {
        message: String,
    },
}

pub async fn handle(
    node: &Node,
    request: &Message,
    frame: RendezvousFrame,
) -> io::Result<Handling> {
    match frame {
        RendezvousFrame::Register {
            address,
            ttl_secs,
            signature,
        } => {
            // The signature must be over `address`, produced by the
            // authenticated caller. Because the transport already proved the
            // caller owns its key, this means a device can only register an
            // endpoint *for itself* — the anti-spoof property.
            use ed25519_dalek::Verifier;
            let key = match request.sender.verifying_key() {
                Ok(key) => key,
                Err(_) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Rendezvous(RendezvousFrame::Error {
                            message: "bad caller key".into(),
                        }),
                    )
                    .await;
                    return Ok(Handling::default());
                }
            };
            if key
                .verify(
                    address.as_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .is_err()
            {
                let _ = reply(
                    node,
                    request,
                    AppFrame::Rendezvous(RendezvousFrame::Error {
                        message: "registration signature invalid".into(),
                    }),
                )
                .await;
                return Ok(Handling::default());
            }
            register(node, request.sender.clone(), address, ttl_secs)?;
            let _ = reply(
                node,
                request,
                AppFrame::Rendezvous(RendezvousFrame::Registered),
            )
            .await;
            Ok(Handling::default())
        }
        RendezvousFrame::Lookup { fingerprint } => {
            let candidates = lookup(node, &fingerprint);
            let _ = reply(
                node,
                request,
                AppFrame::Rendezvous(RendezvousFrame::LookupResult {
                    fingerprint,
                    candidates,
                }),
            )
            .await;
            Ok(Handling::default())
        }
        RendezvousFrame::List => {
            let records = list(node);
            let _ = reply(
                node,
                request,
                AppFrame::Rendezvous(RendezvousFrame::ListResult { records }),
            )
            .await;
            Ok(Handling::default())
        }
        RendezvousFrame::Probe { fingerprint } => {
            let alive = !lookup(node, &fingerprint).is_empty();
            let _ = reply(
                node,
                request,
                AppFrame::Rendezvous(RendezvousFrame::ProbeResult { fingerprint, alive }),
            )
            .await;
            Ok(Handling::default())
        }
        RendezvousFrame::Registered => Ok(Handling::notify("registered with rendezvous")),
        RendezvousFrame::ListResult { .. } => Ok(Handling::default()),
        RendezvousFrame::LookupResult {
            fingerprint,
            candidates,
        } => {
            let mut out = Vec::new();
            for c in &candidates {
                out.push(format!("{} @ {}", c.identity.fingerprint(), c.address));
            }
            let body = if out.is_empty() {
                "(none)".to_string()
            } else {
                out.join("\n")
            };
            Ok(Handling::notify(format!(
                "rendezvous lookup {fingerprint}:\n{body}"
            )))
        }
        RendezvousFrame::ProbeResult { fingerprint, alive } => Ok(Handling::notify(format!(
            "probe {fingerprint}: {}",
            if alive { "alive" } else { "not found" }
        ))),
        RendezvousFrame::Error { message } => {
            Ok(Handling::notify(format!("rendezvous error: {message}")))
        }
    }
}

const DEFAULT_TTL: u64 = 6 * 3600;
const MAX_TTL: u64 = 24 * 3600;

fn register(
    node: &Node,
    identity: PublicIdentity,
    address: String,
    ttl_secs: u32,
) -> io::Result<()> {
    let now = unix_now();
    let ttl = (ttl_secs as u64).clamp(60, MAX_TTL);
    let mut records = all_records(node);
    let expires_at = now + ttl;
    records.insert(
        identity.fingerprint(),
        EndpointRecord {
            identity,
            address,
            last_seen: now,
            expires_at,
        },
    );
    prune(&mut records, now);
    write_records(node, &records)
}

fn lookup(node: &Node, fingerprint: &str) -> Vec<EndpointRecord> {
    let now = unix_now();
    let mut records = all_records(node);
    prune(&mut records, now);
    records
        .into_iter()
        .filter(|(fp, _)| fp == fingerprint)
        .map(|(_, record)| record)
        .collect()
}

/// Every live record, oldest first (used by `scan`).
fn list(node: &Node) -> Vec<EndpointRecord> {
    let now = unix_now();
    let mut records = all_records(node);
    prune(&mut records, now);
    let mut records = records.into_values().collect::<Vec<_>>();
    records.sort_by_key(|record| record.last_seen);
    records
}

fn prune(records: &mut std::collections::HashMap<String, EndpointRecord>, now: u64) {
    records.retain(|_, record| record.expires_at > now);
}

fn all_records(node: &Node) -> std::collections::HashMap<String, EndpointRecord> {
    let path = node.home().join("rendezvous.json");
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => std::collections::HashMap::new(),
    }
}

fn write_records(
    node: &Node,
    records: &std::collections::HashMap<String, EndpointRecord>,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(records)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let path = node.home().join("rendezvous.json");
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The other side of `scan -active`: build the signed register/lookup frames.
pub fn register_frame(node: &Node, address: String) -> RendezvousFrame {
    register_frame_with_ttl(node, address, DEFAULT_TTL as u32)
}

/// Signed registration honoring the caller's requested TTL (clamped to the
/// service's bounds server-side).
pub fn register_frame_with_ttl(node: &Node, address: String, ttl_secs: u32) -> RendezvousFrame {
    let signature = node.local().sign(address.as_bytes());
    RendezvousFrame::Register {
        address,
        ttl_secs,
        signature,
    }
}
