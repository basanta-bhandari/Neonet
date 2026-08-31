//! Wire frames for core-node duties: immutable-chunk replication and key
//! revocation.
//!
//! Replication needs no consensus because chunks are immutable and content
//! addressed — reconciliation is "copy from whichever core has it." Revocation
//! is the architecture's one strong-consistency exception: a revoke record is
//! signalled to every configured core and only applied after the signature and
//! the caller's operator credentials check out, so "eventually consistent"
//! never becomes "insecure" here.

use super::{reply, AppFrame, Handling};
use crate::{identity::PublicIdentity, messaging::Message, node::Node};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoreFrame {
    /// Core A -> core B: the hashes A holds.
    ReconcileRequest {
        hashes: Vec<[u8; 32]>,
    },
    /// B -> A: which of those B is missing.
    ReconcileMissing {
        missing: Vec<[u8; 32]>,
    },
    /// Holder -> peer: store and verify this chunk ("give me this one" is the
    /// inverse direction, covered by the same transfer).
    ChunkData {
        hash: [u8; 32],
        data: Option<Vec<u8>>,
    },
    /// Operator -> every core: apply this revocation (signed by the caller,
    /// who must be in the core's operator set).
    RevokeBroadcast {
        revoked: PublicIdentity,
        epoch: u64,
        #[serde(with = "serde_big_array::BigArray")]
        signature: [u8; 64],
    },
    /// Core -> operator: this core applied it.
    RevokeAck {
        epoch: u64,
    },
    RevokeRefuse {
        epoch: u64,
        reason: String,
    },
    Error {
        message: String,
    },
}

pub async fn handle(node: &Node, request: &Message, frame: CoreFrame) -> io::Result<Handling> {
    match frame {
        CoreFrame::ReconcileRequest { hashes } => {
            // Hold-check against the local content-addressed blob store.
            let root = node.home().join("blobs").join("data");
            let missing = hashes
                .into_iter()
                .filter(|hash| !root.join(format!("{}.blob", hex::encode(hash))).exists())
                .collect::<Vec<_>>();
            let _ = reply(
                node,
                request,
                AppFrame::Core(CoreFrame::ReconcileMissing { missing }),
            )
            .await;
            Ok(Handling::default())
        }
        CoreFrame::ReconcileMissing { missing } => Ok(Handling::notify(format!(
            "peer is missing {} chunk(s)",
            missing.len()
        ))),
        CoreFrame::ChunkData { hash, data } => {
            match data {
                Some(bytes) => {
                    // Verify on arrival regardless of which core relayed it.
                    if blake3::hash(&bytes).as_bytes() != &hash {
                        return Ok(Handling::notify(format!(
                            "core rejected chunk {}: hash mismatch",
                            hex::encode(hash)
                        )));
                    }
                    let root = node.home().join("blobs").join("data");
                    std::fs::create_dir_all(&root)?;
                    let tmp = root.join(format!("{}.blob.tmp", hex::encode(hash)));
                    std::fs::write(&tmp, &bytes)?;
                    std::fs::rename(tmp, root.join(format!("{}.blob", hex::encode(hash))))?;
                    Ok(Handling::notify(format!(
                        "core reconciled chunk {}",
                        hex::encode(hash)
                    )))
                }
                None => Ok(Handling::notify(format!(
                    "peer could not supply chunk {}",
                    hex::encode(hash)
                ))),
            }
        }
        CoreFrame::RevokeBroadcast {
            revoked,
            epoch,
            signature,
        } => {
            // The signature is produced by the directly-authenticated caller;
            // that same identity must be an operator of this core. This keeps
            // revocation the deliberate strong-consistency exception: a core
            // never applies a revoke it cannot attribute to a trusted caller.
            if !operators(node).contains(&request.sender.fingerprint()) {
                let _ = reply(
                    node,
                    request,
                    AppFrame::Core(CoreFrame::RevokeRefuse {
                        epoch,
                        reason: "caller is not an operator of this core".into(),
                    }),
                )
                .await;
                return Ok(Handling::notify(format!(
                    "revocation refused: {} is not an operator",
                    request.sender.fingerprint()
                )));
            }
            let payload = revoke_payload(epoch, &revoked);
            use ed25519_dalek::Verifier;
            let key = match request.sender.verifying_key() {
                Ok(key) => key,
                Err(_) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Core(CoreFrame::RevokeRefuse {
                            epoch,
                            reason: "bad caller key".into(),
                        }),
                    )
                    .await;
                    return Ok(Handling::default());
                }
            };
            if key
                .verify(&payload, &ed25519_dalek::Signature::from_bytes(&signature))
                .is_err()
            {
                let _ = reply(
                    node,
                    request,
                    AppFrame::Core(CoreFrame::RevokeRefuse {
                        epoch,
                        reason: "invalid revocation signature".into(),
                    }),
                )
                .await;
                return Ok(Handling::default());
            }
            super::storage::revoke_identity(node, &revoked)?;
            let _ = reply(
                node,
                request,
                AppFrame::Core(CoreFrame::RevokeAck { epoch }),
            )
            .await;
            Ok(Handling::notify(format!(
                "revoked {}",
                revoked.fingerprint()
            )))
        }
        CoreFrame::RevokeAck { epoch } => Ok(Handling::notify(format!(
            "core acknowledged revocation epoch {epoch}"
        ))),
        CoreFrame::RevokeRefuse { epoch, reason } => Ok(Handling::notify(format!(
            "core refused revocation epoch {epoch}: {reason}"
        ))),
        CoreFrame::Error { message } => Ok(Handling::notify(format!("core error: {message}"))),
    }
}

/// Operator allow-list (fingerprints). Revocation is rejected unless the
/// authenticated calling identity is listed here. Empty means nobody can revoke
/// through this core, failing closed.
pub fn operators(node: &Node) -> HashSet<String> {
    let path = node.home().join("operators.json");
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => HashSet::new(),
    }
}

pub fn set_operator(node: &Node, identity: &PublicIdentity) -> io::Result<()> {
    let mut set = operators(node);
    set.insert(identity.fingerprint());
    let bytes = serde_json::to_vec(&set)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let path = node.home().join("operators.json");
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

/// Deterministic bytes a revocation signature covers. Both the signing CLI and
/// every applying core derive this identically from the epoch and target, so
/// no shared session state is needed.
pub fn revoke_payload(epoch: u64, revoked: &PublicIdentity) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&epoch.to_le_bytes());
    payload.extend_from_slice(&revoked.public_key);
    payload
}
