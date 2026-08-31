//! Wire frames for file transfer over the authenticated messaging substrate.
//!
//! The sender announces a signed manifest; the receiver replies with the set
//! of chunks it still needs (empty on first receipt, non-empty when resuming);
//! the sender streams them; every chunk is BLAKE3-verified by the receiver on
//! arrival regardless of which relay or core carried it. On a dropped
//! connection the receiver persists its verified set, so resuming never starts
//! from zero.

use super::{reply, AppFrame, Handling};
use crate::{
    files::{FileManifest, ReceiveStatus, TransferState},
    messaging::Message,
    node::Node,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum FilesFrame {
    /// Sender -> receiver: "a file with this signed manifest exists."
    Announce {
        manifest_id: String,
        manifest: FileManifest,
        sender_name: String,
    },
    /// Receiver -> sender: "send these chunks (empty = all, non-empty = resume)."
    Accept {
        manifest_id: String,
        missing: Vec<u32>,
    },
    /// Sender -> receiver: one content chunk.
    Chunk {
        manifest_id: String,
        chunk: crate::files::Chunk,
    },
    /// Receiver -> sender after a chunk failed verification.
    Reject {
        manifest_id: String,
        index: u32,
        reason: String,
    },
    /// Receiver -> sender: all chunks verified, transfer complete.
    Complete { manifest_id: String },
    /// Either side asking the peer for the current transfer state (`neonet transfers`).
    StatusRequest { manifest_id: String },
    Status {
        manifest_id: String,
        state: TransferState,
    },
    Error {
        manifest_id: Option<String>,
        message: String,
    },
}

impl FilesFrame {
    fn error(manifest_id: Option<String>, message: impl Into<String>) -> Self {
        Self::Error {
            manifest_id,
            message: message.into(),
        }
    }
}

pub async fn handle(
    node: &Node,
    request: &Message,
    frame: FilesFrame,
) -> std::io::Result<Handling> {
    match frame {
        FilesFrame::Announce {
            manifest_id,
            manifest,
            sender_name,
        } => {
            let result = crate::files::verify_manifest(&manifest)
                .and_then(|_| {
                    crate::files::write_received_manifest(node.home(), &manifest_id, &manifest)
                })
                .and_then(|_| crate::files::resume_for(node.home(), &manifest_id, &manifest));
            match result {
                Ok(state) => {
                    let missing_now = state.missing().collect::<Vec<u32>>();
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Files(FilesFrame::Accept {
                            manifest_id: manifest_id.clone(),
                            missing: missing_now.clone(),
                        }),
                    )
                    .await;
                    Ok(Handling::notify(format!(
                        "file transfer from {sender_name}: {name} ({size} bytes, {n} chunks; {missing_count} to fetch)",
                        name = manifest.name,
                        size = manifest.total_size,
                        n = manifest.chunks.len(),
                        missing_count = missing_now.len(),
                    )))
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Files(FilesFrame::error(Some(manifest_id), e.to_string())),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        FilesFrame::Accept {
            manifest_id,
            missing,
        } => {
            let pending = if missing.is_empty() {
                "all chunks".to_string()
            } else {
                format!("{} chunk(s): {:?}", missing.len(), missing)
            };
            Ok(Handling::notify(format!(
                "receiving file {manifest_id}; {pending} requested"
            )))
        }
        FilesFrame::Chunk { manifest_id, chunk } => {
            let outcome = crate::files::receive_chunk(node.home(), &manifest_id, &chunk);
            match outcome {
                Ok(ReceiveStatus::Verified { complete }) => {
                    if complete {
                        let _ = reply(
                            node,
                            request,
                            AppFrame::Files(FilesFrame::Complete {
                                manifest_id: manifest_id.clone(),
                            }),
                        )
                        .await;
                        Ok(Handling::notify(format!(
                            "file transfer complete: {manifest_id}"
                        )))
                    } else {
                        Ok(Handling::default())
                    }
                }
                Ok(ReceiveStatus::NeedsResend { index, reason }) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Files(FilesFrame::Reject {
                            manifest_id: manifest_id.clone(),
                            index,
                            reason,
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Files(FilesFrame::error(Some(manifest_id), e.to_string())),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        FilesFrame::Reject {
            manifest_id,
            index,
            reason,
        } => {
            eprintln!("[neonet] chunk {index} of {manifest_id} rejected by peer: {reason}");
            Ok(Handling::default())
        }
        FilesFrame::Complete { manifest_id } => Ok(Handling::notify(format!(
            "file transfer complete (confirmed by peer): {manifest_id}"
        ))),
        FilesFrame::StatusRequest { manifest_id } => {
            match crate::files::load_transfer_state(node.home(), &manifest_id) {
                Ok(state) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Files(FilesFrame::Status { manifest_id, state }),
                    )
                    .await;
                    Ok(Handling::default())
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Files(FilesFrame::error(Some(manifest_id), e.to_string())),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        FilesFrame::Status { manifest_id, state } => Ok(Handling::notify(format!(
            "{manifest_id}: {}/{} chunks verified, {} lost",
            state.verified_chunks.len(),
            state.manifest.chunks.len(),
            state.lost_chunks.len(),
        ))),
        FilesFrame::Error { message, .. } => {
            Ok(Handling::notify(format!("file transfer error: {message}")))
        }
    }
}

/// Client-side, single connection attempt: announce, then stream every chunk
/// the receiver still needs, then return the transfer state.
pub async fn send_file(
    peer: &crate::identity::PublicIdentity,
    client: &mut super::Client,
    source: std::path::PathBuf,
) -> Result<TransferState, std::io::Error> {
    let (manifest, chunks) = crate::files::build_manifest(
        &source,
        client.node().local(),
        crate::files::DEFAULT_CHUNK_SIZE,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let manifest_id = crate::files::manifest_id(&manifest);
    let announce = AppFrame::Files(FilesFrame::Announce {
        manifest_id: manifest_id.clone(),
        manifest: manifest.clone(),
        sender_name: client.node().identity().fingerprint(),
    });
    let accept = client.call(peer, announce).await?;
    let missing = match AppFrame::decode(&accept.payload) {
        AppFrame::Files(FilesFrame::Accept { missing, .. }) => missing,
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected Accept reply, got {other:?}"),
            ));
        }
    };

    let need: std::collections::HashSet<u32> = missing.into_iter().collect();
    for chunk in chunks
        .iter()
        .filter(|c| need.is_empty() || need.contains(&c.index))
    {
        let payload = AppFrame::Files(FilesFrame::Chunk {
            manifest_id: manifest_id.clone(),
            chunk: chunk.clone(),
        })
        .encode()?;
        let message =
            crate::messaging::Message::new(client.node().identity(), peer.clone(), payload)?;
        client.node().send_raw(message).await?;
    }

    let mut state = crate::files::TransferState::new(manifest.clone());
    for chunk in &chunks {
        state.mark_verified(chunk.index);
    }
    Ok(state)
}

/// Stream a file (like `send_file`) then poll the peer for authoritative
/// status, re-sending any chunk the receiver is still missing, until the
/// transfer completes, is rejected, or `timeout` elapses. Returns the final
/// known state — partial on timeout, so a subsequent invocation resumes rather
/// than restarts.
pub async fn send_file_and_wait(
    peer: &crate::identity::PublicIdentity,
    client: &mut super::Client,
    source: std::path::PathBuf,
    timeout: std::time::Duration,
) -> Result<TransferState, std::io::Error> {
    let (manifest, chunks) = crate::files::build_manifest(
        &source,
        client.node().local(),
        crate::files::DEFAULT_CHUNK_SIZE,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let _ = send_file(peer, client, source).await?;
    let manifest_id = crate::files::manifest_id(&manifest);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = client
            .call(
                peer,
                AppFrame::Files(FilesFrame::StatusRequest {
                    manifest_id: manifest_id.clone(),
                }),
            )
            .await?;
        let state = match AppFrame::decode(&status.payload) {
            AppFrame::Files(FilesFrame::Status { state, .. }) => state,
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("expected Status reply, got {other:?}"),
                ));
            }
        };
        if state.complete() || std::time::Instant::now() >= deadline {
            return Ok(state);
        }
        let missing: std::collections::HashSet<u32> = state.missing().collect();
        for chunk in chunks.iter().filter(|c| missing.contains(&c.index)) {
            let payload = AppFrame::Files(FilesFrame::Chunk {
                manifest_id: manifest_id.clone(),
                chunk: chunk.clone(),
            })
            .encode()?;
            let message =
                crate::messaging::Message::new(client.node().identity(), peer.clone(), payload)?;
            client.node().send_raw(message).await?;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}
