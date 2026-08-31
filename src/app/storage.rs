//! Wire frames for encrypted storage tunneling.
//!
//! The client encrypts each chunk with XChaCha20-Poly1305 under a key that
//! never leaves the client, then pushes opaque blobs to one or more core(s);
//! a serving core stores them by content hash and can never decrypt them.
//! Reads are gated on (a) the requester being in the file's reader ACL and
//! (b) the requester not being revoked — both checked at the serving core,
//! never inherited from an upstream relay.

use super::{reply, AppFrame, Handling};
use crate::{files::FileManifest, identity::PublicIdentity, messaging::Message, node::Node};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, io};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageFrame {
    /// Client -> core: persist these opaque, already-encrypted chunks for a file.
    StoreChunks {
        file_id: String,
        manifest: FileManifest,
        chunks: Vec<crate::storage::EncryptedChunk>,
    },
    /// Core -> client: stored (or already present).
    StoreAck { file_id: String },
    /// Client -> core: return the next page of chunks this core holds for
    /// `file_id`, starting at `offset` (a chunk index). Paging keeps a reply
    /// under the transport's 1 MiB cap even for large files.
    FetchChunks { file_id: String, offset: u32 },
    /// Core -> client: chunks held by this core (a subset of the whole file —
    /// sharding is a client decision).
    StoredChunks {
        file_id: String,
        manifest: Option<FileManifest>,
        chunks: Vec<crate::storage::EncryptedChunk>,
    },
    /// Either side: an error.
    Error { message: String },
}

pub async fn handle(node: &Node, request: &Message, frame: StorageFrame) -> io::Result<Handling> {
    match frame {
        StorageFrame::StoreChunks {
            file_id,
            manifest,
            chunks,
        } => {
            let outcome = store_chunks(node, request.sender.clone(), &file_id, &manifest, &chunks);
            match outcome {
                Ok(()) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Storage(StorageFrame::StoreAck { file_id }),
                    )
                    .await;
                    Ok(Handling::default())
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Storage(StorageFrame::Error {
                            message: e.to_string(),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        StorageFrame::FetchChunks { file_id, offset } => {
            match fetch_chunks(node, request.sender.clone(), &file_id, offset) {
                Ok((manifest, chunks)) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Storage(StorageFrame::StoredChunks {
                            file_id,
                            manifest,
                            chunks,
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
                Err(e) => {
                    let _ = reply(
                        node,
                        request,
                        AppFrame::Storage(StorageFrame::Error {
                            message: e.to_string(),
                        }),
                    )
                    .await;
                    Ok(Handling::default())
                }
            }
        }
        StorageFrame::StoreAck { file_id } => {
            Ok(Handling::notify(format!("storage acknowledged: {file_id}")))
        }
        StorageFrame::StoredChunks {
            file_id, chunks, ..
        } => Ok(Handling::notify(format!(
            "core holds {} encrypted chunk(s) for {file_id}",
            chunks.len()
        ))),
        StorageFrame::Error { message } => {
            Ok(Handling::notify(format!("storage error: {message}")))
        }
    }
}

fn store_chunks(
    node: &Node,
    requester: PublicIdentity,
    file_id: &str,
    manifest: &FileManifest,
    chunks: &[crate::storage::EncryptedChunk],
) -> io::Result<()> {
    if manifest.verify_signature().is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "manifest signature is invalid",
        ));
    }
    let root = node.home().join("blobs").join(file_id);
    if node_is_revoked(node, &requester) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requester is revoked",
        ));
    }
    std::fs::create_dir_all(&root)?;

    // Content-addressed: a blob's storage id is the hash of its serialized
    // ciphertext, so the store is immutable and deduplicated.
    for chunk in chunks {
        let bytes = postcard::to_allocvec(chunk).map_err(codec)?;
        let id = blake3::hash(&bytes).to_hex().to_string();
        let tmp = root.join(format!("{id}.tmp"));
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(tmp, root.join(id))?;
    }

    // Persist the (already-signed) manifest, then the ACL: the store's readers
    // are the uploader by default.
    std::fs::write(
        root.join("manifest.json"),
        postcard::to_allocvec(manifest).map_err(codec)?,
    )?;
    let mut acl = read_acl(node, file_id)?;
    acl.insert(requester.fingerprint());
    write_acl(node, file_id, &acl)?;
    Ok(())
}

fn fetch_chunks(
    node: &Node,
    requester: PublicIdentity,
    file_id: &str,
    offset: u32,
) -> io::Result<(Option<FileManifest>, Vec<crate::storage::EncryptedChunk>)> {
    if node_is_revoked(node, &requester) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "requester is revoked",
        ));
    }
    let acl = read_acl(node, file_id)?;
    if !acl.contains(&requester.fingerprint()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not in the reader ACL for this file",
        ));
    }
    let root = node.home().join("blobs").join(file_id);
    if !root.is_dir() {
        return Ok((None, Vec::new()));
    }
    let manifest = std::fs::read(root.join("manifest.json"))
        .ok()
        .and_then(|bytes| postcard::from_bytes(&bytes).ok());

    let mut held = Vec::new();
    for entry in std::fs::read_dir(&root)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "manifest.json" || name.ends_with(".tmp") || name == "acl.json" {
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        if let Ok(chunk) = postcard::from_bytes::<crate::storage::EncryptedChunk>(&bytes) {
            // The receiver re-verifies the hash over the ciphertext regardless
            // of which core served it.
            held.push(chunk);
        }
    }
    held.sort_by_key(|chunk| chunk.index);

    // Page out from `offset`, stopping before the reply would exceed the
    // transport cap. The client keeps paging until it has every chunk.
    let mut page = Vec::new();
    let mut budget: usize = MAX_BATCH_PAYLOAD;
    for chunk in held.into_iter().skip(offset as usize) {
        let size = postcard::to_allocvec(&chunk).map_err(codec)?.len();
        if !page.is_empty() && budget < size {
            break;
        }
        page.push(chunk);
        budget = budget.saturating_sub(size);
    }
    Ok((manifest, page))
}

fn read_acl(node: &Node, file_id: &str) -> io::Result<HashSet<String>> {
    let path = node.home().join("blobs").join(file_id).join("acl.json");
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn write_acl(node: &Node, file_id: &str, acl: &HashSet<String>) -> io::Result<()> {
    let root = node.home().join("blobs").join(file_id);
    std::fs::create_dir_all(&root)?;
    let bytes = serde_json::to_vec(acl)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(root.join("acl.json"), bytes)
}

/// Revocation check shared with the core handler: reads the persisted
/// revocation set under the node's home. `node_is_revoked` is deliberately
/// strict — it fails closed if the set cannot be read.
pub fn node_is_revoked(node: &Node, identity: &PublicIdentity) -> bool {
    revoked_set(node).contains(&identity.fingerprint())
}

pub fn revoked_set(node: &Node) -> HashSet<String> {
    let path = node.home().join("revocations.json");
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => HashSet::new(),
    }
}

pub fn revoke_identity(node: &Node, identity: &PublicIdentity) -> io::Result<()> {
    let mut set = revoked_set(node);
    set.insert(identity.fingerprint());
    let bytes = serde_json::to_vec(&set)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let path = node.home().join("revocations.json");
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)
}

fn codec(e: postcard::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Upper bound on one STORE request's serialized size; keeps frames under the
/// 1 MiB transport cap no matter how large the file being stored is.
const MAX_BATCH_PAYLOAD: usize = 900 * 1024;

/// Push encrypted chunks to `peer`, batching greedily so every store frame
/// stays under the messaging size cap. Each batch is acknowledged before the
/// next is sent; the store is content-addressed and idempotent, so a re-push
/// (resume) is safe.
pub async fn push_chunks(
    peer: &crate::identity::PublicIdentity,
    client: &mut super::Client,
    file_id: &str,
    manifest: &FileManifest,
    encrypted: &[crate::storage::EncryptedChunk],
) -> io::Result<()> {
    let sizes: Vec<usize> = encrypted
        .iter()
        .map(|chunk| {
            postcard::to_allocvec(chunk)
                .map_err(codec)
                .map(|bytes| bytes.len())
        })
        .collect::<io::Result<_>>()?;

    let mut batches: Vec<Vec<crate::storage::EncryptedChunk>> = Vec::new();
    let mut carried: usize = 0;
    for (chunk, size) in encrypted.iter().zip(sizes.iter()) {
        if batches.is_empty() || carried + size > MAX_BATCH_PAYLOAD {
            batches.push(Vec::new());
            carried = 0;
        }
        batches.last_mut().unwrap().push(chunk.clone());
        carried += size;
    }

    for batch in batches {
        let reply = client
            .call(
                peer,
                AppFrame::Storage(StorageFrame::StoreChunks {
                    file_id: file_id.to_string(),
                    manifest: manifest.clone(),
                    chunks: batch,
                }),
            )
            .await?;
        match AppFrame::decode(&reply.payload) {
            AppFrame::Storage(StorageFrame::StoreAck { .. }) => {}
            AppFrame::Storage(StorageFrame::Error { message }) => {
                return Err(io::Error::other(message));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected store reply: {other:?}"),
                ));
            }
        }
    }
    Ok(())
}

/// Fetch every chunk `peer` holds for `file_id`, paging so no single reply can
/// exceed the messaging cap. Returns the stored manifest and all chunks sorted
/// by index, or an error if the store did not return them all.
pub async fn pull_chunks(
    peer: &crate::identity::PublicIdentity,
    client: &mut super::Client,
    file_id: &str,
) -> io::Result<(FileManifest, Vec<crate::storage::EncryptedChunk>)> {
    let mut manifest: Option<FileManifest> = None;
    let mut collected = Vec::new();
    let mut offset = 0u32;
    loop {
        let reply = client
            .call(
                peer,
                AppFrame::Storage(StorageFrame::FetchChunks {
                    file_id: file_id.to_string(),
                    offset,
                }),
            )
            .await?;
        let (page_manifest, page) = match AppFrame::decode(&reply.payload) {
            AppFrame::Storage(StorageFrame::StoredChunks {
                manifest, chunks, ..
            }) => (manifest, chunks),
            AppFrame::Storage(StorageFrame::Error { message }) => {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected fetch reply: {other:?}"),
                ));
            }
        };
        if manifest.is_none() {
            manifest = page_manifest;
        }
        let page_len = page.len();
        offset = offset.saturating_add(page_len as u32);
        collected.extend(page);

        let expected = manifest
            .as_ref()
            .map(|manifest| manifest.chunks.len())
            .unwrap_or(0);
        if expected > 0 && collected.len() >= expected {
            break;
        }
        if page_len == 0 {
            break;
        }
    }
    let manifest = manifest.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{file_id} not stored at this core"),
        )
    })?;
    if collected.len() != manifest.chunks.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "core returned {} of {} chunks for {file_id}",
                collected.len(),
                manifest.chunks.len()
            ),
        ));
    }
    collected.sort_by_key(|chunk| chunk.index);
    Ok((manifest, collected))
}
