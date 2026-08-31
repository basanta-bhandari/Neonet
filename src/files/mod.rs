//! Content-addressed file primitives shared by file transfer, Burrow, and storage.
//! The manifest is signed by the sender; individual chunks are verified by BLAKE3.

use crate::identity::Identity;
use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

pub const DEFAULT_CHUNK_SIZE: usize = 768 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifest {
    pub version: u16,
    pub name: String,
    pub total_size: u64,
    pub chunk_size: u32,
    pub chunks: Vec<[u8; 32]>,
    pub signer: crate::identity::PublicIdentity,
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Chunk {
    pub index: u32,
    pub hash: [u8; 32],
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("codec: {0}")]
    Codec(String),
    #[error("chunk {0} hash mismatch")]
    HashMismatch(u32),
    #[error("manifest signature invalid")]
    InvalidSignature,
    #[error("chunk index out of range")]
    InvalidIndex,
}

impl FileManifest {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, FileError> {
        let mut copy = self.clone();
        copy.signature = [0; 64];
        postcard::to_allocvec(&copy).map_err(|e| FileError::Codec(e.to_string()))
    }

    pub fn verify_signature(&self) -> Result<(), FileError> {
        use ed25519_dalek::Verifier;
        let key = self
            .signer
            .verifying_key()
            .map_err(|_| FileError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.signature);
        key.verify(&self.unsigned_bytes()?, &sig)
            .map_err(|_| FileError::InvalidSignature)
    }
}

pub fn build_manifest(
    path: impl AsRef<Path>,
    identity: &Identity,
    chunk_size: usize,
) -> Result<(FileManifest, Vec<Chunk>), FileError> {
    if chunk_size == 0 || chunk_size > u32::MAX as usize {
        return Err(FileError::InvalidIndex);
    }
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let total_size = file.metadata()?.len();
    let mut chunks = Vec::new();
    let mut hashes = Vec::new();
    let mut index = 0u32;
    loop {
        let mut data = vec![0u8; chunk_size];
        let n = file.read(&mut data)?;
        if n == 0 {
            break;
        }
        data.truncate(n);
        let hash = blake3::hash(&data);
        hashes.push(*hash.as_bytes());
        chunks.push(Chunk {
            index,
            hash: *hash.as_bytes(),
            data,
        });
        index = index.checked_add(1).ok_or(FileError::InvalidIndex)?;
    }
    let mut manifest = FileManifest {
        version: 1,
        name: path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("unnamed")
            .to_owned(),
        total_size,
        chunk_size: chunk_size as u32,
        chunks: hashes,
        signer: identity.public(),
        signature: [0; 64],
    };
    manifest.signature = identity.sign(&manifest.unsigned_bytes()?);
    Ok((manifest, chunks))
}

pub fn verify_chunk(manifest: &FileManifest, chunk: &Chunk) -> Result<(), FileError> {
    let expected = manifest
        .chunks
        .get(chunk.index as usize)
        .ok_or(FileError::InvalidIndex)?;
    if expected != &chunk.hash || blake3::hash(&chunk.data).as_bytes() != expected {
        return Err(FileError::HashMismatch(chunk.index));
    }
    Ok(())
}

pub struct ResumeState {
    verified: Vec<bool>,
}
impl ResumeState {
    pub fn new(manifest: &FileManifest) -> Self {
        Self {
            verified: vec![false; manifest.chunks.len()],
        }
    }
    pub fn mark_verified(
        &mut self,
        manifest: &FileManifest,
        chunk: &Chunk,
    ) -> Result<(), FileError> {
        verify_chunk(manifest, chunk)?;
        self.verified[chunk.index as usize] = true;
        Ok(())
    }
    pub fn missing(&self) -> impl Iterator<Item = usize> + '_ {
        self.verified
            .iter()
            .enumerate()
            .filter_map(|(i, ok)| (!*ok).then_some(i))
    }
    pub fn complete(&self) -> bool {
        self.verified.iter().all(|x| *x)
    }
}

pub fn reconstruct(
    manifest: &FileManifest,
    chunks: &[Chunk],
    output: impl AsRef<Path>,
) -> Result<(), FileError> {
    let mut ordered = chunks.to_vec();
    ordered.sort_by_key(|c| c.index);
    let mut out = File::create(output)?;
    for chunk in &ordered {
        verify_chunk(manifest, chunk)?;
        out.write_all(&chunk.data)?;
    }
    out.seek(SeekFrom::Start(0))?;
    if out.metadata()?.len() != manifest.total_size {
        return Err(FileError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "reconstructed size mismatch",
        )));
    }
    Ok(())
}

use std::io::Write;

pub fn hash_bytes(data: &[u8]) -> Hash {
    blake3::hash(data)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferState {
    pub manifest: FileManifest,
    pub verified_chunks: Vec<u32>,
    pub lost_chunks: Vec<u32>,
}

impl TransferState {
    pub fn new(manifest: FileManifest) -> Self {
        Self {
            manifest,
            verified_chunks: Vec::new(),
            lost_chunks: Vec::new(),
        }
    }
    pub fn mark_verified(&mut self, index: u32) {
        if !self.verified_chunks.contains(&index) {
            self.verified_chunks.push(index);
        }
    }
    pub fn mark_lost(&mut self, index: u32) {
        if !self.lost_chunks.contains(&index) {
            self.lost_chunks.push(index);
        }
    }
    /// Chunk indices this receiver still needs (the resume set).
    pub fn missing(&self) -> impl Iterator<Item = u32> + '_ {
        self.manifest
            .chunks
            .iter()
            .enumerate()
            .filter_map(|(i, _)| {
                let index = i as u32;
                if self.verified_chunks.contains(&index) {
                    None
                } else {
                    Some(index)
                }
            })
    }
    pub fn complete(&self) -> bool {
        self.verified_chunks.len() == self.manifest.chunks.len()
    }
}

pub fn safe_relative_path(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
) -> Result<PathBuf, FileError> {
    let root = root.as_ref().canonicalize()?;
    let relative = relative.as_ref();

    // Burrow paths are always relative to the share root. Reject absolute
    // paths and lexical `..` components before touching the filesystem.
    if relative.is_absolute() {
        return Err(FileError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "absolute path is not allowed",
        )));
    }
    for component in relative.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(FileError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path escapes share root",
            )));
        }
    }

    let candidate = root.join(relative);
    // `.` denotes the share root. Its parent is intentionally outside the
    // share, so checking candidate.parent() would incorrectly reject it.
    if candidate == root {
        return Ok(candidate);
    }

    // The requested path may be a file that already exists, or a directory
    // containing further components. Canonicalize the parent so symlinked
    // parents cannot escape the share root, while retaining the final path
    // component so callers can still use symlink_metadata safely.
    let parent = candidate
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?
        .canonicalize()?;
    if !parent.starts_with(&root) {
        return Err(FileError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path escapes share root",
        )));
    }
    Ok(candidate)
}

/// Full check of a received manifest before any chunks are accepted: the
/// signature must verify against the named signer and the chunk list must be
/// non-empty (an empty manifest can never be complete).
pub fn verify_manifest(manifest: &FileManifest) -> Result<(), FileError> {
    manifest.verify_signature()?;
    if manifest.chunks.is_empty() {
        return Err(FileError::InvalidIndex);
    }
    Ok(())
}

/// Stable identifier for a transfer: the hash of the manifest's unsigned bytes.
/// It is content-derived, so resending the same file yields the same id and a
/// receiver's persisted state can resume a dropped transfer directly.
pub fn manifest_id(manifest: &FileManifest) -> String {
    blake3::hash(&manifest.unsigned_bytes().expect("manifest serializes"))
        .to_hex()
        .to_string()
}

/// Manifest id for a transfer state (id of the embedded manifest).
pub fn manifest_id_from_state(state: &TransferState) -> String {
    manifest_id(&state.manifest)
}

fn transfers_dir(home: &Path) -> PathBuf {
    home.join("incoming")
}

/// What the receiver tells the sender after one chunk arrives.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveStatus {
    /// Chunk verified; `complete` is true only when every chunk now verifies.
    Verified { complete: bool },
    /// Chunk failed verification (or the manifest is missing); `index` should
    /// be re-requested/resent. This is the passive partial-loss surface.
    NeedsResend { index: u32, reason: String },
}

/// Record on disk that a receiver wants a `FilesFrame::Accept` to include this
/// set of indices from a resuming transfer.
pub fn write_received_manifest(
    home: &Path,
    id: &str,
    manifest: &FileManifest,
) -> Result<(), FileError> {
    let dir = transfers_dir(home).join(id);
    fs::create_dir_all(&dir)?;
    let bytes = postcard::to_allocvec(manifest).map_err(|e| FileError::Codec(e.to_string()))?;
    let tmp = dir.join("manifest.json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, dir.join("manifest.json"))?;
    Ok(())
}

fn load_received_manifest(home: &Path, id: &str) -> Result<FileManifest, FileError> {
    let path = transfers_dir(home).join(id).join("manifest.json");
    let bytes = fs::read(path)?;
    postcard::from_bytes(&bytes).map_err(|e| FileError::Codec(e.to_string()))
}

fn state_path(home: &Path, id: &str) -> PathBuf {
    transfers_dir(home).join(id).join("state.json")
}

pub fn save_transfer_state(home: &Path, id: &str, state: &TransferState) -> Result<(), FileError> {
    let dir = transfers_dir(home).join(id);
    fs::create_dir_all(&dir)?;
    let bytes = postcard::to_allocvec(state).map_err(|e| FileError::Codec(e.to_string()))?;
    let tmp = dir.join("state.json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, state_path(home, id))?;
    Ok(())
}

/// Receiver-side resumption state. Reads the persisted verified set for `id`;
/// if none exists, returns a fresh state derived from `manifest` so the first
/// exchange and a resumed exchange share one code path.
pub fn resume_for(
    home: &Path,
    id: &str,
    manifest: &FileManifest,
) -> Result<TransferState, FileError> {
    if let Ok(state) = load_transfer_state(home, id) {
        return Ok(state);
    }
    Ok(TransferState::new(manifest.clone()))
}

pub fn load_transfer_state(home: &Path, id: &str) -> Result<TransferState, FileError> {
    let path = state_path(home, id);
    let bytes = fs::read(path)?;
    postcard::from_bytes(&bytes).map_err(|e| FileError::Codec(e.to_string()))
}

/// One row of `neonet transfers`: manifest id, file name, verified chunk
/// count, total chunk count, and lost chunk count.
pub struct TransferSummary {
    pub id: String,
    pub name: String,
    pub verified: usize,
    pub total: usize,
    pub lost: usize,
}

/// Inbound transfers recorded on this device, ordered by manifest id.
pub fn list_transfers(home: &Path) -> Result<Vec<TransferSummary>, FileError> {
    let mut out = Vec::new();
    let dir = transfers_dir(home);
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if let Ok(state) = load_transfer_state(home, &id) {
            out.push(TransferSummary {
                id,
                name: state.manifest.name.clone(),
                verified: state.verified_chunks.len(),
                total: state.manifest.chunks.len(),
                lost: state.lost_chunks.len(),
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Verify one arriving chunk against the stored manifest, persist the verified
/// chunk data, advance the recorded verified set, and reconstruct the file the
/// moment the set completes.
pub fn receive_chunk(home: &Path, id: &str, chunk: &Chunk) -> Result<ReceiveStatus, FileError> {
    let manifest = load_received_manifest(home, id)?;
    verify_chunk(&manifest, chunk)?;

    // Persist the verified chunk data so a completed transfer can be
    // reconstructed without trusting the owner's records alone.
    let chunk_dir = transfers_dir(home).join(id).join("chunks");
    fs::create_dir_all(&chunk_dir)?;
    let tmp = chunk_dir.join(format!("{:08}.chunk.tmp", chunk.index));
    fs::write(&tmp, &chunk.data)?;
    fs::rename(tmp, chunk_dir.join(format!("{:08}.chunk", chunk.index)))?;

    let mut state = resume_for(home, id, &manifest)?;
    if state.verified_chunks.contains(&chunk.index) {
        return Ok(ReceiveStatus::Verified {
            complete: state.verified_chunks.len() == manifest.chunks.len(),
        });
    }
    state.verified_chunks.push(chunk.index);
    save_transfer_state(home, id, &state)?;

    let complete = state.verified_chunks.len() == manifest.chunks.len();
    if complete {
        let out_file = transfers_dir(home).join(id).join(&manifest.name);
        reconstruct_from_verified(&manifest, &state, &chunk_dir, &out_file)?;
    }
    Ok(ReceiveStatus::Verified { complete })
}

/// Assemble the final file from the verified chunk cache, re-verifying each
/// chunk against the manifest at read time rather than trusting recorded flags.
fn reconstruct_from_verified(
    manifest: &FileManifest,
    state: &TransferState,
    chunk_dir: &Path,
    output: &Path,
) -> Result<(), FileError> {
    let mut indices = state.verified_chunks.clone();
    indices.sort_unstable();
    let mut out = File::create(output)?;
    for index in indices {
        let bytes = fs::read(chunk_dir.join(format!("{index:08}.chunk")))?;
        let chunk = Chunk {
            index,
            hash: manifest.chunks[index as usize],
            data: bytes,
        };
        verify_chunk(manifest, &chunk)?;
        out.write_all(&chunk.data)?;
    }
    out.seek(SeekFrom::Start(0))?;
    if out.metadata()?.len() != manifest.total_size {
        return Err(FileError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "reconstructed size mismatch",
        )));
    }
    Ok(())
}

pub mod transfer;
