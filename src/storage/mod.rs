//! Client-side encrypted storage. Each plaintext chunk is encrypted before it
//! leaves the client. Core storage sees only opaque encrypted blobs.

use crate::files::{Chunk, FileManifest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, io, path::Path};

pub type StorageKey = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedChunk {
    pub index: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardPlacement {
    pub chunk_index: u32,
    pub cores: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageManifest {
    pub file: FileManifest,
    pub encrypted_chunks: Vec<EncryptedChunk>,
    pub placements: Vec<ShardPlacement>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("crypto failure")]
    Crypto,
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("codec: {0}")]
    Codec(String),
}

pub fn generate_key() -> StorageKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt_chunk(key: &StorageKey, chunk: &Chunk) -> Result<EncryptedChunk, StorageError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StorageError::Crypto)?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = chunk.index.to_le_bytes();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &chunk.data,
                aad: &aad,
            },
        )
        .map_err(|_| StorageError::Crypto)?;
    Ok(EncryptedChunk {
        index: chunk.index,
        nonce,
        ciphertext,
    })
}

pub fn decrypt_chunk(key: &StorageKey, chunk: &EncryptedChunk) -> Result<Chunk, StorageError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StorageError::Crypto)?;
    let aad = chunk.index.to_le_bytes();
    let data = cipher
        .decrypt(
            XNonce::from_slice(&chunk.nonce),
            chacha20poly1305::aead::Payload {
                msg: &chunk.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| StorageError::Crypto)?;
    let hash = *blake3::hash(&data).as_bytes();
    Ok(Chunk {
        index: chunk.index,
        hash,
        data,
    })
}

/// Simple content-addressed core-side blob store. It intentionally cannot
/// decrypt anything: callers only provide opaque encrypted chunks.
#[derive(Debug)]
pub struct CoreBlobStore {
    root: std::path::PathBuf,
}
impl CoreBlobStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }
    pub fn put(&self, blob: &EncryptedChunk) -> Result<String, StorageError> {
        let id = blake3::hash(&blob.ciphertext).to_hex().to_string();
        fs::write(
            self.root.join(&id),
            postcard::to_allocvec(blob).map_err(|e| StorageError::Codec(e.to_string()))?,
        )?;
        Ok(id)
    }
    pub fn get(&self, id: &str) -> Result<EncryptedChunk, StorageError> {
        let bytes = fs::read(self.root.join(id))?;
        postcard::from_bytes(&bytes).map_err(|e| StorageError::Codec(e.to_string()))
    }
}

#[derive(Debug, Default)]
pub struct ReplicaMap {
    placements: HashMap<u32, Vec<String>>,
}
impl ReplicaMap {
    pub fn place(&mut self, index: u32, cores: Vec<String>) {
        self.placements.insert(index, cores);
    }
    pub fn cores(&self, index: u32) -> &[String] {
        self.placements
            .get(&index)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// Client-only key file. It is deliberately never part of a transfer or
/// bootstrap record. Production deployments should additionally protect this
/// file with the host OS credential store; this reference implementation keeps
/// that boundary explicit rather than pretending a portable Rust file is a
/// hardware-backed secret store.
pub struct LocalKeyStore {
    path: std::path::PathBuf,
}
impl LocalKeyStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
    pub fn load_or_generate(&self) -> Result<StorageKey, StorageError> {
        if self.path.exists() {
            let bytes = fs::read(&self.path)?;
            if bytes.len() != 32 {
                return Err(StorageError::Codec("storage key must be 32 bytes".into()));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return Ok(k);
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let key = generate_key();
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, key)?;
        fs::rename(tmp, &self.path)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::Chunk;
    #[test]
    fn encrypt_round_trip() {
        let key = generate_key();
        let c = Chunk {
            index: 2,
            hash: *blake3::hash(b"secret").as_bytes(),
            data: b"secret".to_vec(),
        };
        let e = encrypt_chunk(&key, &c).unwrap();
        let d = decrypt_chunk(&key, &e).unwrap();
        assert_eq!(d.data, c.data);
        assert_ne!(e.ciphertext, c.data);
    }
}
