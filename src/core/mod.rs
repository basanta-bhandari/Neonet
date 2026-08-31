//! Core-node primitives: content-addressed immutable chunks, ACL checks, and
//! a small replica directory. Mutable metadata is intentionally modeled as
//! eventually consistent; revocation is exposed as a separate strong-state API.

use crate::identity::PublicIdentity;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Acl {
    pub readers: HashSet<PublicIdentity>,
}
impl Acl {
    pub fn allows(&self, identity: &PublicIdentity) -> bool {
        self.readers.contains(identity)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ChunkIndex {
    chunks: HashMap<[u8; 32], Vec<u8>>,
}
impl ChunkIndex {
    pub fn insert(&mut self, hash: [u8; 32], data: Vec<u8>) -> bool {
        if blake3::hash(&data).as_bytes() != &hash {
            return false;
        }
        self.chunks.entry(hash).or_insert(data);
        true
    }
    pub fn get(&self, hash: &[u8; 32]) -> Option<&[u8]> {
        self.chunks.get(hash).map(Vec::as_slice)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RevocationState {
    revoked: HashSet<PublicIdentity>,
    epoch: u64,
}
impl RevocationState {
    pub fn revoke(&mut self, id: PublicIdentity) {
        self.revoked.insert(id);
        self.epoch += 1;
    }
    pub fn is_revoked(&self, id: &PublicIdentity) -> bool {
        self.revoked.contains(id)
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Clone, Debug)]
pub struct CoreNode {
    pub identity: PublicIdentity,
    pub chunks: ChunkIndex,
    pub revocations: RevocationState,
}
impl CoreNode {
    pub fn new(identity: PublicIdentity) -> Self {
        Self {
            identity,
            chunks: ChunkIndex::default(),
            revocations: RevocationState::default(),
        }
    }
    pub fn read_chunk(
        &self,
        requester: &PublicIdentity,
        acl: &Acl,
        hash: &[u8; 32],
    ) -> io::Result<Vec<u8>> {
        if self.revocations.is_revoked(requester) || !acl.allows(requester) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "access denied",
            ));
        }
        self.chunks
            .get(hash)
            .map(ToOwned::to_owned)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "chunk not found"))
    }
}

pub mod replication;
