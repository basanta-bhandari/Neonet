use crate::identity::PublicIdentity;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fs, net::SocketAddr, path::Path};
use thiserror::Error;

mod hex_key {
    use super::*;

    pub fn serialize<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        let decoded = hex::decode(s).map_err(serde::de::Error::custom)?;
        let key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 hex characters (32 bytes)"))?;
        Ok(key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapEntry {
    pub address: SocketAddr,
    #[serde(with = "hex_key")]
    pub pinned_public_key: [u8; 32],
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("bootstrap I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bootstrap format error: {0}")]
    Format(#[from] serde_json::Error),
    #[error("bootstrap public key is not a valid 32-byte hex string")]
    InvalidKey,
}

impl BootstrapEntry {
    pub fn trusts(&self, identity: &PublicIdentity) -> bool {
        self.pinned_public_key == identity.public_key
    }
}

pub fn load(path: impl AsRef<Path>) -> Result<Vec<BootstrapEntry>, BootstrapError> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save(path: impl AsRef<Path>, entries: &[BootstrapEntry]) -> Result<(), BootstrapError> {
    let bytes = serde_json::to_vec_pretty(entries)?;
    fs::write(path, bytes)?;
    Ok(())
}
