use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity directory error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid identity file: {0}")]
    InvalidFile(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PublicIdentity {
    pub public_key: [u8; 32],
}

impl PublicIdentity {
    pub fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| IdentityError::InvalidFile(e.to_string()))
    }

    pub fn fingerprint(&self) -> String {
        blake3::hash(&self.public_key).to_hex().to_string()
    }
}

pub struct Identity {
    signing_key: SigningKey,
    path: PathBuf,
}

impl Identity {
    pub fn load_or_generate(dir: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let path = dir.join("identity.key");

        if path.exists() {
            let bytes = fs::read(&path)?;
            if bytes.len() != 32 {
                return Err(IdentityError::InvalidFile(
                    "private key must contain exactly 32 bytes".into(),
                ));
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&bytes);
            Ok(Self {
                signing_key: SigningKey::from_bytes(&raw),
                path,
            })
        } else {
            let signing_key = SigningKey::generate(&mut OsRng);
            let tmp = path.with_extension("key.tmp");
            fs::write(&tmp, signing_key.to_bytes())?;
            fs::rename(&tmp, &path)?;
            Ok(Self { signing_key, path })
        }
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            public_key: self.signing_key.verifying_key().to_bytes(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_bytes()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_once_and_reloads_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first = Identity::load_or_generate(dir.path()).unwrap();
        let fp = first.public().fingerprint();
        let second = Identity::load_or_generate(dir.path()).unwrap();
        assert_eq!(fp, second.public().fingerprint());
    }
}
