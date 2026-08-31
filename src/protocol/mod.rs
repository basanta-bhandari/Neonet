use crate::identity::{Identity, PublicIdentity};
use ed25519_dalek::{Signature, Verifier};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub version: ProtocolVersion,
    pub features: Vec<String>,
    pub identity: PublicIdentity,
    pub session_id: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; 32],
}

// [u8; 64] (an Ed25519 signature) is larger than serde's derive macro
// natively supports on every toolchain we need to build against; BigArray
// gives an explicit, version-independent Serialize/Deserialize impl instead
// of relying on const-generic array support that varies by serde/rustc
// version.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureMessage {
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedProtocol {
    pub version: ProtocolVersion,
    pub features: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("incompatible protocol major version: local={local}, remote={remote}")]
    MajorMismatch { local: u16, remote: u16 },
    #[error("invalid signature")]
    InvalidSignature,
}

pub fn new_hello(identity: &Identity, features: Vec<String>) -> Hello {
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);
    Hello {
        version: ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        },
        features,
        identity: identity.public(),
        session_id,
    }
}

pub fn negotiate(
    local: &ProtocolVersion,
    local_features: &[String],
    remote: &ProtocolVersion,
    remote_features: &[String],
) -> Result<NegotiatedProtocol, ProtocolError> {
    if local.major != remote.major {
        return Err(ProtocolError::MajorMismatch {
            local: local.major,
            remote: remote.major,
        });
    }
    let minor = local.minor.min(remote.minor);
    let mut features = local_features
        .iter()
        .filter(|f| remote_features.iter().any(|r| r == *f))
        .cloned()
        .collect::<Vec<_>>();
    features.sort();
    Ok(NegotiatedProtocol {
        version: ProtocolVersion {
            major: local.major,
            minor,
        },
        features,
    })
}

pub fn challenge() -> Challenge {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    Challenge { nonce }
}

pub fn sign_challenge(
    identity: &Identity,
    hello: &Hello,
    challenge: &Challenge,
) -> SignatureMessage {
    let payload = challenge_payload(hello, challenge);
    SignatureMessage {
        signature: identity.sign(&payload),
    }
}

/// Verifies that `message` is `signer`'s signature over the payload built
/// from `payload_hello`/`payload_challenge`.
///
/// These are deliberately two separate identities in a real two-party
/// handshake: the payload is built from *your own* Hello/Challenge (because
/// that's what the remote peer received and signed), while the verifying
/// key must come from the *remote peer's* Hello (because they, not you,
/// produced the signature). Collapsing these into a single `hello`
/// parameter — using its identity as both the payload source and the
/// verifying key — silently verifies a peer's signature against their own
/// public key instead of the peer that actually produced it, which passes
/// only when a single identity signs and verifies its own data and fails
/// every real two-party exchange.
pub fn verify_challenge(
    payload_hello: &Hello,
    payload_challenge: &Challenge,
    signer: &crate::identity::PublicIdentity,
    message: &SignatureMessage,
) -> Result<(), ProtocolError> {
    let key = signer
        .verifying_key()
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let signature = Signature::from_bytes(&message.signature);
    key.verify(
        &challenge_payload(payload_hello, payload_challenge),
        &signature,
    )
    .map_err(|_| ProtocolError::InvalidSignature)
}

fn challenge_payload(hello: &Hello, challenge: &Challenge) -> Vec<u8> {
    let hello_bytes = postcard::to_allocvec(hello).expect("protocol types are serializable");
    let mut payload = Vec::with_capacity(hello_bytes.len() + challenge.nonce.len());
    payload.extend_from_slice(&hello_bytes);
    payload.extend_from_slice(&challenge.nonce);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use tempfile::tempdir;

    #[test]
    fn hello_challenge_signature_round_trip() {
        let dir = tempdir().unwrap();
        let identity = Identity::load_or_generate(dir.path()).unwrap();
        let hello = new_hello(&identity, vec!["foundation".into(), "relay".into()]);
        let challenge = challenge();
        let signed = sign_challenge(&identity, &hello, &challenge);
        verify_challenge(&hello, &challenge, &identity.public(), &signed).unwrap();
    }

    #[test]
    fn two_party_challenge_uses_signers_key_not_verifiers_own() {
        // Regression test for a real bug: verifying with the wrong party's
        // key silently passes in a single-actor test (signer == verifier)
        // but must fail whenever two distinct identities are involved.
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let identity_a = Identity::load_or_generate(dir_a.path()).unwrap();
        let identity_b = Identity::load_or_generate(dir_b.path()).unwrap();

        let hello_a = new_hello(&identity_a, vec![]);
        let challenge_a = challenge();
        // B signs a payload built from A's hello/challenge, as it would
        // after receiving them over the wire.
        let signed_by_b = sign_challenge(&identity_b, &hello_a, &challenge_a);

        // Verifying with B's key (the actual signer) must succeed.
        verify_challenge(&hello_a, &challenge_a, &identity_b.public(), &signed_by_b).unwrap();
        // Verifying with A's key (the payload owner, not the signer) must fail.
        assert!(
            verify_challenge(&hello_a, &challenge_a, &identity_a.public(), &signed_by_b).is_err()
        );
    }

    #[test]
    fn feature_negotiation_intersects() {
        let a = vec!["a".into(), "b".into()];
        let b = vec!["b".into(), "c".into()];
        let n = negotiate(
            &ProtocolVersion { major: 1, minor: 2 },
            &a,
            &ProtocolVersion { major: 1, minor: 1 },
            &b,
        )
        .unwrap();
        assert_eq!(n.version.minor, 1);
        assert_eq!(n.features, vec!["b"]);
    }
}
