//! Flash pairing: a single-use token that turns a fresh connection into a
//! durable pairing, recorded in the acceptor's pairing ledger.
//!
//! Modeled on the physical `flash` design: the token is the "flashed drive",
//! reduced to its security essence:
//! - The acceptor runs `neonet pair` and **actively** publishes a token (the
//!   drive) that only exists for a short window (the plugged-in moment).
//! - The requester presents it exactly once (`neonet flash <acceptor> <token>`,
//!   the "insertion"). After one redemption the token is dead: a lost/stolen
//!   token afterwards is just a dead file, never a standing key.
//! - Redemption adds the presenter's public key to the acceptor's pairing
//!   ledger (`paired.json`). It does not by itself open the transport gate —
//!   the ledger feeds `neonet pairs --as-allow` so the operator composes the
//!   core's `--allow-file` from established pairings. (The transport gate is
//!   deliberately not auto-opened: a silently-trusted-first-hookup is the
//!   autorun-malware pattern this mechanism exists to avoid.)

use crate::identity::PublicIdentity;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_TTL_SECS: u64 = 120;
const MAX_TTL_SECS: u64 = 600;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairedDevice {
    pub fingerprint: String,
    #[serde(with = "serde_big_array::BigArray")]
    pub public_key: [u8; 32],
    pub paired_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PairLedger {
    paired: Vec<PairedDevice>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingToken {
    token: String,
    expires_at: u64,
    used: bool,
}

pub fn is_paired(root: &Path, identity: &PublicIdentity) -> bool {
    load(root)
        .paired
        .iter()
        .any(|record| record.fingerprint == identity.fingerprint())
}

pub fn paired_devices(root: &Path) -> Vec<PairedDevice> {
    let mut records = load(root).paired;
    records.sort_by_key(|record| record.paired_at);
    records
}

/// Issue a fresh single-use pairing token. Replaces any previous pending token
/// (only one "drive" is ever plugged in at a time). Returns the token string
/// the operator reads over the shoulder / writes down.
pub fn issue_token(root: &Path, ttl_secs: Option<u64>) -> io::Result<String> {
    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS).clamp(1, MAX_TTL_SECS);
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let token = hex::encode(raw);
    let now = unix_now();
    let pending = PendingToken {
        token: token.clone(),
        expires_at: now + ttl,
        used: false,
    };
    write_pending(root, &pending)?;
    Ok(token)
}

/// Try to present `token` exactly once. Returns `Ok(true)` if it was valid and
/// has now been consumed; the caller records the pairing. Any failure is
/// `Ok(false)`, never a partial state.
pub fn consume_token(root: &Path, token: &str) -> io::Result<bool> {
    let path = pending_path(root);
    let Ok(bytes) = fs::read(&path) else {
        return Ok(false);
    };
    let mut pending: PendingToken = match serde_json::from_slice(&bytes) {
        Ok(pending) => pending,
        Err(_) => return Ok(false),
    };
    if pending.used || pending.expires_at <= unix_now() || pending.token != token {
        return Ok(false);
    }
    pending.used = true;
    write_pending(root, &pending)?;
    Ok(true)
}

/// Record `identity` as durably paired (idempotent).
pub fn record_pairing(root: &Path, identity: &PublicIdentity) -> io::Result<()> {
    let mut ledger = load(root);
    if ledger
        .paired
        .iter()
        .any(|record| record.fingerprint == identity.fingerprint())
    {
        return Ok(());
    }
    ledger.paired.push(PairedDevice {
        fingerprint: identity.fingerprint(),
        public_key: identity.public_key,
        paired_at: unix_now(),
    });
    save(root, &ledger)
}

fn load(root: &Path) -> PairLedger {
    match fs::read(root.join("paired.json")) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => PairLedger::default(),
    }
}

fn save(root: &Path, ledger: &PairLedger) -> io::Result<()> {
    let bytes = serde_json::to_vec(ledger)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let path = root.join("paired.json");
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

fn pending_path(root: &Path) -> std::path::PathBuf {
    root.join("pair.json")
}

fn write_pending(root: &Path, pending: &PendingToken) -> io::Result<()> {
    let bytes = serde_json::to_vec(pending)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let path = pending_path(root);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
