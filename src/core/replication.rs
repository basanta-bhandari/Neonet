//! Core-to-core immutable-chunk reconciliation. No consensus protocol is
//! required for immutable content: missing chunks are copied from any replica.

use super::ChunkIndex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub missing: Vec<[u8; 32]>,
}

pub fn plan(
    local: &ChunkIndex,
    remote_hashes: impl IntoIterator<Item = [u8; 32]>,
) -> ReconcilePlan {
    let missing = remote_hashes
        .into_iter()
        .filter(|h| local.get(h).is_none())
        .collect();
    ReconcilePlan { missing }
}
