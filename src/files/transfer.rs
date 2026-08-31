//! Resumable chunk transfer coordinator. A failed chunk is retried against
//! alternate sources up to the configured budget before being marked lost.

use super::{Chunk, FileError, FileManifest, TransferState};

pub const DEFAULT_RETRY_BUDGET: usize = 3;

pub trait ChunkSource {
    fn fetch(&self, index: u32) -> Result<Chunk, FileError>;
}

pub fn transfer_manifest<S: ChunkSource>(
    manifest: &FileManifest,
    sources: &[S],
    retry_budget: usize,
) -> TransferState {
    let mut state = TransferState::new(manifest.clone());
    let budget = retry_budget.max(1);
    for index in 0..manifest.chunks.len() as u32 {
        let mut success = false;
        let mut attempts = 0;
        for source in sources.iter().cycle().take(sources.len().min(budget)) {
            attempts += 1;
            match source.fetch(index) {
                Ok(chunk) if super::verify_chunk(manifest, &chunk).is_ok() => {
                    state.mark_verified(index);
                    success = true;
                    break;
                }
                _ => {}
            }
        }
        if !success || attempts == 0 {
            state.mark_lost(index);
        }
    }
    state
}
