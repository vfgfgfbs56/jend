use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{ManifestId, ModelChunk, ModelManifest, ModelStoreError, Result};

/// Incremental verifier so a 128 MiB chunk never needs to be copied into a
/// second in-memory buffer just for integrity checking.
pub struct ChunkVerifier {
    expected_len: u32,
    expected_hash: [u8; 32],
    received: u64,
    hasher: Sha256,
}

impl ChunkVerifier {
    pub fn new(chunk: &ModelChunk) -> Self {
        Self {
            expected_len: chunk.plaintext_len,
            expected_hash: chunk.sha256,
            received: 0,
            hasher: Sha256::new(),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.received = self
            .received
            .checked_add(bytes.len() as u64)
            .ok_or(ModelStoreError::Overflow)?;
        if self.received > self.expected_len as u64 {
            return Err(ModelStoreError::ChunkLengthMismatch);
        }
        self.hasher.update(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        if self.received != self.expected_len as u64 {
            return Err(ModelStoreError::ChunkLengthMismatch);
        }
        let digest: [u8; 32] = self.hasher.finalize().into();
        if digest != self.expected_hash {
            return Err(ModelStoreError::ChunkDigestMismatch);
        }
        Ok(())
    }
}


/// Final integrity check over the exact assembled model bytes. Chunk hashes make
/// resume/local corruption detection cheap; this second digest prevents a buggy
/// assembler from silently producing the wrong concatenation/order.
pub struct WholeModelVerifier {
    expected_len: u64,
    expected_hash: [u8; 32],
    received: u64,
    hasher: Sha256,
}

impl WholeModelVerifier {
    pub fn new(manifest: &ModelManifest) -> Self {
        Self {
            expected_len: manifest.total_plaintext_len,
            expected_hash: manifest.whole_model_sha256,
            received: 0,
            hasher: Sha256::new(),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.received = self.received.checked_add(bytes.len() as u64).ok_or(ModelStoreError::Overflow)?;
        if self.received > self.expected_len {
            return Err(ModelStoreError::ChunkLengthMismatch);
        }
        self.hasher.update(bytes);
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        if self.received != self.expected_len {
            return Err(ModelStoreError::ChunkLengthMismatch);
        }
        let digest: [u8; 32] = self.hasher.finalize().into();
        if digest != self.expected_hash {
            return Err(ModelStoreError::ChunkDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadState {
    pub manifest_id: ManifestId,
    completed: BTreeSet<u32>,
}

impl DownloadState {
    pub fn new(manifest: &ModelManifest) -> Result<Self> {
        Ok(Self {
            manifest_id: manifest.manifest_id()?,
            completed: BTreeSet::new(),
        })
    }

    pub fn mark_complete(&mut self, manifest: &ModelManifest, chunk_index: u32) -> Result<()> {
        self.ensure_manifest(manifest)?;
        manifest.chunk(chunk_index)?;
        self.completed.insert(chunk_index);
        Ok(())
    }

    pub fn is_complete(&self, manifest: &ModelManifest) -> Result<bool> {
        self.ensure_manifest(manifest)?;
        Ok(self.completed.len() == manifest.chunks.len())
    }

    pub fn missing_chunks(&self, manifest: &ModelManifest) -> Result<Vec<u32>> {
        self.ensure_manifest(manifest)?;
        Ok(manifest
            .chunks
            .iter()
            .filter_map(|chunk| (!self.completed.contains(&chunk.index)).then_some(chunk.index))
            .collect())
    }

    fn ensure_manifest(&self, manifest: &ModelManifest) -> Result<()> {
        if self.manifest_id != manifest.manifest_id()? {
            return Err(ModelStoreError::DownloadStateMismatch);
        }
        Ok(())
    }
}
