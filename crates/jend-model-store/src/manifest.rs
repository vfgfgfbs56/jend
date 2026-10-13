use sha2::{Digest, Sha256};

use crate::{ManifestId, ModelId, ModelObjectId, ModelStoreError, ReleaseKeyId, Result};

const MANIFEST_MAGIC: &[u8; 4] = b"JMDL";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_DOMAIN: &[u8] = b"JEND/MODEL/MANIFEST/V1";
const MAX_STRING: usize = 96;
const MAX_CHUNKS: usize = 131_072;
const MAX_MODEL_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024; // 64 TiB logical ceiling
const MAX_CHUNK_BYTES: u32 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelChunk {
    pub index: u32,
    /// Opaque object-store key. It is intentionally not a URL and does not
    /// encode the model name/version.
    pub object_id: ModelObjectId,
    pub offset: u64,
    pub plaintext_len: u32,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelManifest {
    pub model_id: ModelId,
    pub release_sequence: u64,
    pub minimum_runtime: u32,
    pub format: String,
    pub architecture: String,
    pub quantization: String,
    pub total_plaintext_len: u64,
    pub whole_model_sha256: [u8; 32],
    pub chunks: Vec<ModelChunk>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedModelManifest {
    pub manifest: ModelManifest,
    pub manifest_id: ManifestId,
    pub release_key_id: ReleaseKeyId,
    pub signature: [u8; 64],
}

impl ModelManifest {
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.format)?;
        validate_text(&self.architecture)?;
        validate_text(&self.quantization)?;
        if self.chunks.is_empty()
            || self.chunks.len() > MAX_CHUNKS
            || self.total_plaintext_len == 0
            || self.total_plaintext_len > MAX_MODEL_BYTES
        {
            return Err(ModelStoreError::InvalidManifest);
        }

        let mut expected_offset = 0u64;
        for (expected_index, chunk) in self.chunks.iter().enumerate() {
            if chunk.index != expected_index as u32
                || chunk.offset != expected_offset
                || chunk.plaintext_len == 0
                || chunk.plaintext_len > MAX_CHUNK_BYTES
            {
                return Err(ModelStoreError::InvalidManifest);
            }
            expected_offset = expected_offset
                .checked_add(chunk.plaintext_len as u64)
                .ok_or(ModelStoreError::Overflow)?;
        }
        if expected_offset != self.total_plaintext_len {
            return Err(ModelStoreError::InvalidManifest);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(256 + self.chunks.len() * 80);
        out.extend_from_slice(MANIFEST_MAGIC);
        out.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
        out.extend_from_slice(&self.model_id.0);
        out.extend_from_slice(&self.release_sequence.to_be_bytes());
        out.extend_from_slice(&self.minimum_runtime.to_be_bytes());
        put_text(&mut out, &self.format)?;
        put_text(&mut out, &self.architecture)?;
        put_text(&mut out, &self.quantization)?;
        out.extend_from_slice(&self.total_plaintext_len.to_be_bytes());
        out.extend_from_slice(&self.whole_model_sha256);
        out.extend_from_slice(&(self.chunks.len() as u32).to_be_bytes());
        for chunk in &self.chunks {
            out.extend_from_slice(&chunk.index.to_be_bytes());
            out.extend_from_slice(&chunk.object_id.0);
            out.extend_from_slice(&chunk.offset.to_be_bytes());
            out.extend_from_slice(&chunk.plaintext_len.to_be_bytes());
            out.extend_from_slice(&chunk.sha256);
        }
        Ok(out)
    }

    pub fn manifest_id(&self) -> Result<ManifestId> {
        let bytes = self.canonical_bytes()?;
        let mut h = Sha256::new();
        h.update(MANIFEST_DOMAIN);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(&bytes);
        Ok(ManifestId(h.finalize().into()))
    }



    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != MANIFEST_MAGIC {
            return Err(ModelStoreError::InvalidManifest);
        }
        if r.u16()? != MANIFEST_VERSION {
            return Err(ModelStoreError::InvalidManifest);
        }
        let model_id = ModelId(r.array()?);
        let release_sequence = r.u64()?;
        let minimum_runtime = r.u32()?;
        let format = r.text()?;
        let architecture = r.text()?;
        let quantization = r.text()?;
        let total_plaintext_len = r.u64()?;
        let whole_model_sha256 = r.array()?;
        let chunk_count = r.u32()? as usize;
        if chunk_count == 0 || chunk_count > MAX_CHUNKS {
            return Err(ModelStoreError::InvalidManifest);
        }
        let mut chunks = Vec::with_capacity(chunk_count);
        for _ in 0..chunk_count {
            chunks.push(ModelChunk {
                index: r.u32()?,
                object_id: ModelObjectId(r.array()?),
                offset: r.u64()?,
                plaintext_len: r.u32()?,
                sha256: r.array()?,
            });
        }
        r.finish()?;
        let manifest = Self {
            model_id,
            release_sequence,
            minimum_runtime,
            format,
            architecture,
            quantization,
            total_plaintext_len,
            whole_model_sha256,
            chunks,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn chunk(&self, index: u32) -> Result<&ModelChunk> {
        self.chunks
            .get(index as usize)
            .filter(|chunk| chunk.index == index)
            .ok_or(ModelStoreError::InvalidChunk)
    }

    pub fn chunk_by_object_id(&self, object_id: ModelObjectId) -> Result<&ModelChunk> {
        self.chunks
            .iter()
            .find(|chunk| chunk.object_id == object_id)
            .ok_or(ModelStoreError::InvalidChunk)
    }
}


impl SignedModelManifest {
    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        let manifest = self.manifest.canonical_bytes()?;
        let manifest_len = u32::try_from(manifest.len()).map_err(|_| ModelStoreError::ManifestTooLarge)?;
        let mut out = Vec::with_capacity(4 + manifest.len() + 32 + 16 + 64);
        out.extend_from_slice(&manifest_len.to_be_bytes());
        out.extend_from_slice(&manifest);
        out.extend_from_slice(&self.manifest_id.0);
        out.extend_from_slice(&self.release_key_id.0);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let manifest_len = r.u32()? as usize;
        if manifest_len == 0 || manifest_len > 32 * 1024 * 1024 {
            return Err(ModelStoreError::ManifestTooLarge);
        }
        let manifest = ModelManifest::from_canonical_bytes(r.take(manifest_len)?)?;
        let manifest_id = ManifestId(r.array()?);
        let release_key_id = ReleaseKeyId(r.array()?);
        let signature = r.array()?;
        r.finish()?;
        let signed = Self { manifest, manifest_id, release_key_id, signature };
        if signed.manifest.manifest_id()? != signed.manifest_id {
            return Err(ModelStoreError::InvalidManifest);
        }
        Ok(signed)
    }
}

fn validate_text(text: &str) -> Result<()> {
    if text.is_empty()
        || text.len() > MAX_STRING
        || !text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'+'))
    {
        return Err(ModelStoreError::InvalidManifest);
    }
    Ok(())
}

fn put_text(out: &mut Vec<u8>, text: &str) -> Result<()> {
    validate_text(text)?;
    let len = u16::try_from(text.len()).map_err(|_| ModelStoreError::ManifestTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}


struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(ModelStoreError::Overflow)?;
        if end > self.bytes.len() { return Err(ModelStoreError::InvalidManifest); }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| ModelStoreError::InvalidManifest)?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| ModelStoreError::InvalidManifest)?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| ModelStoreError::InvalidManifest)?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| ModelStoreError::InvalidManifest)
    }

    fn text(&mut self) -> Result<String> {
        let len = self.u16()? as usize;
        if len == 0 || len > MAX_STRING { return Err(ModelStoreError::InvalidManifest); }
        let text = core::str::from_utf8(self.take(len)?).map_err(|_| ModelStoreError::InvalidManifest)?;
        validate_text(text)?;
        Ok(text.to_owned())
    }

    fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() { Ok(()) } else { Err(ModelStoreError::InvalidManifest) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ModelManifest {
        ModelManifest {
            model_id: ModelId([1u8; 16]),
            release_sequence: 7,
            minimum_runtime: 1,
            format: "gguf".into(),
            architecture: "llama".into(),
            quantization: "Q4_K_M".into(),
            total_plaintext_len: 6,
            whole_model_sha256: [9u8; 32],
            chunks: vec![
                ModelChunk { index: 0, object_id: ModelObjectId([2u8; 32]), offset: 0, plaintext_len: 3, sha256: [3u8; 32] },
                ModelChunk { index: 1, object_id: ModelObjectId([4u8; 32]), offset: 3, plaintext_len: 3, sha256: [5u8; 32] },
            ],
        }
    }

    #[test]
    fn manifest_digest_is_stable() {
        let a = sample().manifest_id().unwrap();
        let b = sample().manifest_id().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_wire_roundtrip() {
        let manifest = sample();
        let bytes = manifest.canonical_bytes().unwrap();
        assert_eq!(ModelManifest::from_canonical_bytes(&bytes).unwrap(), manifest);
    }

    #[test]
    fn gaps_in_chunk_offsets_are_rejected() {
        let mut manifest = sample();
        manifest.chunks[1].offset = 4;
        assert!(manifest.validate().is_err());
    }
}
