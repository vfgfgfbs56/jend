//! Jend Source Descriptor Protocol (JSDP) v1.
//!
//! The Store and WeightVM trust content identities, not origin URLs. A source
//! descriptor says where immutable bytes may be obtained; a page binding says
//! which byte range is expected to reconstruct a particular `WeightPageId`.
//! Adapters (HF/Xet, publisher HTTPS, mirrors, peers) live outside WeightVM.
//!
//! Security invariants:
//! - no arbitrary URL string is part of the protocol;
//! - HF sources are pinned to a full immutable commit;
//! - publisher HTTPS is host/path structured and immutable-path validated;
//! - every page binding carries the expected `WeightPageDescriptor`;
//! - source maps are canonical and release-signed;
//! - remote bytes still require WeightVM SHA-256 verification before residency.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::{
    ModelId, ModelObjectId, ModelStoreError, ReleaseKeyId, Result, VirtualModelMap,
    VirtualMapId, WeightPageDescriptor, WeightPageId,
};

const SOURCE_DESCRIPTOR_DOMAIN: &[u8] = b"JEND/SOURCE-DESCRIPTOR/V1";
const SOURCE_MAP_DOMAIN: &[u8] = b"JEND/SOURCE-MAP/V1";
const SOURCE_MAP_MAGIC: &[u8; 4] = b"JSMP";
const SOURCE_MAP_VERSION: u16 = 1;
const MAX_SOURCES: usize = 65_536;
const MAX_BINDINGS: usize = 1_048_576;
const MAX_REPO_ID: usize = 128;
const MAX_HOST: usize = 253;
const MAX_PATH: usize = 2048;
const MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024; // 64 TiB
const MAX_RANGE_BYTES: u64 = 512 * 1024 * 1024; // WeightVM page ceiling

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SourceId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SourceMapId(pub [u8; 32]);

/// Transport-specific immutable locator. This type is interpreted by a source
/// adapter, never by WeightVM itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceOrigin {
    HuggingFaceXet {
        repo_id: String,
        commit_sha: String,
        file_path: String,
    },
    PublisherHttps {
        host: String,
        immutable_path: String,
    },
    JendObject {
        object_id: ModelObjectId,
    },
}

/// One immutable remote/local object from which byte ranges may be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceDescriptor {
    pub origin: SourceOrigin,
    pub object_len: u64,
    /// Optional whole-object SHA-256. A range binding is still verified by the
    /// page digest, so this may be absent when an upstream CAS has its own
    /// immutable object identity but no convenient whole-file SHA-256.
    pub whole_object_sha256: Option<[u8; 32]>,
}

/// Bind one trusted Jend page identity to a byte range of a source object.
/// Multiple bindings for the same page are allowed so later resolver versions
/// can choose among HF, publisher mirrors, Jend mirrors, or peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageSourceBinding {
    pub page: WeightPageDescriptor,
    pub source_id: SourceId,
    pub source_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelSourceMap {
    pub model_id: ModelId,
    pub release_sequence: u64,
    pub sources: Vec<SourceDescriptor>,
    pub bindings: Vec<PageSourceBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedModelSourceMap {
    pub map: ModelSourceMap,
    pub map_id: SourceMapId,
    pub release_key_id: ReleaseKeyId,
    pub signature: [u8; 64],
}

/// Network-agnostic read request produced after resolving a binding. It contains
/// no URL and no credential. A source adapter receives this plus the descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceReadRequest {
    pub source_id: SourceId,
    pub source_offset: u64,
    pub len: u64,
    pub expected_page: WeightPageDescriptor,
}

/// Opaque proof that a source read request came from both a release-signed
/// source map and the matching release-signed virtual model map. Callers
/// cannot construct or alter this token outside `jend-model-store`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSourceReadRequest {
    request: SourceReadRequest,
    source_map_id: SourceMapId,
    virtual_map_id: VirtualMapId,
    release_key_id: ReleaseKeyId,
}

impl VerifiedSourceReadRequest {
    pub fn request(self) -> SourceReadRequest {
        self.request
    }

    pub fn expected_page(self) -> WeightPageDescriptor {
        self.request.expected_page
    }

    pub fn source_map_id(self) -> SourceMapId {
        self.source_map_id
    }

    pub fn virtual_map_id(self) -> VirtualMapId {
        self.virtual_map_id
    }

    pub fn release_key_id(self) -> ReleaseKeyId {
        self.release_key_id
    }

    pub(crate) fn from_verified_maps(
        request: SourceReadRequest,
        source_map_id: SourceMapId,
        virtual_map_id: VirtualMapId,
        release_key_id: ReleaseKeyId,
    ) -> Self {
        Self {
            request,
            source_map_id,
            virtual_map_id,
            release_key_id,
        }
    }
}

impl SourceOrigin {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::HuggingFaceXet {
                repo_id,
                commit_sha,
                file_path,
            } => {
                validate_repo_id(repo_id)?;
                validate_commit_sha(commit_sha)?;
                validate_repo_file_path(file_path)?;
            }
            Self::PublisherHttps {
                host,
                immutable_path,
            } => {
                validate_host(host)?;
                validate_immutable_path(immutable_path)?;
            }
            Self::JendObject { object_id } => {
                if object_id.0.iter().all(|b| *b == 0) {
                    return Err(ModelStoreError::InvalidSourceDescriptor);
                }
            }
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        match self {
            Self::HuggingFaceXet {
                repo_id,
                commit_sha,
                file_path,
            } => {
                out.push(1);
                put_text(out, repo_id)?;
                put_text(out, commit_sha)?;
                put_text(out, file_path)?;
            }
            Self::PublisherHttps {
                host,
                immutable_path,
            } => {
                out.push(2);
                put_text(out, host)?;
                put_text(out, immutable_path)?;
            }
            Self::JendObject { object_id } => {
                out.push(3);
                out.extend_from_slice(&object_id.0);
            }
        }
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let origin = match reader.u8()? {
            1 => Self::HuggingFaceXet {
                repo_id: reader.text(MAX_REPO_ID)?,
                commit_sha: reader.text(40)?,
                file_path: reader.text(MAX_PATH)?,
            },
            2 => Self::PublisherHttps {
                host: reader.text(MAX_HOST)?,
                immutable_path: reader.text(MAX_PATH)?,
            },
            3 => Self::JendObject {
                object_id: ModelObjectId(reader.array()?),
            },
            _ => return Err(ModelStoreError::InvalidSourceDescriptor),
        };
        origin.validate()?;
        Ok(origin)
    }
}

impl SourceDescriptor {
    pub fn validate(&self) -> Result<()> {
        self.origin.validate()?;
        if self.object_len == 0 || self.object_len > MAX_OBJECT_BYTES {
            return Err(ModelStoreError::InvalidSourceDescriptor);
        }
        if self
            .whole_object_sha256
            .is_some_and(|digest| digest.iter().all(|byte| *byte == 0))
        {
            return Err(ModelStoreError::InvalidSourceDescriptor);
        }
        Ok(())
    }

    pub fn source_id(&self) -> Result<SourceId> {
        self.validate()?;
        let mut bytes = Vec::new();
        self.origin.encode(&mut bytes)?;
        bytes.extend_from_slice(&self.object_len.to_be_bytes());
        match self.whole_object_sha256 {
            Some(hash) => {
                bytes.push(1);
                bytes.extend_from_slice(&hash);
            }
            None => bytes.push(0),
        }
        let mut h = Sha256::new();
        h.update(SOURCE_DESCRIPTOR_DOMAIN);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
        Ok(SourceId(h.finalize().into()))
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        let source_id = self.source_id()?;
        out.extend_from_slice(&source_id.0);
        self.origin.encode(out)?;
        out.extend_from_slice(&self.object_len.to_be_bytes());
        match self.whole_object_sha256 {
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(&hash);
            }
            None => out.push(0),
        }
        Ok(())
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let encoded_id = SourceId(reader.array()?);
        let descriptor = Self {
            origin: SourceOrigin::decode(reader)?,
            object_len: reader.u64()?,
            whole_object_sha256: match reader.u8()? {
                0 => None,
                1 => Some(reader.array()?),
                _ => return Err(ModelStoreError::InvalidSourceDescriptor),
            },
        };
        descriptor.validate()?;
        if descriptor.source_id()? != encoded_id {
            return Err(ModelStoreError::InvalidSourceDescriptor);
        }
        Ok(descriptor)
    }
}

impl PageSourceBinding {
    pub fn validate_against(&self, source: &SourceDescriptor) -> Result<()> {
        self.page.validate()?;
        source.validate()?;
        if self.page.plaintext_len == 0 || self.page.plaintext_len > MAX_RANGE_BYTES {
            return Err(ModelStoreError::InvalidSourceBinding);
        }
        let end = self
            .source_offset
            .checked_add(self.page.plaintext_len)
            .ok_or(ModelStoreError::Overflow)?;
        if end > source.object_len {
            return Err(ModelStoreError::InvalidSourceBinding);
        }
        Ok(())
    }

    pub fn read_request(&self) -> SourceReadRequest {
        SourceReadRequest {
            source_id: self.source_id,
            source_offset: self.source_offset,
            len: self.page.plaintext_len,
            expected_page: self.page,
        }
    }
}

impl ModelSourceMap {
    pub fn validate(&self) -> Result<()> {
        if self.sources.is_empty()
            || self.sources.len() > MAX_SOURCES
            || self.bindings.is_empty()
            || self.bindings.len() > MAX_BINDINGS
        {
            return Err(ModelStoreError::InvalidSourceMap);
        }

        let mut source_ids = Vec::with_capacity(self.sources.len());
        let mut seen_sources = HashSet::new();
        for source in &self.sources {
            let source_id = source.source_id()?;
            if !seen_sources.insert(source_id) {
                return Err(ModelStoreError::InvalidSourceMap);
            }
            source_ids.push(source_id);
        }

        let mut seen_binding = HashSet::new();
        for binding in &self.bindings {
            let source_index = source_ids
                .iter()
                .position(|candidate| *candidate == binding.source_id)
                .ok_or(ModelStoreError::InvalidSourceBinding)?;
            binding.validate_against(&self.sources[source_index])?;
            if !seen_binding.insert((
                binding.page.page_id,
                binding.source_id,
                binding.source_offset,
            )) {
                return Err(ModelStoreError::InvalidSourceMap);
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(SOURCE_MAP_MAGIC);
        out.extend_from_slice(&SOURCE_MAP_VERSION.to_be_bytes());
        out.extend_from_slice(&self.model_id.0);
        out.extend_from_slice(&self.release_sequence.to_be_bytes());
        out.extend_from_slice(&(self.sources.len() as u32).to_be_bytes());
        for source in &self.sources {
            source.encode(&mut out)?;
        }
        out.extend_from_slice(&(self.bindings.len() as u32).to_be_bytes());
        for binding in &self.bindings {
            out.extend_from_slice(&binding.page.page_id.0);
            out.extend_from_slice(&binding.page.plaintext_len.to_be_bytes());
            out.extend_from_slice(&binding.source_id.0);
            out.extend_from_slice(&binding.source_offset.to_be_bytes());
        }
        Ok(out)
    }

    pub fn map_id(&self) -> Result<SourceMapId> {
        let bytes = self.canonical_bytes()?;
        let mut h = Sha256::new();
        h.update(SOURCE_MAP_DOMAIN);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
        Ok(SourceMapId(h.finalize().into()))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != SOURCE_MAP_MAGIC || reader.u16()? != SOURCE_MAP_VERSION {
            return Err(ModelStoreError::InvalidSourceMap);
        }
        let model_id = ModelId(reader.array()?);
        let release_sequence = reader.u64()?;
        let source_count = reader.u32()? as usize;
        if source_count == 0 || source_count > MAX_SOURCES {
            return Err(ModelStoreError::InvalidSourceMap);
        }
        let mut sources = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            sources.push(SourceDescriptor::decode(&mut reader)?);
        }

        let binding_count = reader.u32()? as usize;
        if binding_count == 0 || binding_count > MAX_BINDINGS {
            return Err(ModelStoreError::InvalidSourceMap);
        }
        let mut bindings = Vec::with_capacity(binding_count);
        for _ in 0..binding_count {
            bindings.push(PageSourceBinding {
                page: WeightPageDescriptor {
                    page_id: WeightPageId(reader.array()?),
                    plaintext_len: reader.u64()?,
                },
                source_id: SourceId(reader.array()?),
                source_offset: reader.u64()?,
            });
        }
        reader.finish()?;
        let map = Self {
            model_id,
            release_sequence,
            sources,
            bindings,
        };
        map.validate()?;
        Ok(map)
    }

    /// Ensure this transport map describes exactly pages belonging to the same
    /// signed logical model release. Every virtual page must have at least one
    /// source candidate and source bindings may not smuggle unrelated pages.
    pub fn validate_against_virtual_map(&self, virtual_map: &VirtualModelMap) -> Result<()> {
        self.validate()?;
        virtual_map.validate()?;
        if self.model_id != virtual_map.model_id
            || self.release_sequence != virtual_map.release_sequence
        {
            return Err(ModelStoreError::SourceVirtualMapMismatch);
        }

        let expected: HashSet<(WeightPageId, u64)> = virtual_map
            .regions
            .iter()
            .flat_map(|region| region.pages.iter())
            .map(|page| (page.page_id, page.plaintext_len))
            .collect();
        if expected.is_empty() {
            return Err(ModelStoreError::SourceVirtualMapMismatch);
        }

        let mut covered = HashSet::new();
        for binding in &self.bindings {
            let key = (binding.page.page_id, binding.page.plaintext_len);
            if !expected.contains(&key) {
                return Err(ModelStoreError::SourceVirtualMapMismatch);
            }
            covered.insert(key);
        }
        if covered != expected {
            return Err(ModelStoreError::SourceVirtualMapMismatch);
        }
        Ok(())
    }

    pub fn source(&self, source_id: SourceId) -> Result<&SourceDescriptor> {
        for source in &self.sources {
            if source.source_id()? == source_id {
                return Ok(source);
            }
        }
        Err(ModelStoreError::UnknownSourceDescriptor)
    }

    pub fn bindings_for_page(&self, page_id: WeightPageId) -> Vec<&PageSourceBinding> {
        self.bindings
            .iter()
            .filter(|binding| binding.page.page_id == page_id)
            .collect()
    }

    /// Produce a typed URL-free request for a particular source candidate.
    pub fn read_request(
        &self,
        page_id: WeightPageId,
        source_id: SourceId,
    ) -> Result<SourceReadRequest> {
        let binding = self
            .bindings
            .iter()
            .find(|binding| {
                binding.page.page_id == page_id && binding.source_id == source_id
            })
            .ok_or(ModelStoreError::UnknownSourceBinding)?;
        let source = self.source(source_id)?;
        binding.validate_against(source)?;
        Ok(binding.read_request())
    }
}

impl SignedModelSourceMap {
    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        let map = self.map.canonical_bytes()?;
        let map_len = u32::try_from(map.len()).map_err(|_| ModelStoreError::SourceMapTooLarge)?;
        let mut out = Vec::with_capacity(4 + map.len() + 32 + 16 + 64);
        out.extend_from_slice(&map_len.to_be_bytes());
        out.extend_from_slice(&map);
        out.extend_from_slice(&self.map_id.0);
        out.extend_from_slice(&self.release_key_id.0);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let map_len = reader.u32()? as usize;
        if map_len == 0 || map_len > 128 * 1024 * 1024 {
            return Err(ModelStoreError::SourceMapTooLarge);
        }
        let map = ModelSourceMap::from_canonical_bytes(reader.take(map_len)?)?;
        let map_id = SourceMapId(reader.array()?);
        let release_key_id = ReleaseKeyId(reader.array()?);
        let signature = reader.array()?;
        reader.finish()?;
        let signed = Self {
            map,
            map_id,
            release_key_id,
            signature,
        };
        if signed.map.map_id()? != signed.map_id {
            return Err(ModelStoreError::InvalidSourceMap);
        }
        Ok(signed)
    }
}

fn validate_repo_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_REPO_ID
        || value.starts_with('/')
        || value.ends_with('/')
        || value.matches('/').count() != 1
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(ModelStoreError::InvalidSourceDescriptor);
    }
    Ok(())
}

fn validate_commit_sha(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ModelStoreError::InvalidSourceDescriptor);
    }
    Ok(())
}

fn validate_repo_file_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > MAX_PATH
        || path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
        || path.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || !path.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'/' | b'-' | b'_' | b'.' | b'+' | b'=' )
        })
    {
        return Err(ModelStoreError::InvalidSourceDescriptor);
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > MAX_HOST
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host.contains('.')
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        return Err(ModelStoreError::InvalidSourceDescriptor);
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return Err(ModelStoreError::InvalidSourceDescriptor);
        }
    }
    Ok(())
}

fn validate_immutable_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > MAX_PATH
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
        || path.split('/').any(|segment| segment == "." || segment == "..")
        || !path.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'/' | b'-' | b'_' | b'.' | b'+' | b'=')
        })
    {
        return Err(ModelStoreError::InvalidSourceDescriptor);
    }
    Ok(())
}

fn put_text(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let len = u16::try_from(text.len()).map_err(|_| ModelStoreError::SourceMapTooLarge)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(ModelStoreError::Overflow)?;
        if end > self.bytes.len() {
            return Err(ModelStoreError::InvalidSourceMap);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(ModelStoreError::InvalidSourceMap)?)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ModelStoreError::InvalidSourceMap)?,
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ModelStoreError::InvalidSourceMap)?,
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ModelStoreError::InvalidSourceMap)?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| ModelStoreError::InvalidSourceMap)
    }

    fn text(&mut self, max: usize) -> Result<String> {
        let len = self.u16()? as usize;
        if len == 0 || len > max {
            return Err(ModelStoreError::InvalidSourceDescriptor);
        }
        let value = core::str::from_utf8(self.take(len)?)
            .map_err(|_| ModelStoreError::InvalidSourceDescriptor)?;
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(ModelStoreError::InvalidSourceMap)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(seed: u8, len: usize) -> WeightPageDescriptor {
        let bytes = vec![seed; len];
        WeightPageDescriptor {
            page_id: WeightPageId::for_bytes(&bytes),
            plaintext_len: len as u64,
        }
    }

    fn hf_source() -> SourceDescriptor {
        SourceDescriptor {
            origin: SourceOrigin::HuggingFaceXet {
                repo_id: "org/model".into(),
                commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                file_path: "model-00001-of-00002.safetensors".into(),
            },
            object_len: 16 * 1024,
            whole_object_sha256: None,
        }
    }

    #[test]
    fn hf_descriptor_requires_immutable_revision_and_structured_path() {
        assert!(hf_source().validate().is_ok());

        let mut bad = hf_source();
        if let SourceOrigin::HuggingFaceXet { commit_sha, .. } = &mut bad.origin {
            *commit_sha = "main".into();
        }
        assert!(bad.validate().is_err());

        let mut traversal = hf_source();
        if let SourceOrigin::HuggingFaceXet { file_path, .. } = &mut traversal.origin {
            *file_path = "../secret".into();
        }
        assert!(traversal.validate().is_err());
    }

    #[test]
    fn page_binding_is_range_bounded() {
        let source = hf_source();
        let binding = PageSourceBinding {
            page: page(3, 4096),
            source_id: source.source_id().unwrap(),
            source_offset: 14 * 1024,
        };
        assert!(binding.validate_against(&source).is_err());
    }

    #[test]
    fn one_page_can_have_multiple_transport_sources() {
        let hf = hf_source();
        let mirror = SourceDescriptor {
            origin: SourceOrigin::PublisherHttps {
                host: "models.example.com".into(),
                immutable_path: "/model/v1/shard.safetensors".into(),
            },
            object_len: 16 * 1024,
            whole_object_sha256: Some([7u8; 32]),
        };
        let p = page(9, 4096);
        let map = ModelSourceMap {
            model_id: ModelId([2u8; 16]),
            release_sequence: 7,
            sources: vec![hf.clone(), mirror.clone()],
            bindings: vec![
                PageSourceBinding {
                    page: p,
                    source_id: hf.source_id().unwrap(),
                    source_offset: 0,
                },
                PageSourceBinding {
                    page: p,
                    source_id: mirror.source_id().unwrap(),
                    source_offset: 8192,
                },
            ],
        };
        map.validate().unwrap();
        assert_eq!(map.bindings_for_page(p.page_id).len(), 2);
        assert_eq!(
            map.read_request(p.page_id, hf.source_id().unwrap())
                .unwrap()
                .expected_page,
            p
        );
    }

    #[test]
    fn source_map_must_cover_same_virtual_model_release() {
        let source = hf_source();
        let p = page(6, 4096);
        let map = ModelSourceMap {
            model_id: ModelId([6u8; 16]),
            release_sequence: 3,
            sources: vec![source.clone()],
            bindings: vec![PageSourceBinding {
                page: p,
                source_id: source.source_id().unwrap(),
                source_offset: 0,
            }],
        };
        let virtual_map = VirtualModelMap {
            model_id: ModelId([6u8; 16]),
            release_sequence: 3,
            minimum_runtime: 1,
            logical_weight_bytes: 4096,
            regions: vec![crate::VirtualRegion {
                region_id: 0,
                kind: crate::VirtualRegionKind::SharedBackbone,
                expert_id: None,
                expert_role: None,
                logical_offset: 0,
                logical_len: 4096,
                pages: vec![p],
                prefetch_regions: vec![],
            }],
        };
        map.validate_against_virtual_map(&virtual_map).unwrap();

        let mut wrong_release = virtual_map.clone();
        wrong_release.release_sequence += 1;
        assert!(matches!(
            map.validate_against_virtual_map(&wrong_release),
            Err(ModelStoreError::SourceVirtualMapMismatch)
        ));
    }

    #[test]
    fn canonical_source_map_roundtrip_is_stable() {
        let source = hf_source();
        let p = page(4, 4096);
        let map = ModelSourceMap {
            model_id: ModelId([5u8; 16]),
            release_sequence: 11,
            sources: vec![source.clone()],
            bindings: vec![PageSourceBinding {
                page: p,
                source_id: source.source_id().unwrap(),
                source_offset: 4096,
            }],
        };
        let bytes = map.canonical_bytes().unwrap();
        let decoded = ModelSourceMap::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, map);
        assert_eq!(decoded.map_id().unwrap(), map.map_id().unwrap());
    }
}
