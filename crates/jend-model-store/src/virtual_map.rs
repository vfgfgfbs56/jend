//! Signed virtual-model address map for WeightVM.
//!
//! A map binds logical model regions (backbone/router/experts/modules) to
//! ordered content-addressed weight pages. The map is canonical and release-
//! signed so a local cache cannot silently redirect an expert to other bytes.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::{ModelId, ModelStoreError, Result, WeightPageDescriptor, WeightPageId};

const MAP_MAGIC: &[u8; 4] = b"JVMP";
const MAP_VERSION: u16 = 1;
const MAP_ID_DOMAIN: &[u8] = b"JEND/MODEL/VIRTUAL-MAP/V1";
const MAX_REGIONS: usize = 65_536;
const MAX_PAGES_PER_REGION: usize = 131_072;
const MAX_PREFETCH_REGIONS: usize = 32;
const MAX_LOGICAL_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024; // 64 TiB

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VirtualMapId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExpertId(pub u32);

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualRegionKind {
    SharedBackbone = 1,
    Router = 2,
    Expert = 3,
    Adapter = 4,
    LongContext = 5,
    ToolUse = 6,
    Multimodal = 7,
}

impl VirtualRegionKind {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::SharedBackbone),
            2 => Ok(Self::Router),
            3 => Ok(Self::Expert),
            4 => Ok(Self::Adapter),
            5 => Ok(Self::LongContext),
            6 => Ok(Self::ToolUse),
            7 => Ok(Self::Multimodal),
            _ => Err(ModelStoreError::InvalidVirtualModelMap),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpertRole {
    General = 1,
    Reasoning = 2,
    Coding = 3,
    ToolUse = 4,
    Vision = 5,
    Writing = 6,
    Math = 7,
}

impl ExpertRole {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::General),
            2 => Ok(Self::Reasoning),
            3 => Ok(Self::Coding),
            4 => Ok(Self::ToolUse),
            5 => Ok(Self::Vision),
            6 => Ok(Self::Writing),
            7 => Ok(Self::Math),
            _ => Err(ModelStoreError::InvalidVirtualModelMap),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualRegion {
    /// Dense region index. M8.2 requires IDs 0..N so map references remain
    /// compact and deterministic.
    pub region_id: u32,
    pub kind: VirtualRegionKind,
    pub expert_id: Option<ExpertId>,
    pub expert_role: Option<ExpertRole>,
    pub logical_offset: u64,
    pub logical_len: u64,
    /// Ordered page descriptors covering this entire region.
    pub pages: Vec<WeightPageDescriptor>,
    /// Region IDs worth warming when this region is selected. Hints never
    /// bypass WeightVM budgets and do not make pages mandatory.
    pub prefetch_regions: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualModelMap {
    pub model_id: ModelId,
    pub release_sequence: u64,
    pub minimum_runtime: u32,
    pub logical_weight_bytes: u64,
    pub regions: Vec<VirtualRegion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedVirtualModelMap {
    pub map: VirtualModelMap,
    pub map_id: VirtualMapId,
    pub release_key_id: crate::ReleaseKeyId,
    pub signature: [u8; 64],
}

impl VirtualModelMap {
    pub fn validate(&self) -> Result<()> {
        if self.regions.is_empty()
            || self.regions.len() > MAX_REGIONS
            || self.logical_weight_bytes == 0
            || self.logical_weight_bytes > MAX_LOGICAL_BYTES
        {
            return Err(ModelStoreError::InvalidVirtualModelMap);
        }

        let mut expected_offset = 0u64;
        let mut expert_ids = HashSet::new();
        let mut has_backbone = false;
        let mut has_router = false;
        let mut expert_count = 0usize;

        for (expected_id, region) in self.regions.iter().enumerate() {
            if region.region_id != expected_id as u32
                || region.logical_offset != expected_offset
                || region.logical_len == 0
                || region.pages.is_empty()
                || region.pages.len() > MAX_PAGES_PER_REGION
                || region.prefetch_regions.len() > MAX_PREFETCH_REGIONS
            {
                return Err(ModelStoreError::InvalidVirtualModelMap);
            }

            match region.kind {
                VirtualRegionKind::SharedBackbone => {
                    has_backbone = true;
                    if region.expert_id.is_some() || region.expert_role.is_some() {
                        return Err(ModelStoreError::InvalidVirtualModelMap);
                    }
                }
                VirtualRegionKind::Router => {
                    has_router = true;
                    if region.expert_id.is_some() || region.expert_role.is_some() {
                        return Err(ModelStoreError::InvalidVirtualModelMap);
                    }
                }
                VirtualRegionKind::Expert => {
                    expert_count = expert_count
                        .checked_add(1)
                        .ok_or(ModelStoreError::Overflow)?;
                    let expert_id = region
                        .expert_id
                        .ok_or(ModelStoreError::InvalidVirtualModelMap)?;
                    if expert_id.0 == 0
                        || region.expert_role.is_none()
                        || !expert_ids.insert(expert_id)
                    {
                        return Err(ModelStoreError::InvalidVirtualModelMap);
                    }
                }
                _ => {
                    if region.expert_id.is_some() || region.expert_role.is_some() {
                        return Err(ModelStoreError::InvalidVirtualModelMap);
                    }
                }
            }

            let mut page_total = 0u64;
            for page in &region.pages {
                page.validate()?;
                page_total = page_total
                    .checked_add(page.plaintext_len)
                    .ok_or(ModelStoreError::Overflow)?;
            }
            if page_total != region.logical_len {
                return Err(ModelStoreError::InvalidVirtualModelMap);
            }

            let mut hints = HashSet::new();
            for hint in &region.prefetch_regions {
                if *hint as usize >= self.regions.len()
                    || *hint == region.region_id
                    || !hints.insert(*hint)
                {
                    return Err(ModelStoreError::InvalidVirtualModelMap);
                }
            }

            expected_offset = expected_offset
                .checked_add(region.logical_len)
                .ok_or(ModelStoreError::Overflow)?;
        }

        if expected_offset != self.logical_weight_bytes
            || !has_backbone
            || (expert_count > 0 && !has_router)
        {
            return Err(ModelStoreError::InvalidVirtualModelMap);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(MAP_MAGIC);
        out.extend_from_slice(&MAP_VERSION.to_be_bytes());
        out.extend_from_slice(&self.model_id.0);
        out.extend_from_slice(&self.release_sequence.to_be_bytes());
        out.extend_from_slice(&self.minimum_runtime.to_be_bytes());
        out.extend_from_slice(&self.logical_weight_bytes.to_be_bytes());
        out.extend_from_slice(&(self.regions.len() as u32).to_be_bytes());

        for region in &self.regions {
            out.extend_from_slice(&region.region_id.to_be_bytes());
            out.push(region.kind as u8);
            match (region.expert_id, region.expert_role) {
                (Some(expert_id), Some(role)) => {
                    out.push(1);
                    out.extend_from_slice(&expert_id.0.to_be_bytes());
                    out.push(role as u8);
                }
                (None, None) => out.push(0),
                _ => return Err(ModelStoreError::InvalidVirtualModelMap),
            }
            out.extend_from_slice(&region.logical_offset.to_be_bytes());
            out.extend_from_slice(&region.logical_len.to_be_bytes());
            out.extend_from_slice(&(region.pages.len() as u32).to_be_bytes());
            for page in &region.pages {
                out.extend_from_slice(&page.page_id.0);
                out.extend_from_slice(&page.plaintext_len.to_be_bytes());
            }
            out.extend_from_slice(&(region.prefetch_regions.len() as u16).to_be_bytes());
            for hint in &region.prefetch_regions {
                out.extend_from_slice(&hint.to_be_bytes());
            }
        }
        Ok(out)
    }

    pub fn map_id(&self) -> Result<VirtualMapId> {
        let bytes = self.canonical_bytes()?;
        let mut h = Sha256::new();
        h.update(MAP_ID_DOMAIN);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(&bytes);
        Ok(VirtualMapId(h.finalize().into()))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != MAP_MAGIC || r.u16()? != MAP_VERSION {
            return Err(ModelStoreError::InvalidVirtualModelMap);
        }
        let model_id = ModelId(r.array()?);
        let release_sequence = r.u64()?;
        let minimum_runtime = r.u32()?;
        let logical_weight_bytes = r.u64()?;
        let region_count = r.u32()? as usize;
        if region_count == 0 || region_count > MAX_REGIONS {
            return Err(ModelStoreError::InvalidVirtualModelMap);
        }

        let mut regions = Vec::with_capacity(region_count);
        for _ in 0..region_count {
            let region_id = r.u32()?;
            let kind = VirtualRegionKind::from_u8(r.u8()?)?;
            let has_expert = r.u8()?;
            let (expert_id, expert_role) = match has_expert {
                0 => (None, None),
                1 => (
                    Some(ExpertId(r.u32()?)),
                    Some(ExpertRole::from_u8(r.u8()?)?),
                ),
                _ => return Err(ModelStoreError::InvalidVirtualModelMap),
            };
            let logical_offset = r.u64()?;
            let logical_len = r.u64()?;
            let page_count = r.u32()? as usize;
            if page_count == 0 || page_count > MAX_PAGES_PER_REGION {
                return Err(ModelStoreError::InvalidVirtualModelMap);
            }
            let mut pages = Vec::with_capacity(page_count);
            for _ in 0..page_count {
                pages.push(WeightPageDescriptor {
                    page_id: WeightPageId(r.array()?),
                    plaintext_len: r.u64()?,
                });
            }
            let hint_count = r.u16()? as usize;
            if hint_count > MAX_PREFETCH_REGIONS {
                return Err(ModelStoreError::InvalidVirtualModelMap);
            }
            let mut prefetch_regions = Vec::with_capacity(hint_count);
            for _ in 0..hint_count {
                prefetch_regions.push(r.u32()?);
            }
            regions.push(VirtualRegion {
                region_id,
                kind,
                expert_id,
                expert_role,
                logical_offset,
                logical_len,
                pages,
                prefetch_regions,
            });
        }
        r.finish()?;
        let map = Self {
            model_id,
            release_sequence,
            minimum_runtime,
            logical_weight_bytes,
            regions,
        };
        map.validate()?;
        Ok(map)
    }

    pub fn region(&self, region_id: u32) -> Result<&VirtualRegion> {
        self.regions
            .get(region_id as usize)
            .filter(|region| region.region_id == region_id)
            .ok_or(ModelStoreError::UnknownVirtualRegion)
    }

    pub fn expert(&self, expert_id: ExpertId) -> Result<&VirtualRegion> {
        self.regions
            .iter()
            .find(|region| region.expert_id == Some(expert_id))
            .ok_or(ModelStoreError::UnknownVirtualExpert)
    }

    pub fn experts_for_role(&self, role: ExpertRole) -> Vec<ExpertId> {
        self.regions
            .iter()
            .filter(|region| {
                region.kind == VirtualRegionKind::Expert && region.expert_role == Some(role)
            })
            .filter_map(|region| region.expert_id)
            .collect()
    }

    /// Ordered mandatory pages for one expert.
    pub fn pages_for_expert(&self, expert_id: ExpertId) -> Result<&[WeightPageDescriptor]> {
        Ok(&self.expert(expert_id)?.pages)
    }

    /// Build a deduplicated warm-up plan containing hinted regions first and
    /// the selected expert last. This ordering helps keep the selected expert
    /// hottest in a small LRU cache.
    pub fn prefetch_pages_for_expert(
        &self,
        expert_id: ExpertId,
    ) -> Result<Vec<WeightPageDescriptor>> {
        let expert = self.expert(expert_id)?;
        let mut out = Vec::new();
        let mut seen = HashSet::<WeightPageId>::new();

        for region_id in &expert.prefetch_regions {
            let region = self.region(*region_id)?;
            for page in &region.pages {
                if seen.insert(page.page_id) {
                    out.push(*page);
                }
            }
        }
        for page in &expert.pages {
            if seen.insert(page.page_id) {
                out.push(*page);
            }
        }
        Ok(out)
    }
}

impl SignedVirtualModelMap {
    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        let map = self.map.canonical_bytes()?;
        let map_len = u32::try_from(map.len()).map_err(|_| ModelStoreError::VirtualMapTooLarge)?;
        let mut out = Vec::with_capacity(4 + map.len() + 32 + 16 + 64);
        out.extend_from_slice(&map_len.to_be_bytes());
        out.extend_from_slice(&map);
        out.extend_from_slice(&self.map_id.0);
        out.extend_from_slice(&self.release_key_id.0);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let map_len = r.u32()? as usize;
        if map_len == 0 || map_len > 64 * 1024 * 1024 {
            return Err(ModelStoreError::VirtualMapTooLarge);
        }
        let map = VirtualModelMap::from_canonical_bytes(r.take(map_len)?)?;
        let map_id = VirtualMapId(r.array()?);
        let release_key_id = crate::ReleaseKeyId(r.array()?);
        let signature = r.array()?;
        r.finish()?;
        let signed = Self {
            map,
            map_id,
            release_key_id,
            signature,
        };
        if signed.map.map_id()? != signed.map_id {
            return Err(ModelStoreError::InvalidVirtualModelMap);
        }
        Ok(signed)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(ModelStoreError::Overflow)?;
        if end > self.bytes.len() {
            return Err(ModelStoreError::InvalidVirtualModelMap);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(*self.take(1)?.first().ok_or(ModelStoreError::InvalidVirtualModelMap)?)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| ModelStoreError::InvalidVirtualModelMap)?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| ModelStoreError::InvalidVirtualModelMap)?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| ModelStoreError::InvalidVirtualModelMap)?))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| ModelStoreError::InvalidVirtualModelMap)
    }
    fn finish(self) -> Result<()> {
        if self.pos == self.bytes.len() { Ok(()) } else { Err(ModelStoreError::InvalidVirtualModelMap) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(seed: u8, len: u64) -> WeightPageDescriptor {
        let payload = vec![seed; len as usize];
        WeightPageDescriptor {
            page_id: WeightPageId::for_bytes(&payload),
            plaintext_len: len,
        }
    }

    fn sample() -> VirtualModelMap {
        VirtualModelMap {
            model_id: ModelId([5u8; 16]),
            release_sequence: 9,
            minimum_runtime: 1,
            logical_weight_bytes: 6 * 1024,
            regions: vec![
                VirtualRegion {
                    region_id: 0,
                    kind: VirtualRegionKind::SharedBackbone,
                    expert_id: None,
                    expert_role: None,
                    logical_offset: 0,
                    logical_len: 1024,
                    pages: vec![page(1, 1024)],
                    prefetch_regions: vec![],
                },
                VirtualRegion {
                    region_id: 1,
                    kind: VirtualRegionKind::Router,
                    expert_id: None,
                    expert_role: None,
                    logical_offset: 1024,
                    logical_len: 1024,
                    pages: vec![page(2, 1024)],
                    prefetch_regions: vec![0],
                },
                VirtualRegion {
                    region_id: 2,
                    kind: VirtualRegionKind::Expert,
                    expert_id: Some(ExpertId(17)),
                    expert_role: Some(ExpertRole::Coding),
                    logical_offset: 2048,
                    logical_len: 2 * 1024,
                    pages: vec![page(3, 1024), page(4, 1024)],
                    prefetch_regions: vec![0, 1],
                },
                VirtualRegion {
                    region_id: 3,
                    kind: VirtualRegionKind::Expert,
                    expert_id: Some(ExpertId(42)),
                    expert_role: Some(ExpertRole::Reasoning),
                    logical_offset: 4 * 1024,
                    logical_len: 2 * 1024,
                    pages: vec![page(5, 1024), page(6, 1024)],
                    prefetch_regions: vec![0, 1],
                },
            ],
        }
    }

    #[test]
    fn canonical_roundtrip_is_stable() {
        let map = sample();
        let encoded = map.canonical_bytes().unwrap();
        let decoded = VirtualModelMap::from_canonical_bytes(&encoded).unwrap();
        assert_eq!(map, decoded);
        assert_eq!(map.map_id().unwrap(), decoded.map_id().unwrap());
    }

    #[test]
    fn coding_expert_resolves_pages_and_prefetch_dependencies() {
        let map = sample();
        assert_eq!(map.experts_for_role(ExpertRole::Coding), vec![ExpertId(17)]);
        assert_eq!(map.pages_for_expert(ExpertId(17)).unwrap().len(), 2);
        assert_eq!(map.prefetch_pages_for_expert(ExpertId(17)).unwrap().len(), 4);
    }

    #[test]
    fn duplicate_expert_id_is_rejected() {
        let mut map = sample();
        map.regions[3].expert_id = Some(ExpertId(17));
        assert!(map.validate().is_err());
    }

    #[test]
    fn region_page_lengths_must_cover_logical_region() {
        let mut map = sample();
        map.regions[2].logical_len += 1;
        assert!(map.validate().is_err());
    }
}
