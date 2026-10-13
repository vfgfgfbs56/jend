//! M8.5.13: untrusted Xet physical ranges -> existing release-signed
//! Jend WeightPage authorization -> durable local verified page.
//!
//! This module does NOT establish a release trust root. Callers MUST supply a
//! previously pinned/trusted ModelReleasePublicKey from independent local
//! release policy, never a key shipped alongside untrusted Xet metadata.
//! It uses the M8.5.6 signed-map gate and verified durable store, not a new
//! independent signature scheme. No network, model-signing or WeightVM bypass.

use jend_model_store::{
    DurableWeightPageStore, ModelReleasePublicKey, ModelSourceMap,
    ModelStoreError, SignedModelSourceMap, SignedVirtualModelMap,
    SourceId, SourceOrigin, WeightPageDescriptor, WeightPageId,
};
use crate::xet_metadata::Reconstruction;
use crate::xet_multi_decode::{decode_untrusted_multipart_ranges, MultiDecodeError};
use crate::xet_multi_fetch_transport::UntrustedXorbPhysicalRange;
use crate::xorb_decode::{reconstruct_slice_from_ranges, XorbDecodeError};

const HARD_MAX_PROBE_PAGE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct ExpectedImmutableHfSource<'a> {
    pub repo_id: &'a str,
    pub commit_sha: &'a str,
    pub file_path: &'a str,
    pub source_offset: u64,
}

#[derive(Debug)]
pub enum PageAdmissionError {
    InvalidLimits,
    UntrustedOrigin,
    UntrustedSourceOffset,
    SignedMap(ModelStoreError),
    PhysicalDecode(MultiDecodeError),
    LogicalReconstruction(XorbDecodeError),
    VerifiedStore(ModelStoreError),
}

impl std::fmt::Display for PageAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("verified Xet page size/byte limits rejected"),
            Self::UntrustedOrigin => f.write_str("signed Xet page source identity mismatch"),
            Self::UntrustedSourceOffset => f.write_str("signed Xet page source offset mismatch"),
            Self::SignedMap(_) => f.write_str("release-signed Xet page authorization rejected"),
            Self::PhysicalDecode(_) => f.write_str("untrusted Xet physical decode rejected"),
            Self::LogicalReconstruction(_) => f.write_str("Xet logical reconstruction rejected"),
            Self::VerifiedStore(_) => f.write_str("signed WeightPage length/SHA-256 or storage rejected"),
        }
    }
}
impl std::error::Error for PageAdmissionError {}

/// The requested source ID and page ID must appear in BOTH authenticated
/// release maps; the map key is supplied by independent trusted release
/// configuration. Source and offset must match the immutable pinned HF target.
///
/// All validation occurs before *any* staging file can exist. Once the signed
/// authorization is proved, Xet data are decoded/assembled into memory and
/// checked against the independent signed WeightPage digest+length by
/// DurableWeightPageStore::put_verified_source_page. The resulting object
/// can be read by WeightVM's SHA-256-verifying local page source.
pub fn reconstruct_and_publish_signed_xet_page(
    store: &DurableWeightPageStore,
    trusted_release_key: &ModelReleasePublicKey,
    signed_source_map: &SignedModelSourceMap,
    signed_virtual_map: &SignedVirtualModelMap,
    page_id: WeightPageId,
    source_id: SourceId,
    expected_source: ExpectedImmutableHfSource<'_>,
    reconstruction: &Reconstruction,
    physical_ranges: Vec<UntrustedXorbPhysicalRange>,
    max_physical_bytes: u64,
    max_decoded_bytes: u64,
) -> Result<WeightPageDescriptor, PageAdmissionError> {
    if max_physical_bytes == 0
        || max_physical_bytes > HARD_MAX_PROBE_PAGE_BYTES
        || max_decoded_bytes == 0
        || max_decoded_bytes > HARD_MAX_PROBE_PAGE_BYTES
    {
        return Err(PageAdmissionError::InvalidLimits);
    }

    // Authenticity of both maps and exact coverage of virtual WeightPages is
    // verified BEFORE a source descriptor is accepted for any publication.
    let verified = trusted_release_key.verify_source_read_request(
        signed_source_map,
        signed_virtual_map,
        page_id,
        source_id,
    ).map_err(PageAdmissionError::SignedMap)?;
    let request = verified.request();
    let source = signed_source_map.map.source(source_id)
        .map_err(PageAdmissionError::SignedMap)?;
    match &source.origin {
        SourceOrigin::HuggingFaceXet { repo_id, commit_sha, file_path }
            if repo_id == expected_source.repo_id
                && commit_sha == expected_source.commit_sha
                && file_path == expected_source.file_path => {}
        _ => return Err(PageAdmissionError::UntrustedOrigin),
    }
    if request.source_offset != expected_source.source_offset {
        return Err(PageAdmissionError::UntrustedSourceOffset);
    }
    if request.len == 0
        || request.len > HARD_MAX_PROBE_PAGE_BYTES
        || request.len > max_decoded_bytes
    {
        return Err(PageAdmissionError::InvalidLimits);
    }

    // The reconstruction and raw Xet ranges are NOT themselves Jend trust
    // claims. They may be reordered/forged by the source, but the final digest
    // and length are compared only to descriptors authorized by signed maps.
    let decoded = decode_untrusted_multipart_ranges(
        physical_ranges,
        max_physical_bytes,
        max_decoded_bytes,
    ).map_err(PageAdmissionError::PhysicalDecode)?;
    let bytes = reconstruct_slice_from_ranges(
        reconstruction,
        &decoded,
        request.len,
        request.len,
    ).map_err(PageAdmissionError::LogicalReconstruction)?;

    // Existing M8.5.6 code checks SHA-256+exact length before ANY staging.
    store.put_verified_source_page(verified, &bytes)
        .map_err(PageAdmissionError::VerifiedStore)
}

/// Avoid confusing an unauthenticated SourceMap with a release-signed grant.
/// The caller may inspect it only AFTER a trusted release-key verification.
#[allow(dead_code)]
fn _require_signed_map_type(_: &SignedModelSourceMap, _: &ModelSourceMap) {}
