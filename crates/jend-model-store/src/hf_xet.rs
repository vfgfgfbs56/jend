//! Hugging Face/Xet source-adapter request and reconstruction planner.
//!
//! M8.4 deliberately contains NO HTTP client. It converts the URL-free Jend
//! Source Descriptor Protocol into typed HTTPS request metadata and validates
//! Xet reconstruction metadata before a future isolated transport is allowed to
//! fetch signed xorb ranges.
//!
//! Security invariants:
//! - WeightVM never sees Hugging Face URLs or credentials.
//! - Hub resolve discovery never follows the redirect; it only accepts
//!   `X-Xet-Hash` as the Xet file identity.
//! - model revisions stay pinned to full immutable 40-hex commits.
//! - Xet CAS/transfer endpoints are explicit allowlists.
//! - Xet bearer tokens and signed transfer URLs are zeroized and not Debug.
//! - object ranges, metadata fanout and transfer bytes are bounded.
//!
//! M8.5 will add isolated HTTP/DNS/JSON/xorb transport and decoding. Keeping it
//! separate prevents `jend-model-store` / WeightVM from gaining arbitrary
//! network access.

use zeroize::Zeroizing;

use crate::{
    ModelStoreError, Result, SourceDescriptor, SourceOrigin, SourceReadRequest,
    WeightPageDescriptor,
};

const HF_HUB_HOST: &str = "huggingface.co";
const HF_CAS_HOST_US: &str = "cas-server.xethub.hf.co";
const HF_CAS_HOST_EU: &str = "cas-server.xethub-eu.hf.co";
const HF_TRANSFER_HOST_US: &str = "transfer.xethub.hf.co";
const HF_TRANSFER_HOST_EU: &str = "transfer.xethub-eu.hf.co";
const HF_CDN_HOST_AWS_US: &str = "us.aws.cdn.hf.co";
const HF_CDN_HOST_GCP_US: &str = "us.gcp.cdn.hf.co";
const MAX_TOKEN_CHARS: usize = 64_000;
const MAX_SIGNED_URL_CHARS: usize = 64 * 1024;
const TOKEN_REFRESH_SKEW_SECONDS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HfCredentialScope {
    HubRead,
    XetRead,
    SignedTransfer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HfRedirectPolicy {
    Reject,
}

/// Safe-to-log request metadata. Secrets are never embedded in this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HfHttpRequestPlan {
    pub host: String,
    pub path_and_query: String,
    pub range_header: Option<String>,
    pub credential_scope: HfCredentialScope,
    pub redirect_policy: HfRedirectPolicy,
    pub max_response_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HfXetAdapterPolicy {
    pub max_reconstruction_response_bytes: u64,
    pub max_terms: usize,
    pub max_fetch_entries: usize,
    pub max_ranges: usize,
    pub max_single_fetch_bytes: u64,
    pub max_total_fetch_bytes: u64,
}

impl Default for HfXetAdapterPolicy {
    fn default() -> Self {
        Self {
            max_reconstruction_response_bytes: 8 * 1024 * 1024,
            max_terms: 16_384,
            max_fetch_entries: 8_192,
            max_ranges: 32_768,
            max_single_fetch_bytes: 128 * 1024 * 1024,
            max_total_fetch_bytes: 1024 * 1024 * 1024,
        }
    }
}

impl HfXetAdapterPolicy {
    pub fn validate(self) -> Result<Self> {
        if self.max_reconstruction_response_bytes == 0
            || self.max_reconstruction_response_bytes > 32 * 1024 * 1024
            || self.max_terms == 0
            || self.max_terms > 65_536
            || self.max_fetch_entries == 0
            || self.max_fetch_entries > 65_536
            || self.max_ranges == 0
            || self.max_ranges > 262_144
            || self.max_single_fetch_bytes == 0
            || self.max_single_fetch_bytes > 512 * 1024 * 1024
            || self.max_total_fetch_bytes < self.max_single_fetch_bytes
            || self.max_total_fetch_bytes > 2 * 1024 * 1024 * 1024
        {
            return Err(ModelStoreError::InvalidHfXetPolicy);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HfXetFileId(pub [u8; 32]);

impl HfXetFileId {
    pub fn parse_lower_hex(value: &str) -> Result<Self> {
        Ok(Self(
            parse_32_lower_hex(value).ok_or(ModelStoreError::InvalidHfXetFileId)?,
        ))
    }

    pub fn to_lower_hex(self) -> String {
        lower_hex(&self.0)
    }
}

/// Secret-bearing Xet read grant. Intentionally no `Debug` implementation.
pub struct HfXetReadGrant {
    access_token: Zeroizing<String>,
    cas_host: String,
    expires_unix: u64,
}

impl HfXetReadGrant {
    pub fn from_token_fields(
        access_token: String,
        expires_unix: u64,
        cas_url: &str,
        now_unix: u64,
    ) -> Result<Self> {
        if access_token.is_empty()
            || access_token.len() > MAX_TOKEN_CHARS
            || access_token
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(ModelStoreError::InvalidHfXetGrant);
        }
        let min_expiry = now_unix
            .checked_add(TOKEN_REFRESH_SKEW_SECONDS)
            .ok_or(ModelStoreError::Overflow)?;
        if expires_unix <= min_expiry {
            return Err(ModelStoreError::InvalidHfXetGrant);
        }
        let cas_host =
            parse_exact_https_origin(cas_url).ok_or(ModelStoreError::InvalidHfXetGrant)?;
        if !is_allowed_cas_host(&cas_host) {
            return Err(ModelStoreError::InvalidHfXetGrant);
        }
        Ok(Self {
            access_token: Zeroizing::new(access_token),
            cas_host,
            expires_unix,
        })
    }

    pub fn cas_host(&self) -> &str { &self.cas_host }
    pub fn expires_unix(&self) -> u64 { self.expires_unix }

    pub fn is_usable_at(&self, now_unix: u64) -> bool {
        now_unix
            .checked_add(TOKEN_REFRESH_SKEW_SECONDS)
            .is_some_and(|refresh_at| refresh_at < self.expires_unix)
    }

    /// Transport-only access. Do not log.
    pub fn access_token(&self) -> &str { self.access_token.as_str() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XetChunkRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XetByteRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XetTermMetadata {
    pub xorb_hash: String,
    pub chunks: XetChunkRange,
    pub unpacked_length: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XetRangeMetadata {
    pub chunks: XetChunkRange,
    pub bytes: XetByteRange,
}

/// Signed URL is secret-ish because its query authorizes a short-lived read.
pub struct XetFetchMetadata {
    pub xorb_hash: String,
    pub signed_url: Zeroizing<String>,
    pub ranges: Vec<XetRangeMetadata>,
}

impl XetFetchMetadata {
    pub fn new(xorb_hash: String, signed_url: String, ranges: Vec<XetRangeMetadata>) -> Self {
        Self {
            xorb_hash,
            signed_url: Zeroizing::new(signed_url),
            ranges,
        }
    }
}

/// Validated transfer request. Intentionally no Debug because signed URLs carry
/// short-lived authorization query material.
pub struct XetSignedFetchPlan {
    xorb_hash: String,
    signed_url: Zeroizing<String>,
    range_header: String,
    response_budget_bytes: u64,
}

impl XetSignedFetchPlan {
    pub fn xorb_hash(&self) -> &str { &self.xorb_hash }
    pub fn signed_url(&self) -> &str { self.signed_url.as_str() }
    pub fn range_header(&self) -> &str { &self.range_header }
    pub fn response_budget_bytes(&self) -> u64 { self.response_budget_bytes }
}

pub struct HfXetReconstructionPlan {
    pub trim_leading_bytes: u64,
    pub output_len: u64,
    pub expected_page: WeightPageDescriptor,
    fetches: Vec<XetSignedFetchPlan>,
}

impl HfXetReconstructionPlan {
    pub fn fetches(&self) -> &[XetSignedFetchPlan] { &self.fetches }

    pub fn total_fetch_budget_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        for fetch in &self.fetches {
            total = total
                .checked_add(fetch.response_budget_bytes)
                .ok_or(ModelStoreError::Overflow)?;
        }
        Ok(total)
    }
}

#[derive(Clone, Debug)]
pub struct HfXetRequestPlanner {
    policy: HfXetAdapterPolicy,
    repo_id: String,
    commit_sha: String,
    file_path: String,
    request: SourceReadRequest,
}

impl HfXetRequestPlanner {
    pub fn new(
        source: &SourceDescriptor,
        request: SourceReadRequest,
        policy: HfXetAdapterPolicy,
    ) -> Result<Self> {
        source.validate()?;
        let policy = policy.validate()?;
        if source.source_id()? != request.source_id {
            return Err(ModelStoreError::InvalidHfXetSource);
        }
        request.expected_page.validate()?;
        if request.len != request.expected_page.plaintext_len || request.len == 0 {
            return Err(ModelStoreError::InvalidHfXetSource);
        }
        let end = request
            .source_offset
            .checked_add(request.len)
            .ok_or(ModelStoreError::Overflow)?;
        if end > source.object_len {
            return Err(ModelStoreError::InvalidHfXetSource);
        }

        let SourceOrigin::HuggingFaceXet {
            repo_id,
            commit_sha,
            file_path,
        } = &source.origin
        else {
            return Err(ModelStoreError::InvalidHfXetSource);
        };

        Ok(Self {
            policy,
            repo_id: repo_id.clone(),
            commit_sha: commit_sha.clone(),
            file_path: file_path.clone(),
            request,
        })
    }

    /// Read `X-Xet-Hash` only. Redirects MUST NOT be followed.
    pub fn resolve_request(&self) -> HfHttpRequestPlan {
        HfHttpRequestPlan {
            host: HF_HUB_HOST.into(),
            path_and_query: format!(
                "/{}/resolve/{}/{}",
                self.repo_id, self.commit_sha, self.file_path
            ),
            range_header: Some("bytes=0-0".into()),
            credential_scope: HfCredentialScope::HubRead,
            redirect_policy: HfRedirectPolicy::Reject,
            max_response_bytes: 4096,
        }
    }

    pub fn read_token_request(&self) -> HfHttpRequestPlan {
        HfHttpRequestPlan {
            host: HF_HUB_HOST.into(),
            path_and_query: format!(
                "/api/models/{}/xet-read-token/{}",
                self.repo_id, self.commit_sha
            ),
            range_header: None,
            credential_scope: HfCredentialScope::HubRead,
            redirect_policy: HfRedirectPolicy::Reject,
            max_response_bytes: 128 * 1024,
        }
    }

    pub fn accept_resolve_response(
        &self,
        status_code: u16,
        x_xet_hash: Option<&str>,
    ) -> Result<HfXetFileId> {
        if !(300..400).contains(&status_code) {
            return Err(ModelStoreError::InvalidHfXetResolveResponse);
        }
        let value = x_xet_hash.ok_or(ModelStoreError::HfXetFileIdentityMissing)?;
        HfXetFileId::parse_lower_hex(value)
    }

    pub fn reconstruction_v2_request(
        &self,
        file_id: HfXetFileId,
        grant: &HfXetReadGrant,
        now_unix: u64,
    ) -> Result<HfHttpRequestPlan> {
        if !grant.is_usable_at(now_unix) {
            return Err(ModelStoreError::InvalidHfXetGrant);
        }
        let end_inclusive = self
            .request
            .source_offset
            .checked_add(self.request.len)
            .and_then(|value| value.checked_sub(1))
            .ok_or(ModelStoreError::Overflow)?;
        Ok(HfHttpRequestPlan {
            host: grant.cas_host().into(),
            path_and_query: format!("/v2/reconstructions/{}", file_id.to_lower_hex()),
            range_header: Some(format!(
                "bytes={}-{}",
                self.request.source_offset, end_inclusive
            )),
            credential_scope: HfCredentialScope::XetRead,
            redirect_policy: HfRedirectPolicy::Reject,
            max_response_bytes: self.policy.max_reconstruction_response_bytes,
        })
    }

    pub fn reconstruction_v1_fallback_request(
        &self,
        file_id: HfXetFileId,
        grant: &HfXetReadGrant,
        now_unix: u64,
    ) -> Result<HfHttpRequestPlan> {
        let mut request = self.reconstruction_v2_request(file_id, grant, now_unix)?;
        request.path_and_query = format!("/v1/reconstructions/{}", file_id.to_lower_hex());
        Ok(request)
    }

    pub fn validate_v2_reconstruction(
        &self,
        offset_into_first_range: u64,
        terms: &[XetTermMetadata],
        fetches: Vec<XetFetchMetadata>,
    ) -> Result<HfXetReconstructionPlan> {
        if terms.is_empty()
            || terms.len() > self.policy.max_terms
            || fetches.is_empty()
            || fetches.len() > self.policy.max_fetch_entries
        {
            return Err(ModelStoreError::InvalidHfXetReconstruction);
        }

        let mut total_unpacked = 0u64;
        for term in terms {
            validate_hash_text(&term.xorb_hash)?;
            validate_chunk_range(term.chunks)?;
            if term.unpacked_length == 0 {
                return Err(ModelStoreError::InvalidHfXetReconstruction);
            }
            total_unpacked = total_unpacked
                .checked_add(term.unpacked_length)
                .ok_or(ModelStoreError::Overflow)?;
        }
        let needed_unpacked = offset_into_first_range
            .checked_add(self.request.len)
            .ok_or(ModelStoreError::Overflow)?;
        if total_unpacked < needed_unpacked {
            return Err(ModelStoreError::InvalidHfXetReconstruction);
        }

        let mut validated_fetches = Vec::with_capacity(fetches.len());
        let mut coverage: Vec<(String, XetChunkRange)> = Vec::new();
        let mut total_range_count = 0usize;
        let mut total_fetch_bytes = 0u64;

        for fetch in fetches {
            validate_hash_text(&fetch.xorb_hash)?;
            validate_signed_xorb_url(fetch.signed_url.as_str(), &fetch.xorb_hash)?;
            if fetch.ranges.is_empty() {
                return Err(ModelStoreError::InvalidHfXetReconstruction);
            }
            total_range_count = total_range_count
                .checked_add(fetch.ranges.len())
                .ok_or(ModelStoreError::Overflow)?;
            if total_range_count > self.policy.max_ranges {
                return Err(ModelStoreError::HfXetBudgetExceeded);
            }

            let mut range_header = String::from("bytes=");
            let mut fetch_bytes = 0u64;
            let mut previous_byte_end: Option<u64> = None;
            let mut previous_chunk_end: Option<u32> = None;

            for (index, range) in fetch.ranges.iter().enumerate() {
                validate_chunk_range(range.chunks)?;
                if range.bytes.start > range.bytes.end {
                    return Err(ModelStoreError::InvalidHfXetReconstruction);
                }
                if previous_byte_end.is_some_and(|end| range.bytes.start <= end)
                    || previous_chunk_end.is_some_and(|end| range.chunks.start < end)
                {
                    return Err(ModelStoreError::InvalidHfXetReconstruction);
                }
                let bytes = range
                    .bytes
                    .end
                    .checked_sub(range.bytes.start)
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ModelStoreError::Overflow)?;
                if bytes > self.policy.max_single_fetch_bytes {
                    return Err(ModelStoreError::HfXetBudgetExceeded);
                }
                fetch_bytes = fetch_bytes
                    .checked_add(bytes)
                    .ok_or(ModelStoreError::Overflow)?;
                if index > 0 {
                    range_header.push(',');
                }
                range_header.push_str(&format!("{}-{}", range.bytes.start, range.bytes.end));
                previous_byte_end = Some(range.bytes.end);
                previous_chunk_end = Some(range.chunks.end);
                coverage.push((fetch.xorb_hash.clone(), range.chunks));
            }

            total_fetch_bytes = total_fetch_bytes
                .checked_add(fetch_bytes)
                .ok_or(ModelStoreError::Overflow)?;
            if total_fetch_bytes > self.policy.max_total_fetch_bytes {
                return Err(ModelStoreError::HfXetBudgetExceeded);
            }

            validated_fetches.push(XetSignedFetchPlan {
                xorb_hash: fetch.xorb_hash,
                signed_url: fetch.signed_url,
                range_header,
                response_budget_bytes: fetch_bytes,
            });
        }

        for term in terms {
            let mut intervals: Vec<XetChunkRange> = coverage
                .iter()
                .filter(|(hash, _)| hash == &term.xorb_hash)
                .map(|(_, range)| *range)
                .collect();
            intervals.sort_by_key(|range| range.start);

            let mut cursor = term.chunks.start;
            for interval in intervals {
                if interval.end <= cursor {
                    continue;
                }
                if interval.start > cursor {
                    break;
                }
                cursor = cursor.max(interval.end);
                if cursor >= term.chunks.end {
                    break;
                }
            }
            if cursor < term.chunks.end {
                return Err(ModelStoreError::InvalidHfXetReconstruction);
            }
        }

        Ok(HfXetReconstructionPlan {
            trim_leading_bytes: offset_into_first_range,
            output_len: self.request.len,
            expected_page: self.request.expected_page,
            fetches: validated_fetches,
        })
    }
}

fn validate_chunk_range(range: XetChunkRange) -> Result<()> {
    if range.start >= range.end {
        return Err(ModelStoreError::InvalidHfXetReconstruction);
    }
    Ok(())
}

fn validate_hash_text(value: &str) -> Result<()> {
    if parse_32_lower_hex(value).is_none() {
        return Err(ModelStoreError::InvalidHfXetReconstruction);
    }
    Ok(())
}

fn validate_signed_xorb_url(url: &str, expected_hash: &str) -> Result<()> {
    if url.is_empty() || url.len() > MAX_SIGNED_URL_CHARS {
        return Err(ModelStoreError::InvalidHfXetReconstruction);
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(ModelStoreError::InvalidHfXetReconstruction);
    };
    let slash = rest
        .find('/')
        .ok_or(ModelStoreError::InvalidHfXetReconstruction)?;
    let authority = &rest[..slash];
    if authority.is_empty() || authority.contains('@') || authority.contains(':') {
        return Err(ModelStoreError::InvalidHfXetReconstruction);
    }
    let path_and_query = &rest[slash..];
    if path_and_query.contains('#') {
        return Err(ModelStoreError::InvalidHfXetReconstruction);
    }
    let (path, query) = path_and_query
        .split_once('?')
        .ok_or(ModelStoreError::InvalidHfXetReconstruction)?;

    if is_allowed_transfer_host(authority) {
        let plural = format!("/xorbs/default/{expected_hash}");
        let singular = format!("/xorb/default/{expected_hash}");
        if path != plural && path != singular || !query_has_nonempty(query, "X-Xet-Signed-Range") {
            return Err(ModelStoreError::InvalidHfXetReconstruction);
        }
    } else if is_allowed_cdn_host(authority) {
        let plural = format!("/xorbs/default/{expected_hash}");
        let singular = format!("/xorb/default/{expected_hash}");
        let is_direct_xorb = path == plural || path == singular;
        if (!is_direct_xorb && !valid_hf_cdn_bridge_path(path, expected_hash))
            || ["Expires", "Policy", "Signature", "Key-Pair-Id"]
                .iter()
                .any(|key| !query_has_nonempty(query, key))
        {
            return Err(ModelStoreError::InvalidHfXetReconstruction);
        }
        // HF CDN direct-xorb URLs can omit X-Xet-Signed-Range in current
        // live traffic. The authenticated reconstruction ranges remain the
        // sole source for the future HTTP Range header. transfer.xethub.*
        // still requires X-Xet-Signed-Range above.
    } else {
        return Err(ModelStoreError::InvalidHfXetReconstruction);
    }
    Ok(())
}


fn query_has_nonempty(query: &str, key: &str) -> bool {
    query.split('&').any(|pair| {
        pair.split_once('=')
            .is_some_and(|(candidate, value)| candidate == key && !value.is_empty())
    })
}

fn valid_hf_cdn_bridge_path(path: &str, expected_hash: &str) -> bool {
    let Some(rest) = path.strip_prefix("/xet-bridge-us/") else { return false; };
    let mut parts = rest.split('/');
    let Some(opaque_id) = parts.next() else { return false; };
    let Some(hash) = parts.next() else { return false; };
    parts.next().is_none()
        && !opaque_id.is_empty()
        && opaque_id.len() <= 128
        && opaque_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        && hash == expected_hash
}

fn parse_exact_https_origin(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    if rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return None;
    }
    let host = rest.strip_suffix('/').unwrap_or(rest);
    if host.is_empty()
        || host.contains('/')
        || host.contains(':')
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
    {
        return None;
    }
    Some(host.to_owned())
}

fn is_allowed_cas_host(host: &str) -> bool {
    matches!(host, HF_CAS_HOST_US | HF_CAS_HOST_EU)
}

fn is_allowed_transfer_host(host: &str) -> bool {
    matches!(host, HF_TRANSFER_HOST_US | HF_TRANSFER_HOST_EU)
}

fn is_allowed_cdn_host(host: &str) -> bool {
    matches!(host, HF_CDN_HOST_AWS_US | HF_CDN_HOST_GCP_US)
}

fn parse_32_lower_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[index * 2])?;
        let lo = hex_nibble(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceId, WeightPageId};

    fn fixture() -> (SourceDescriptor, SourceReadRequest) {
        let source = SourceDescriptor {
            origin: SourceOrigin::HuggingFaceXet {
                repo_id: "org/model".into(),
                commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                file_path: "model-00001-of-00004.safetensors".into(),
            },
            object_len: 64 * 1024 * 1024,
            whole_object_sha256: None,
        };
        let page = WeightPageDescriptor {
            page_id: WeightPageId([3u8; 32]),
            plaintext_len: 128 * 1024,
        };
        let request = SourceReadRequest {
            source_id: source.source_id().unwrap(),
            source_offset: 4 * 1024 * 1024,
            len: page.plaintext_len,
            expected_page: page,
        };
        (source, request)
    }

    #[test]
    fn planner_is_immutable_commit_and_redirect_rejecting() {
        let (source, request) = fixture();
        let planner =
            HfXetRequestPlanner::new(&source, request, HfXetAdapterPolicy::default()).unwrap();
        let resolve = planner.resolve_request();
        assert_eq!(resolve.host, "huggingface.co");
        assert!(resolve.path_and_query.contains(
            "/org/model/resolve/0123456789abcdef0123456789abcdef01234567/"
        ));
        assert_eq!(resolve.redirect_policy, HfRedirectPolicy::Reject);
    }

    #[test]
    fn source_id_mismatch_fails_closed() {
        let (source, mut request) = fixture();
        request.source_id = SourceId([9u8; 32]);
        assert!(matches!(
            HfXetRequestPlanner::new(&source, request, HfXetAdapterPolicy::default()),
            Err(ModelStoreError::InvalidHfXetSource)
        ));
    }

    #[test]
    fn xet_identity_and_cas_grant_are_strict() {
        let (source, request) = fixture();
        let planner =
            HfXetRequestPlanner::new(&source, request, HfXetAdapterPolicy::default()).unwrap();
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let file_id = planner.accept_resolve_response(302, Some(hash)).unwrap();
        assert_eq!(file_id.to_lower_hex(), hash);

        let grant = HfXetReadGrant::from_token_fields(
            "xet_read_secret".into(),
            10_000,
            "https://cas-server.xethub.hf.co",
            100,
        )
        .unwrap();
        let reconstruction = planner
            .reconstruction_v2_request(file_id, &grant, 100)
            .unwrap();
        assert_eq!(
            reconstruction.range_header.as_deref(),
            Some("bytes=4194304-4325375")
        );

        assert!(HfXetReadGrant::from_token_fields(
            "secret".into(),
            10_000,
            "https://evil.example.com",
            100,
        )
        .is_err());
    }

    #[test]
    fn hf_cdn_xorb_and_bridge_signed_urls_are_exactly_scoped() {
        let hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let direct = format!(
            "https://us.aws.cdn.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D0-65535&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        validate_signed_xorb_url(&direct, hash).unwrap();
        let bridge = format!(
            "https://us.aws.cdn.hf.co/xet-bridge-us/697f459103755de5f6541db0/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        validate_signed_xorb_url(&bridge, hash).unwrap();
        let wrong = direct.replace(hash, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        assert!(validate_signed_xorb_url(&wrong, hash).is_err());
        let evil = direct.replace("us.aws.cdn.hf.co", "evil.example.com");
        assert!(validate_signed_xorb_url(&evil, hash).is_err());
        let cdn_without_signed_range = format!(
            "https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        validate_signed_xorb_url(&cdn_without_signed_range, hash).unwrap();

        let cdn_missing_signature = format!(
            "https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9&Policy=p&Key-Pair-Id=k"
        );
        assert!(validate_signed_xorb_url(&cdn_missing_signature, hash).is_err());

        let transfer_without_signed_range = format!(
            "https://transfer.xethub.hf.co/xorbs/default/{hash}?Expires=9&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        assert!(validate_signed_xorb_url(&transfer_without_signed_range, hash).is_err());
    }

    #[test]
    fn signed_transfer_url_and_budgets_fail_closed() {
        let (source, request) = fixture();
        let planner =
            HfXetRequestPlanner::new(&source, request, HfXetAdapterPolicy::default()).unwrap();
        let hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let signed_url = format!(
            "https://transfer.xethub.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D0-65535&Expires=9999999999&Policy=x&Signature=y&Key-Pair-Id=z"
        );
        let fetch = XetFetchMetadata::new(
            hash.into(),
            signed_url,
            vec![XetRangeMetadata {
                chunks: XetChunkRange { start: 0, end: 2 },
                bytes: XetByteRange { start: 0, end: 65_535 },
            }],
        );
        let plan = planner
            .validate_v2_reconstruction(
                0,
                &[XetTermMetadata {
                    xorb_hash: hash.into(),
                    chunks: XetChunkRange { start: 0, end: 2 },
                    unpacked_length: 128 * 1024,
                }],
                vec![fetch],
            )
            .unwrap();
        assert_eq!(plan.fetches().len(), 1);
        assert_eq!(plan.fetches()[0].range_header(), "bytes=0-65535");

        let bad = XetFetchMetadata::new(
            hash.into(),
            format!("https://169.254.169.254/xorbs/default/{hash}?X-Xet-Signed-Range=x"),
            vec![XetRangeMetadata {
                chunks: XetChunkRange { start: 0, end: 2 },
                bytes: XetByteRange { start: 0, end: 65_535 },
            }],
        );
        assert!(planner
            .validate_v2_reconstruction(
                0,
                &[XetTermMetadata {
                    xorb_hash: hash.into(),
                    chunks: XetChunkRange { start: 0, end: 2 },
                    unpacked_length: 128 * 1024,
                }],
                vec![bad],
            )
            .is_err());
    }
}
