//! M8.5.2.2 bounded Xet token/reconstruction metadata parsing.
//!
//! This module follows the published Xet v2 reconstruction shape:
//! - `terms[].range = { start, end }`
//! - `xorbs` is a map from xorb hash to an array of fetch entries
//! - `ranges[].chunks` is an end-exclusive chunk span
//! - `ranges[].bytes` is an end-inclusive HTTP byte span
//!
//! Transport-neutral: no HTTP execution and no inference access here.

use serde_json::Value;
use zeroize::Zeroizing;

const MAX_JSON: usize = 8 * 1024 * 1024;
const MAX_TOKEN: usize = 64 * 1024;
const MAX_SIGNED_URL: usize = 64 * 1024;
const MAX_TERMS: usize = 16_384;
const MAX_XORBS: usize = 8_192;
const MAX_FETCH_ENTRIES: usize = 16_384;
const MAX_RANGES: usize = 32_768;
const MAX_EXEC_RANGE_HEADER_BYTES: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    InvalidJson,
    InvalidSchema,
    LimitExceeded,
    ForbiddenEndpoint,
    SignedUrlTooLong,
    SignedUrlInvalidScheme,
    SignedUrlForbiddenHost,
    SignedUrlInvalidPath,
    SignedRangeMissing,
    CdnSignatureMissing,
    SingleRangeRequired,
    RangeOverflow,
    RangeHeaderTooLong,
    Expired,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Xet metadata rejected: {self:?}")
    }
}

impl std::error::Error for ParseError {}

/// Never derives Debug: a grant contains a live bearer token.
pub struct ReadGrant {
    token: Zeroizing<String>,
    pub cas_host: String,
    pub expires_unix: u64,
}

impl ReadGrant {
    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    /// Move the live Xet token directly into the transport secret wrapper
    /// without first converting it back into an ordinary String.
    pub fn into_parts(self) -> (Zeroizing<String>, String, u64) {
        (self.token, self.cas_host, self.expires_unix)
    }
}

fn object(value: &Value) -> Result<&serde_json::Map<String, Value>, ParseError> {
    value.as_object().ok_or(ParseError::InvalidSchema)
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, ParseError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ParseError::InvalidSchema)
}

fn uint_field(value: &Value, key: &str) -> Result<u64, ParseError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(ParseError::InvalidSchema)
}

fn parse_json(data: &[u8]) -> Result<Value, ParseError> {
    if data.is_empty() || data.len() > MAX_JSON {
        return Err(ParseError::LimitExceeded);
    }
    serde_json::from_slice(data).map_err(|_| ParseError::InvalidJson)
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn parse_read_grant(data: &[u8], now_unix: u64) -> Result<ReadGrant, ParseError> {
    let value = parse_json(data)?;
    object(&value)?;

    let token = string_field(&value, "accessToken")?;
    if token.is_empty()
        || token.len() > MAX_TOKEN
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ParseError::InvalidSchema);
    }

    let expires_unix = uint_field(&value, "exp")?;
    if expires_unix <= now_unix.saturating_add(30) {
        return Err(ParseError::Expired);
    }

    let cas_url = string_field(&value, "casUrl")?;
    let cas_host = cas_url
        .strip_prefix("https://")
        .ok_or(ParseError::ForbiddenEndpoint)?
        .strip_suffix('/')
        .unwrap_or_else(|| cas_url.strip_prefix("https://").unwrap_or_default());

    if cas_host.contains('/')
        || cas_host.contains('?')
        || cas_host.contains('#')
        || cas_host.contains('@')
        || cas_host.contains(':')
        || !matches!(
            cas_host,
            "cas-server.xethub.hf.co" | "cas-server.xethub-eu.hf.co"
        )
    {
        return Err(ParseError::ForbiddenEndpoint);
    }

    Ok(ReadGrant {
        token: Zeroizing::new(token.to_owned()),
        cas_host: cas_host.to_owned(),
        expires_unix,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSpan {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSpan {
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReconstructionTerm {
    pub hash: String,
    pub chunks: ChunkSpan,
    pub unpacked_length: u64,
}

/// Signed URLs are authorization material and must not be logged.
pub struct ReconstructionFetch {
    pub hash: String,
    pub signed_url: Zeroizing<String>,
    pub ranges: Vec<(ChunkSpan, ByteSpan)>,
}

/// A validated signed xorb request for exactly one physical byte range.
///
/// The query string contains short-lived authorization material, so this type
/// intentionally does not implement `Debug`. The host and range are safe to
/// log; `path_and_query` is transport-only.
pub struct SignedSingleRangeRequest {
    pub host: String,
    path_and_query: Zeroizing<String>,
    pub range_header: String,
    pub expected_len: u64,
    pub xorb_hash: String,
}

/// A validated signed xorb request containing every physical range authorized
/// by one reconstruction fetch entry. This is a planning object only in
/// M8.5.8: multi-range HTTP execution remains disabled until a strict
/// multipart/byteranges parser is wired into the transport.
///
/// Signed query material intentionally remains non-Debug and zeroized on drop.
pub struct SignedRangeBatchRequest {
    pub host: String,
    path_and_query: Zeroizing<String>,
    pub range_header: String,
    pub authorized_payload_bytes: u64,
    pub xorb_hash: String,
    pub ranges: Vec<(ChunkSpan, ByteSpan)>,
}

impl SignedRangeBatchRequest {
    pub fn path_and_query(&self) -> &str {
        self.path_and_query.as_str()
    }
}

impl SignedSingleRangeRequest {
    /// Transport-only access. Never log or persist the returned string.
    pub fn path_and_query(&self) -> &str {
        self.path_and_query.as_str()
    }
}

impl ReconstructionFetch {
    /// Build the exact HTTP Range header authorized by this reconstruction
    /// fetch entry while keeping its signed URL opaque. The byte count is the
    /// sum of authorized xorb payload bytes only; multipart framing overhead is
    /// deliberately not guessed here.
    pub fn range_batch_request(&self) -> Result<SignedRangeBatchRequest, ParseError> {
        if self.ranges.is_empty() {
            return Err(ParseError::InvalidSchema);
        }
        validate_signed_xorb_url(self.signed_url.as_str(), &self.hash)?;
        let rest = self
            .signed_url
            .strip_prefix("https://")
            .ok_or(ParseError::SignedUrlInvalidScheme)?;
        let slash = rest.find('/').ok_or(ParseError::SignedUrlInvalidPath)?;
        let host = &rest[..slash];
        let path_and_query = &rest[slash..];

        let mut range_header = String::from("bytes=");
        let mut authorized_payload_bytes = 0u64;
        for (index, (_, bytes)) in self.ranges.iter().enumerate() {
            if index != 0 {
                range_header.push(',');
            }
            use std::fmt::Write as _;
            write!(&mut range_header, "{}-{}", bytes.start, bytes.end)
                .map_err(|_| ParseError::RangeOverflow)?;
            if range_header.len() > MAX_EXEC_RANGE_HEADER_BYTES {
                return Err(ParseError::RangeHeaderTooLong);
            }
            let len = bytes
                .end
                .checked_sub(bytes.start)
                .and_then(|value| value.checked_add(1))
                .ok_or(ParseError::RangeOverflow)?;
            authorized_payload_bytes = authorized_payload_bytes
                .checked_add(len)
                .ok_or(ParseError::RangeOverflow)?;
        }
        if authorized_payload_bytes == 0 {
            return Err(ParseError::RangeOverflow);
        }

        Ok(SignedRangeBatchRequest {
            host: host.to_owned(),
            path_and_query: Zeroizing::new(path_and_query.to_owned()),
            range_header,
            authorized_payload_bytes,
            xorb_hash: self.hash.clone(),
            ranges: self.ranges.clone(),
        })
    }

    /// Convert a validated reconstruction fetch into an executable request
    /// only when it contains exactly one physical range. Multi-range fetches
    /// remain fail-closed until the multipart/byteranges parser lands.
    pub fn single_range_request(&self) -> Result<SignedSingleRangeRequest, ParseError> {
        if self.ranges.len() != 1 {
            return Err(ParseError::SingleRangeRequired);
        }
        validate_signed_xorb_url(self.signed_url.as_str(), &self.hash)?;
        let rest = self
            .signed_url
            .strip_prefix("https://")
            .ok_or(ParseError::SignedUrlInvalidScheme)?;
        let slash = rest.find('/').ok_or(ParseError::SignedUrlInvalidPath)?;
        let host = &rest[..slash];
        let path_and_query = &rest[slash..];
        let bytes = self.ranges[0].1;
        let expected_len = bytes
            .end
            .checked_sub(bytes.start)
            .and_then(|value| value.checked_add(1))
            .ok_or(ParseError::RangeOverflow)?;
        if expected_len == 0 {
            return Err(ParseError::RangeOverflow);
        }
        Ok(SignedSingleRangeRequest {
            host: host.to_owned(),
            path_and_query: Zeroizing::new(path_and_query.to_owned()),
            range_header: format!("bytes={}-{}", bytes.start, bytes.end),
            expected_len,
            xorb_hash: self.hash.clone(),
        })
    }
}

pub struct Reconstruction {
    pub offset_into_first_range: u64,
    pub terms: Vec<ReconstructionTerm>,
    pub fetches: Vec<ReconstructionFetch>,
}

fn chunk_span(value: &Value) -> Result<ChunkSpan, ParseError> {
    object(value)?;
    let start = uint_field(value, "start")?;
    let end = uint_field(value, "end")?;
    if start >= end {
        return Err(ParseError::InvalidSchema);
    }
    Ok(ChunkSpan { start, end })
}

fn byte_span(value: &Value) -> Result<ByteSpan, ParseError> {
    object(value)?;
    let start = uint_field(value, "start")?;
    let end = uint_field(value, "end")?;
    if start > end {
        return Err(ParseError::InvalidSchema);
    }
    Ok(ByteSpan { start, end })
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignedHostKind {
    XetTransfer,
    HfCdnBridge,
}

fn query_has_nonempty(query: &str, key: &str) -> bool {
    query.split('&').any(|pair| {
        pair.split_once('=')
            .is_some_and(|(candidate, value)| candidate == key && !value.is_empty())
    })
}

fn validate_hf_cdn_bridge_path(path: &str, expected_hash: &str) -> Result<(), ParseError> {
    let rest = path
        .strip_prefix("/xet-bridge-us/")
        .ok_or(ParseError::SignedUrlInvalidPath)?;
    let mut parts = rest.split('/');
    let opaque_id = parts.next().ok_or(ParseError::SignedUrlInvalidPath)?;
    let hash = parts.next().ok_or(ParseError::SignedUrlInvalidPath)?;
    if parts.next().is_some()
        || opaque_id.is_empty()
        || opaque_id.len() > 128
        || !opaque_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || hash != expected_hash
    {
        return Err(ParseError::SignedUrlInvalidPath);
    }
    Ok(())
}

fn validate_signed_xorb_url(url: &str, expected_hash: &str) -> Result<(), ParseError> {
    if url.is_empty() {
        return Err(ParseError::SignedUrlInvalidScheme);
    }
    if url.len() > MAX_SIGNED_URL {
        return Err(ParseError::SignedUrlTooLong);
    }

    // Parse the security-sensitive URL components explicitly instead of
    // searching the whole signed URL for characters such as '@'. Query values
    // are opaque authorization material and may contain characters that are
    // harmless there but dangerous in authority/userinfo.
    let rest = url
        .strip_prefix("https://")
        .ok_or(ParseError::SignedUrlInvalidScheme)?;
    let slash = rest.find('/').ok_or(ParseError::SignedUrlInvalidPath)?;
    let authority = &rest[..slash];
    if authority.is_empty() || authority.contains('@') || authority.contains(':') {
        return Err(ParseError::SignedUrlForbiddenHost);
    }

    let host_kind = match authority {
        "transfer.xethub.hf.co" | "transfer.xethub-eu.hf.co" => SignedHostKind::XetTransfer,
        "us.aws.cdn.hf.co" | "us.gcp.cdn.hf.co" => SignedHostKind::HfCdnBridge,
        _ => return Err(ParseError::SignedUrlForbiddenHost),
    };

    let path_and_query = &rest[slash..];
    if path_and_query.contains('#') {
        return Err(ParseError::SignedUrlInvalidPath);
    }
    let (path, query) = path_and_query
        .split_once('?')
        .ok_or(ParseError::SignedUrlInvalidPath)?;

    match host_kind {
        SignedHostKind::XetTransfer => {
            let plural = format!("/xorbs/default/{expected_hash}");
            let singular = format!("/xorb/default/{expected_hash}");
            if path != plural && path != singular {
                return Err(ParseError::SignedUrlInvalidPath);
            }
            // Xet transfer URLs authorize an explicit set of byte ranges.
            if !query_has_nonempty(query, "X-Xet-Signed-Range") {
                return Err(ParseError::SignedRangeMissing);
            }
        }
        SignedHostKind::HfCdnBridge => {
            // Current HF/Xet CDN routing has two observed/documented path
            // families. Both remain exact and hash-bound:
            //   /xorbs/default/<expected xorb hash>
            //   /xorb/default/<expected xorb hash>
            //   /xet-bridge-us/<opaque repository/storage id>/<expected hash>
            //
            // Do NOT widen this to arbitrary *.hf.co paths.
            let plural = format!("/xorbs/default/{expected_hash}");
            let singular = format!("/xorb/default/{expected_hash}");
            let is_direct_xorb = path == plural || path == singular;
            if !is_direct_xorb {
                validate_hf_cdn_bridge_path(path, expected_hash)?;
            }

            // Current HF CDN direct-xorb URLs use the CloudFront signature
            // envelope while the exact byte ranges remain explicit in the
            // authenticated reconstruction metadata and are sent in the HTTP
            // Range header. Do not require X-Xet-Signed-Range for this CDN
            // profile: live hf_xet/xet-core traffic can omit it.
            //
            // This is intentionally different from transfer.xethub.* above,
            // where X-Xet-Signed-Range remains mandatory.
            for key in ["Expires", "Policy", "Signature", "Key-Pair-Id"] {
                if !query_has_nonempty(query, key) {
                    return Err(ParseError::CdnSignatureMissing);
                }
            }
        }
    }
    Ok(())
}

/// Strict parser for the published Xet v2 QueryReconstructionResponse shape.
///
/// This validates metadata only. It does not execute signed URLs, parse
/// multipart bodies, decode xorbs, decompress chunks, or publish a WeightPage.
pub fn parse_v2_reconstruction(
    data: &[u8],
    needed_len: u64,
) -> Result<Reconstruction, ParseError> {
    if needed_len == 0 {
        return Err(ParseError::InvalidSchema);
    }

    let value = parse_json(data)?;
    object(&value)?;
    let offset_into_first_range = uint_field(&value, "offset_into_first_range")?;

    let terms = value
        .get("terms")
        .and_then(Value::as_array)
        .ok_or(ParseError::InvalidSchema)?;
    let xorbs = value
        .get("xorbs")
        .and_then(Value::as_object)
        .ok_or(ParseError::InvalidSchema)?;

    if terms.is_empty()
        || terms.len() > MAX_TERMS
        || xorbs.is_empty()
        || xorbs.len() > MAX_XORBS
    {
        return Err(ParseError::LimitExceeded);
    }

    let mut parsed_terms = Vec::with_capacity(terms.len());
    let mut total_unpacked = 0u64;
    for term in terms {
        object(term)?;
        let hash = string_field(term, "hash")?;
        if !is_lower_hex_64(hash) {
            return Err(ParseError::InvalidSchema);
        }
        let chunks = chunk_span(term.get("range").ok_or(ParseError::InvalidSchema)?)?;
        let unpacked_length = uint_field(term, "unpacked_length")?;
        if unpacked_length == 0 {
            return Err(ParseError::InvalidSchema);
        }
        total_unpacked = total_unpacked
            .checked_add(unpacked_length)
            .ok_or(ParseError::LimitExceeded)?;
        parsed_terms.push(ReconstructionTerm {
            hash: hash.to_owned(),
            chunks,
            unpacked_length,
        });
    }

    if offset_into_first_range
        >= parsed_terms
            .first()
            .ok_or(ParseError::InvalidSchema)?
            .unpacked_length
        || offset_into_first_range
            .checked_add(needed_len)
            .ok_or(ParseError::LimitExceeded)?
            > total_unpacked
    {
        return Err(ParseError::InvalidSchema);
    }

    let mut parsed_fetches = Vec::new();
    let mut fetch_count = 0usize;
    let mut range_count = 0usize;

    for (hash, fetch_entries_value) in xorbs {
        if !is_lower_hex_64(hash) {
            return Err(ParseError::InvalidSchema);
        }
        let fetch_entries = fetch_entries_value
            .as_array()
            .ok_or(ParseError::InvalidSchema)?;
        if fetch_entries.is_empty() {
            return Err(ParseError::InvalidSchema);
        }

        fetch_count = fetch_count
            .checked_add(fetch_entries.len())
            .ok_or(ParseError::LimitExceeded)?;
        if fetch_count > MAX_FETCH_ENTRIES {
            return Err(ParseError::LimitExceeded);
        }

        for fetch in fetch_entries {
            object(fetch)?;
            let signed_url = string_field(fetch, "url")?;
            validate_signed_xorb_url(signed_url, hash)?;

            let ranges = fetch
                .get("ranges")
                .and_then(Value::as_array)
                .ok_or(ParseError::InvalidSchema)?;
            if ranges.is_empty() {
                return Err(ParseError::InvalidSchema);
            }

            range_count = range_count
                .checked_add(ranges.len())
                .ok_or(ParseError::LimitExceeded)?;
            if range_count > MAX_RANGES {
                return Err(ParseError::LimitExceeded);
            }

            let mut parsed_ranges = Vec::with_capacity(ranges.len());
            let mut previous_chunk_end: Option<u64> = None;
            let mut previous_byte_end: Option<u64> = None;

            for descriptor in ranges {
                object(descriptor)?;
                let chunks = chunk_span(
                    descriptor
                        .get("chunks")
                        .ok_or(ParseError::InvalidSchema)?,
                )?;
                let bytes = byte_span(
                    descriptor
                        .get("bytes")
                        .ok_or(ParseError::InvalidSchema)?,
                )?;

                if previous_chunk_end.is_some_and(|end| chunks.start < end)
                    || previous_byte_end.is_some_and(|end| bytes.start <= end)
                {
                    return Err(ParseError::InvalidSchema);
                }
                previous_chunk_end = Some(chunks.end);
                previous_byte_end = Some(bytes.end);
                parsed_ranges.push((chunks, bytes));
            }

            parsed_fetches.push(ReconstructionFetch {
                hash: hash.to_owned(),
                signed_url: Zeroizing::new(signed_url.to_owned()),
                ranges: parsed_ranges,
            });
        }
    }

    // Every term must be covered by one or more authorized fetch ranges for
    // the same xorb. Overlap between term use is valid (deduplication); gaps
    // in available chunk coverage are not.
    for term in &parsed_terms {
        let mut spans: Vec<ChunkSpan> = parsed_fetches
            .iter()
            .filter(|fetch| fetch.hash == term.hash)
            .flat_map(|fetch| fetch.ranges.iter().map(|(chunks, _)| *chunks))
            .collect();
        spans.sort_by_key(|span| span.start);

        let mut cursor = term.chunks.start;
        for span in spans {
            if span.end <= cursor {
                continue;
            }
            if span.start > cursor {
                break;
            }
            cursor = cursor.max(span.end);
            if cursor >= term.chunks.end {
                break;
            }
        }
        if cursor < term.chunks.end {
            return Err(ParseError::InvalidSchema);
        }
    }

    Ok(Reconstruction {
        offset_into_first_range,
        terms: parsed_terms,
        fetches: parsed_fetches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published_shape_fixture() -> String {
        let hash = "a".repeat(64);
        let url = format!(
            "https://transfer.xethub.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D0-131071&Expires=9999999999&Policy=x&Signature=y&Key-Pair-Id=z"
        );
        format!(
            r#"{{
              "offset_into_first_range": 0,
              "terms": [{{
                "hash": "{hash}",
                "unpacked_length": 263873,
                "range": {{"start": 0, "end": 4}}
              }}],
              "xorbs": {{
                "{hash}": [{{
                  "url": "{url}",
                  "ranges": [{{
                    "chunks": {{"start": 0, "end": 4}},
                    "bytes": {{"start": 0, "end": 131071}}
                  }}]
                }}]
              }}
            }}"#
        )
    }

    #[test]
    fn grant_rejects_credential_leak_hosts() {
        let good = br#"{"accessToken":"secret","exp":999999,"casUrl":"https://cas-server.xethub.hf.co"}"#;
        assert_eq!(parse_read_grant(good, 100).unwrap().token(), "secret");
        let bad = br#"{"accessToken":"secret","exp":999999,"casUrl":"https://evil.example"}"#;
        assert!(matches!(
            parse_read_grant(bad, 100),
            Err(ParseError::ForbiddenEndpoint)
        ));
    }

    #[test]
    fn published_v2_shape_is_accepted() {
        let parsed = parse_v2_reconstruction(published_shape_fixture().as_bytes(), 128 * 1024)
            .expect("published v2-shaped fixture should parse");
        assert_eq!(parsed.terms.len(), 1);
        assert_eq!(parsed.fetches.len(), 1);
        assert_eq!(parsed.terms[0].chunks, ChunkSpan { start: 0, end: 4 });
        assert_eq!(
            parsed.fetches[0].ranges[0].1,
            ByteSpan {
                start: 0,
                end: 131_071
            }
        );
    }

    #[test]
    fn live_plural_xorbs_path_is_accepted_and_wrong_path_is_rejected() {
        let good = published_shape_fixture();
        assert!(good.contains("/xorbs/default/"));
        assert!(parse_v2_reconstruction(good.as_bytes(), 128 * 1024).is_ok());

        let wrong = good.replace("/xorbs/default/", "/objects/default/");
        assert!(matches!(
            parse_v2_reconstruction(wrong.as_bytes(), 128 * 1024),
            Err(ParseError::SignedUrlInvalidPath)
        ));
    }

    #[test]
    fn signed_query_is_opaque_but_authority_is_not() {
        let body = published_shape_fixture().replace("&Policy=x", "&Policy=user@example~opaque");
        assert!(parse_v2_reconstruction(body.as_bytes(), 128 * 1024).is_ok());

        let malicious_authority = body.replace("https://transfer.xethub.hf.co/", "https://user@transfer.xethub.hf.co/");
        assert!(matches!(
            parse_v2_reconstruction(malicious_authority.as_bytes(), 128 * 1024),
            Err(ParseError::SignedUrlForbiddenHost)
        ));
    }

    #[test]
    fn current_hf_cdn_xorb_and_bridge_paths_are_exactly_allowlisted() {
        let hash = "c".repeat(64);
        for host in ["us.aws.cdn.hf.co", "us.gcp.cdn.hf.co"] {
            let direct = format!(
                "https://{host}/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D0-65535&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k"
            );
            validate_signed_xorb_url(&direct, &hash).unwrap();

            let bridge = format!(
                "https://{host}/xet-bridge-us/697f459103755de5f6541db0/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k"
            );
            validate_signed_xorb_url(&bridge, &hash).unwrap();
        }

        let wrong_host = format!(
            "https://eu.aws.cdn.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes%3D0-1&Expires=9&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        assert_eq!(
            validate_signed_xorb_url(&wrong_host, &hash),
            Err(ParseError::SignedUrlForbiddenHost)
        );

        let wrong_hash = "d".repeat(64);
        let wrong_path = format!(
            "https://us.aws.cdn.hf.co/xorbs/default/{wrong_hash}?X-Xet-Signed-Range=bytes%3D0-1&Expires=9&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        assert_eq!(
            validate_signed_xorb_url(&wrong_path, &hash),
            Err(ParseError::SignedUrlInvalidPath)
        );

        // Current live HF CDN direct-xorb URLs may omit
        // X-Xet-Signed-Range. The CloudFront signature envelope plus the
        // reconstruction's exact `ranges[].bytes` remains mandatory.
        let cdn_without_signed_range = format!(
            "https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        validate_signed_xorb_url(&cdn_without_signed_range, &hash).unwrap();

        let cdn_missing_signature = format!(
            "https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9&Policy=p&Key-Pair-Id=k"
        );
        assert_eq!(
            validate_signed_xorb_url(&cdn_missing_signature, &hash),
            Err(ParseError::CdnSignatureMissing)
        );

        let transfer_without_signed_range = format!(
            "https://transfer.xethub.hf.co/xorbs/default/{hash}?Expires=9&Policy=p&Signature=s&Key-Pair-Id=k"
        );
        assert_eq!(
            validate_signed_xorb_url(&transfer_without_signed_range, &hash),
            Err(ParseError::SignedRangeMissing)
        );
    }

    #[test]
    fn single_range_execution_plan_is_exact_and_secret_bearing() {
        let parsed = parse_v2_reconstruction(published_shape_fixture().as_bytes(), 128 * 1024)
            .expect("published fixture should parse");
        let request = parsed.fetches[0]
            .single_range_request()
            .expect("single range should produce a request");
        assert_eq!(request.host, "transfer.xethub.hf.co");
        assert_eq!(request.range_header, "bytes=0-131071");
        assert_eq!(request.expected_len, 131_072);
        assert!(request.path_and_query().starts_with("/xorbs/default/"));

        let mut multi = parse_v2_reconstruction(published_shape_fixture().as_bytes(), 128 * 1024)
            .expect("published fixture should parse");
        multi.fetches[0].ranges.push((
            ChunkSpan { start: 4, end: 5 },
            ByteSpan { start: 131_072, end: 131_999 },
        ));
        assert!(matches!(
            multi.fetches[0].single_range_request(),
            Err(ParseError::SingleRangeRequired)
        ));
    }

    #[test]
    fn range_batch_plan_preserves_all_authorized_ranges() {
        let mut parsed = parse_v2_reconstruction(published_shape_fixture().as_bytes(), 128 * 1024)
            .expect("published fixture should parse");
        parsed.fetches[0].ranges.push((
            ChunkSpan { start: 4, end: 5 },
            ByteSpan { start: 200_000, end: 200_999 },
        ));
        let hash = parsed.fetches[0].hash.clone();
        parsed.fetches[0].signed_url = Zeroizing::new(format!(
            "https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k"
        ));
        let request = parsed.fetches[0]
            .range_batch_request()
            .expect("multi-range planning should preserve all ranges");
        assert_eq!(request.host, "us.aws.cdn.hf.co");
        assert_eq!(request.range_header, "bytes=0-131071,200000-200999");
        assert_eq!(request.authorized_payload_bytes, 132_072);
        assert_eq!(request.ranges.len(), 2);
        assert!(request.path_and_query().starts_with("/xorbs/default/"));
    }

    #[test]
    fn legacy_wrong_fixture_shape_is_rejected() {
        let hash = "a".repeat(64);
        let wrong = format!(
            r#"{{"offset_into_first_range":0,"terms":[{{"hash":"{hash}","start":0,"end":2,"unpacked_length":100}}],"xorbs":[{{"hash":"{hash}","url":"https://transfer.xethub.hf.co/xorbs/default/{hash}?X-Xet-Signed-Range=bytes","ranges":[{{"start":0,"end":2,"range":{{"start":0,"end":20}}}}]}}]}}"#
        );
        assert!(parse_v2_reconstruction(wrong.as_bytes(), 50).is_err());
    }

    #[test]
    fn reconstruction_rejects_ssrf_and_missing_coverage() {
        let body = published_shape_fixture();
        let malicious = body.replace("transfer.xethub.hf.co", "169.254.169.254");
        assert!(matches!(
            parse_v2_reconstruction(malicious.as_bytes(), 50),
            Err(ParseError::SignedUrlForbiddenHost)
        ));

        let gap = body.replace(
            "\"chunks\": {\"start\": 0, \"end\": 4}",
            "\"chunks\": {\"start\": 1, \"end\": 4}",
        );
        assert!(parse_v2_reconstruction(gap.as_bytes(), 50).is_err());
    }
}
