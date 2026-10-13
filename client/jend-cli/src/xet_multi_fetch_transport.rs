//! M8.5.10: atomically fetch one signed Xet physical multi-range entry.
//!
//! This is the *untrusted* bytes boundary: HTTPS 206 alone is not page trust.
//! The caller provides a typed request produced from strict Xet reconstruction
//! metadata, not an arbitrary URL or an AI/runtime string. No Vault secrets,
//! model-store network dependency, or WeightVM publication exist here.

use crate::source_worker_transport::{
    execute_pinned_get, ExpectedResponse, PinnedGetRequest, TransportError, TransportLimits,
};
use crate::xet_metadata::{validate_signed_xorb_url, ByteSpan, ChunkSpan, SignedRangeBatchRequest};
use crate::xet_multipart::{
    parse_multipart_ranges, MultipartError, MultipartLimits, HARD_MAX_FRAMING, HARD_MAX_PARTS,
    HARD_MAX_PAYLOAD,
};
use reqwest::StatusCode;
use std::fmt::Write as _;
use zeroize::Zeroizing;

/// Raw physical xorb data. Never pass this into WeightVM; it still requires
/// bounded xorb decoding, logical assembly and independent signed page hash.
pub struct UntrustedXorbPhysicalRange {
    pub xorb_hash: String,
    pub chunks: ChunkSpan,
    pub physical_bytes: ByteSpan,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum MultiFetchError {
    InvalidAuthorization,
    InvalidBudget,
    UnexpectedStatus,
    Transport(TransportError),
    Multipart(MultipartError),
}

impl std::fmt::Display for MultiFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAuthorization => f.write_str("signed Xet multi-range authorization rejected"),
            Self::InvalidBudget => f.write_str("signed Xet multi-range budget rejected"),
            Self::UnexpectedStatus => f.write_str("signed Xet multi-range requires HTTP 206"),
            Self::Transport(e) => write!(f, "bounded source transport rejected: {e}"),
            Self::Multipart(e) => write!(f, "strict multipart validation rejected: {e}"),
        }
    }
}

impl std::error::Error for MultiFetchError {}

impl From<TransportError> for MultiFetchError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<MultipartError> for MultiFetchError {
    fn from(value: MultipartError) -> Self {
        Self::Multipart(value)
    }
}

/// Revalidate public fields before network I/O; a signed URL, its Xorb hash,
/// exact ranges and their aggregate byte budget must remain bound together.
fn validated_authorization(
    signed: &SignedRangeBatchRequest,
    limits: MultipartLimits,
) -> Result<(Vec<ByteSpan>, u64), MultiFetchError> {
    if limits.max_payload == 0 || limits.max_payload > HARD_MAX_PAYLOAD
        || limits.max_framing == 0 || limits.max_framing > HARD_MAX_FRAMING
    {
        return Err(MultiFetchError::InvalidBudget);
    }
    if !(2..=HARD_MAX_PARTS).contains(&signed.ranges.len()) {
        return Err(MultiFetchError::InvalidAuthorization);
    }

    // Revalidate authority/hash/path after potentially mutable request fields.
    // Do not format this URL into errors or print it in logs.
    let signed_url = Zeroizing::new(format!(
        "https://{}{}", signed.host, signed.path_and_query()
    ));
    validate_signed_xorb_url(signed_url.as_str(), &signed.xorb_hash)
        .map_err(|_| MultiFetchError::InvalidAuthorization)?;

    let mut header = String::from("bytes=");
    let mut authorized_bytes = 0u64;
    let mut physical_spans = Vec::with_capacity(signed.ranges.len());
    for (index, (chunks, bytes)) in signed.ranges.iter().enumerate() {
        if chunks.start >= chunks.end || bytes.start > bytes.end {
            return Err(MultiFetchError::InvalidAuthorization);
        }
        for previous in &physical_spans {
            let previous: &ByteSpan = previous;
            if bytes.start <= previous.end && previous.start <= bytes.end {
                return Err(MultiFetchError::InvalidAuthorization);
            }
        }
        if index != 0 {
            header.push(',');
        }
        write!(&mut header, "{}-{}", bytes.start, bytes.end)
            .map_err(|_| MultiFetchError::InvalidAuthorization)?;
        if header.len() > 8192 {
            return Err(MultiFetchError::InvalidAuthorization);
        }
        let length = bytes.end.checked_sub(bytes.start)
            .and_then(|n| n.checked_add(1))
            .ok_or(MultiFetchError::InvalidAuthorization)?;
        authorized_bytes = authorized_bytes.checked_add(length)
            .ok_or(MultiFetchError::InvalidBudget)?;
        if authorized_bytes > limits.max_payload {
            return Err(MultiFetchError::InvalidBudget);
        }
        physical_spans.push(*bytes);
    }
    if header != signed.range_header || authorized_bytes != signed.authorized_payload_bytes {
        return Err(MultiFetchError::InvalidAuthorization);
    }
    let response_cap = authorized_bytes.checked_add(limits.max_framing)
        .ok_or(MultiFetchError::InvalidBudget)?;
    Ok((physical_spans, response_cap))
}

/// Pure testable trust gate for an already-received response. The real network
/// entrypoint additionally rejects top-level Content-Range, Content-Encoding
/// and duplicate Content-Type before reading bounded HTTP 206 bytes.
pub fn validate_signed_multipart_body(
    signed: &SignedRangeBatchRequest,
    status: StatusCode,
    content_type: &str,
    body: &[u8],
    limits: MultipartLimits,
) -> Result<Vec<UntrustedXorbPhysicalRange>, MultiFetchError> {
    let (authorized, response_cap) = validated_authorization(signed, limits)?;
    if status != StatusCode::PARTIAL_CONTENT {
        return Err(MultiFetchError::UnexpectedStatus);
    }
    if u64::try_from(body.len()).map_err(|_| MultiFetchError::InvalidBudget)? > response_cap {
        return Err(MultiFetchError::InvalidBudget);
    }
    let parsed = parse_multipart_ranges(content_type, body, &authorized, limits)?;
    Ok(parsed.into_iter().zip(&signed.ranges).map(|(part, (chunks, _))| {
        UntrustedXorbPhysicalRange {
            xorb_hash: signed.xorb_hash.clone(),
            chunks: *chunks,
            physical_bytes: part.span,
            bytes: part.bytes,
        }
    }).collect())
}

/// One atomic HTTPS Range request, never split into individually executable
/// ranges. Accept only the first *fully validated* response. This function
/// does not retry, race origins, decompress xorbs or publish WeightPages.
pub async fn execute_signed_xet_multi_range(
    signed: SignedRangeBatchRequest,
    transport_limits: TransportLimits,
    multipart_limits: MultipartLimits,
) -> Result<Vec<UntrustedXorbPhysicalRange>, MultiFetchError> {
    let (_, response_cap) = validated_authorization(&signed, multipart_limits)?;
    if transport_limits.max_response_bytes == 0 {
        return Err(MultiFetchError::InvalidBudget);
    }
    // TransportLimits already enforces connect/request timeout ceilings. A
    // caller may lower the transfer cap, never raise signed payload + framing.
    let max_response_bytes = transport_limits.max_response_bytes.min(response_cap);
    let response = execute_pinned_get(PinnedGetRequest {
        host: signed.host.clone(),
        // Query carries live signed authorization: no Debug/logging.
        path_and_query: signed.path_and_query().to_owned(),
        range_header: Some(signed.range_header.clone()),
        bearer: None,
        expected: ExpectedResponse::Multipart206 { max_body_bytes: response_cap },
        limits: TransportLimits {
            max_response_bytes,
            connect_timeout_ms: transport_limits.connect_timeout_ms,
            request_timeout_ms: transport_limits.request_timeout_ms,
        },
    }).await?;
    let content_type = response.content_type.as_deref()
        .ok_or(MultiFetchError::Multipart(MultipartError::InvalidContentType))?;
    validate_signed_multipart_body(
        &signed, response.status, content_type, &response.body, multipart_limits
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xet_metadata::parse_v2_reconstruction;

    fn planned_request() -> SignedRangeBatchRequest {
        let hash = "a".repeat(64);
        let fixture = format!(
            r#"{{"offset_into_first_range":0,
              "terms":[{{"hash":"{hash}","unpacked_length":6,"range":{{"start":0,"end":2}}}}],
              "xorbs":{{"{hash}":[{{"url":"https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
              "ranges":[
                {{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":2}}}},
                {{"chunks":{{"start":1,"end":2}},"bytes":{{"start":20,"end":22}}}}
              ]}}]}}}}"#
        );
        let parsed = parse_v2_reconstruction(fixture.as_bytes(), 6).unwrap();
        parsed.fetches[0].range_batch_request().unwrap()
    }

    fn good_body() -> Vec<u8> {
        b"--JEND\r\nContent-Range: bytes 0-2/100\r\n\r\nabc\r\n--JEND\r\nContent-Range: bytes 20-22/100\r\n\r\nxyz\r\n--JEND--\r\n".to_vec()
    }

    #[test]
    fn signed_batch_maps_exact_physical_ranges_to_chunk_identity() {
        let request = planned_request();
        let result = validate_signed_multipart_body(
            &request, StatusCode::PARTIAL_CONTENT,
            "multipart/byteranges; boundary=JEND",
            &good_body(),
            MultipartLimits { max_payload: 6, max_framing: 512 }
        ).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].xorb_hash, "a".repeat(64));
        assert_eq!(result[0].chunks, ChunkSpan { start: 0, end: 1 });
        assert_eq!(result[1].chunks, ChunkSpan { start: 1, end: 2 });
        assert_eq!(result[1].physical_bytes, ByteSpan { start: 20, end: 22 });
        assert_eq!(result[0].bytes, b"abc");
        assert_eq!(result[1].bytes, b"xyz");
    }

    #[test]
    fn authorization_mutation_cannot_change_range_or_budget() {
        let mut request = planned_request();
        let limits = MultipartLimits { max_payload: 6, max_framing: 512 };
        request.range_header = "bytes=0-2,30-32".to_string();
        assert!(matches!(validated_authorization(&request, limits), Err(MultiFetchError::InvalidAuthorization)));
        request.range_header = "bytes=0-2,20-22".to_string();
        request.authorized_payload_bytes = 5;
        assert!(matches!(validated_authorization(&request, limits), Err(MultiFetchError::InvalidAuthorization)));
        request.authorized_payload_bytes = 6;
        request.host = "huggingface.co".to_string();
        assert!(matches!(validated_authorization(&request, limits), Err(MultiFetchError::InvalidAuthorization)));
        request.host = "us.aws.cdn.hf.co".to_string();
        request.ranges[1].1.start = 2;
        assert!(matches!(validated_authorization(&request, limits), Err(MultiFetchError::InvalidAuthorization)));
    }

    #[test]
    fn incorrect_status_mime_and_truncation_fail_closed() {
        let signed = planned_request();
        let limits = MultipartLimits { max_payload: 6, max_framing: 512 };
        let response = good_body();
        assert!(matches!(validate_signed_multipart_body(
            &signed, StatusCode::OK, "multipart/byteranges; boundary=JEND",
            &response, limits
        ), Err(MultiFetchError::UnexpectedStatus)));
        assert!(validate_signed_multipart_body(
            &signed, StatusCode::PARTIAL_CONTENT, "application/octet-stream",
            &response, limits
        ).is_err());
        assert!(validate_signed_multipart_body(
            &signed, StatusCode::PARTIAL_CONTENT, "multipart/byteranges; boundary=JEND",
            &response[..response.len() - 10], limits
        ).is_err());
    }

    #[test]
    fn signed_payload_and_mime_framing_are_separately_budgeted() {
        let signed = planned_request();
        assert!(matches!(validated_authorization(
            &signed, MultipartLimits { max_payload: 5, max_framing: 512 }
        ), Err(MultiFetchError::InvalidBudget)));
        assert!(matches!(validated_authorization(
            &signed, MultipartLimits { max_payload: HARD_MAX_PAYLOAD + 1, max_framing: 512 }
        ), Err(MultiFetchError::InvalidBudget)));
        assert!(validate_signed_multipart_body(
            &signed, StatusCode::PARTIAL_CONTENT, "multipart/byteranges; boundary=JEND",
            &good_body(), MultipartLimits { max_payload: 6, max_framing: 2 }
        ).is_err());
    }
}
