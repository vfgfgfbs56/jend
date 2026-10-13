//! M8.5.12 bounded sequential execution of validated signed Xet fetch entries.
//!
//! Unlike an artificial one-entry multipart-only probe, real reconstruction
//! metadata can contain multiple distinct signed URLs, with one or many ranges
//! per authorization. Never merge URL grants. Fail atomically (no partial
//! result publication), no retry, no WeightVM integration.

use crate::source_worker_transport::{
    execute_pinned_get, ExpectedResponse, PinnedGetRequest, TransportError, TransportLimits,
};
use crate::xet_fetch_schedule::XetFetchSchedule;
use crate::xet_metadata::{validate_signed_xorb_url, ByteSpan, SignedRangeBatchRequest};
use crate::xet_multi_fetch_transport::{
    execute_signed_xet_multi_range, MultiFetchError, UntrustedXorbPhysicalRange,
};
use crate::xet_multipart::MultipartLimits;
use reqwest::StatusCode;
use zeroize::Zeroizing;

const HARD_MAX_JOBS: usize = 8;
const HARD_MAX_TOTAL_PHYSICAL_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_FRAMING_PER_JOB: u64 = 128 * 1024;

pub struct CompletedUntrustedFetch {
    pub parts: Vec<UntrustedXorbPhysicalRange>,
    pub single_range_jobs: usize,
    pub multipart_jobs: usize,
    pub physical_bytes: u64,
}

#[derive(Debug)]
pub enum ExecutionError {
    InvalidSchedule,
    InvalidSignedEntry,
    BudgetExceeded,
    UnexpectedResponse,
    Transport(TransportError),
    Multipart(MultiFetchError),
}
impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSchedule => f.write_str("signed Xet fetch schedule is invalid"),
            Self::InvalidSignedEntry => f.write_str("signed Xet fetch entry is invalid"),
            Self::BudgetExceeded => f.write_str("bounded signed Xet fetch budget exceeded"),
            Self::UnexpectedResponse => f.write_str("signed Xet singleton HTTP 206 response rejected"),
            Self::Transport(e) => write!(f, "bounded signed Xet transport rejected: {e}"),
            Self::Multipart(e) => write!(f, "atomic signed multipart transport rejected: {e}"),
        }
    }
}
impl std::error::Error for ExecutionError {}
impl From<TransportError> for ExecutionError {
    fn from(e: TransportError) -> Self { Self::Transport(e) }
}
impl From<MultiFetchError> for ExecutionError {
    fn from(e: MultiFetchError) -> Self { Self::Multipart(e) }
}

#[derive(Clone, Copy)]
pub struct SequentialFetchLimits {
    pub max_total_physical_bytes: u64,
    pub max_jobs: usize,
    pub max_framing_per_job: u64,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
}

impl SequentialFetchLimits {
    fn validate(self) -> Result<Self, ExecutionError> {
        if self.max_total_physical_bytes == 0
            || self.max_total_physical_bytes > HARD_MAX_TOTAL_PHYSICAL_BYTES
            || self.max_jobs == 0 || self.max_jobs > HARD_MAX_JOBS
            || self.max_framing_per_job == 0
            || self.max_framing_per_job > HARD_MAX_FRAMING_PER_JOB
            || self.connect_timeout_ms == 0 || self.connect_timeout_ms > 30_000
            || self.request_timeout_ms < self.connect_timeout_ms
            || self.request_timeout_ms > 120_000
        {
            return Err(ExecutionError::BudgetExceeded);
        }
        Ok(self)
    }
}

/// Check an individual signed singleton before any request. This is required
/// even though reconstruction metadata was previously validated: request
/// fields are public and might have been modified by a later caller.
fn validate_single_authorization(
    signed: &SignedRangeBatchRequest,
    max_bytes: u64,
) -> Result<(ByteSpan, u64), ExecutionError> {
    if signed.ranges.len() != 1 || max_bytes == 0 {
        return Err(ExecutionError::InvalidSignedEntry);
    }
    let joined = Zeroizing::new(format!("https://{}{}", signed.host, signed.path_and_query()));
    validate_signed_xorb_url(joined.as_str(), &signed.xorb_hash)
        .map_err(|_| ExecutionError::InvalidSignedEntry)?;
    let (chunks, span) = signed.ranges[0];
    if chunks.start >= chunks.end || span.start > span.end {
        return Err(ExecutionError::InvalidSignedEntry);
    }
    let length = span.end.checked_sub(span.start)
        .and_then(|v| v.checked_add(1))
        .ok_or(ExecutionError::InvalidSignedEntry)?;
    if length > max_bytes {
        return Err(ExecutionError::BudgetExceeded);
    }
    if signed.range_header != format!("bytes={}-{}", span.start, span.end)
        || signed.authorized_payload_bytes != length
    {
        return Err(ExecutionError::InvalidSignedEntry);
    }
    Ok((span, length))
}

/// Offline-testable signed single-range gate. HTTP transport separately
/// requires exact Content-Range, rejects compression and verifies byte count.
pub fn validate_signed_single_range_body(
    signed: &SignedRangeBatchRequest,
    status: StatusCode,
    content_range: &str,
    body: Vec<u8>,
    max_bytes: u64,
) -> Result<UntrustedXorbPhysicalRange, ExecutionError> {
    let (span, length) = validate_single_authorization(signed, max_bytes)?;
    if status != StatusCode::PARTIAL_CONTENT
        || u64::try_from(body.len()).map_err(|_| ExecutionError::BudgetExceeded)? != length
    {
        return Err(ExecutionError::UnexpectedResponse);
    }
    let (actual, total) = content_range.strip_prefix("bytes ")
        .and_then(|s| s.split_once('/'))
        .ok_or(ExecutionError::UnexpectedResponse)?;
    let (start, end) = actual.split_once('-').ok_or(ExecutionError::UnexpectedResponse)?;
    let (Ok(start), Ok(end), Ok(total)) = (
        start.parse::<u64>(), end.parse::<u64>(), total.parse::<u64>()
    ) else {
        return Err(ExecutionError::UnexpectedResponse);
    };
    if start != span.start || end != span.end || total <= end {
        return Err(ExecutionError::UnexpectedResponse);
    }
    Ok(UntrustedXorbPhysicalRange {
        xorb_hash: signed.xorb_hash.clone(),
        chunks: signed.ranges[0].0,
        physical_bytes: span,
        bytes: body,
    })
}

/// Execute one *already validated* signed singleton. No Hub token forwarded,
/// no redirects, no full-object fallback and no inferred page integrity.
pub async fn execute_signed_xet_single_range(
    signed: SignedRangeBatchRequest,
    limits: SequentialFetchLimits,
) -> Result<UntrustedXorbPhysicalRange, ExecutionError> {
    let limits = limits.validate()?;
    let (_, expected_len) =
        validate_single_authorization(&signed, limits.max_total_physical_bytes)?;
    let response = execute_pinned_get(PinnedGetRequest {
        host: signed.host.clone(),
        path_and_query: signed.path_and_query().to_owned(),
        range_header: Some(signed.range_header.clone()),
        bearer: None,
        expected: ExpectedResponse::SingleRange206 { expected_len },
        limits: TransportLimits {
            max_response_bytes: expected_len,
            connect_timeout_ms: limits.connect_timeout_ms,
            request_timeout_ms: limits.request_timeout_ms,
        },
    }).await?;
    validate_signed_single_range_body(
        &signed,
        response.status,
        response.content_range.as_deref().ok_or(ExecutionError::UnexpectedResponse)?,
        response.body,
        limits.max_total_physical_bytes,
    )
}

/// Preflight the full schedule before any network use. The scheduler builds
/// this type from strict reconstruction metadata; here we reassert its public
/// aggregate fields and prohibit duplicate chunk coverage across signed jobs.
pub fn validate_schedule(
    schedule: &XetFetchSchedule,
    limits: SequentialFetchLimits,
) -> Result<(), ExecutionError> {
    let limits = limits.validate()?;
    if schedule.jobs.is_empty() || schedule.jobs.len() > limits.max_jobs
        || schedule.max_concurrency == 0 || schedule.max_concurrency > 8
    {
        return Err(ExecutionError::InvalidSchedule);
    }
    let mut total = 0u64;
    let mut ranges = 0usize;
    let mut spans = Vec::new();
    for (ordinal, job) in schedule.jobs.iter().enumerate() {
        if job.ordinal != ordinal || job.wave != ordinal / schedule.max_concurrency
            || job.request.ranges.is_empty() || job.request.ranges.len() > 512
        {
            return Err(ExecutionError::InvalidSchedule);
        }
        let signed = &job.request;
        // Do not alter an entry's signed range set. For singleton, verify it
        // directly; for multipart, the typed transport checks every part.
        if signed.ranges.len() == 1 {
            validate_single_authorization(signed, limits.max_total_physical_bytes)?;
        } else {
            let joined = Zeroizing::new(format!("https://{}{}", signed.host, signed.path_and_query()));
            validate_signed_xorb_url(joined.as_str(), &signed.xorb_hash)
                .map_err(|_| ExecutionError::InvalidSignedEntry)?;
            let mut header = String::from("bytes=");
            let mut entry_bytes = 0u64;
            for (index, (chunks, span)) in signed.ranges.iter().enumerate() {
                if chunks.start >= chunks.end || span.start > span.end {
                    return Err(ExecutionError::InvalidSignedEntry);
                }
                if index != 0 { header.push(','); }
                use std::fmt::Write as _;
                write!(&mut header, "{}-{}", span.start, span.end)
                    .map_err(|_| ExecutionError::InvalidSignedEntry)?;
                let len = span.end.checked_sub(span.start)
                    .and_then(|n| n.checked_add(1))
                    .ok_or(ExecutionError::InvalidSignedEntry)?;
                entry_bytes = entry_bytes.checked_add(len)
                    .ok_or(ExecutionError::BudgetExceeded)?;
            }
            if header != signed.range_header
                || signed.authorized_payload_bytes != entry_bytes
                || entry_bytes > limits.max_total_physical_bytes
                || entry_bytes > 16 * 1024 * 1024
            {
                return Err(ExecutionError::InvalidSignedEntry);
            }
        }
        total = total.checked_add(signed.authorized_payload_bytes)
            .ok_or(ExecutionError::BudgetExceeded)?;
        ranges = ranges.checked_add(signed.ranges.len())
            .ok_or(ExecutionError::BudgetExceeded)?;
        if total > limits.max_total_physical_bytes {
            return Err(ExecutionError::BudgetExceeded);
        }
        for (chunks, _) in &signed.ranges {
            spans.push((signed.xorb_hash.as_str(), *chunks));
        }
    }
    if total != schedule.total_authorized_payload_bytes
        || ranges != schedule.total_ranges
        || schedule.wave_count != schedule.jobs.last()
            .map(|job| job.wave + 1).unwrap_or(0)
    {
        return Err(ExecutionError::InvalidSchedule);
    }
    spans.sort_by(|a,b| a.0.cmp(b.0).then(a.1.start.cmp(&b.1.start)));
    for pair in spans.windows(2) {
        if pair[0].0 == pair[1].0 && pair[1].1.start < pair[0].1.end {
            return Err(ExecutionError::InvalidSchedule);
        }
    }
    Ok(())
}

/// Serial dispatch preserves each independent signed grant and avoids
/// concurrent RAM/transfer spikes. If one entry fails, nothing is returned.
/// A result stays untrusted until a distinct release-signed page hash gate.
pub async fn execute_signed_schedule_sequentially(
    schedule: XetFetchSchedule,
    limits: SequentialFetchLimits,
) -> Result<CompletedUntrustedFetch, ExecutionError> {
    validate_schedule(&schedule, limits)?;
    let mut parts = Vec::new();
    let mut singles = 0usize;
    let mut multiples = 0usize;
    let mut total = 0u64;
    for job in schedule.jobs {
        let request = job.request;
        let fetched = if request.ranges.len() == 1 {
            singles += 1;
            vec![execute_signed_xet_single_range(request, limits).await?]
        } else {
            multiples += 1;
            execute_signed_xet_multi_range(
                request,
                TransportLimits {
                    max_response_bytes: limits.max_total_physical_bytes
                        .checked_add(limits.max_framing_per_job)
                        .ok_or(ExecutionError::BudgetExceeded)?,
                    connect_timeout_ms: limits.connect_timeout_ms,
                    request_timeout_ms: limits.request_timeout_ms,
                },
                MultipartLimits {
                    max_payload: limits.max_total_physical_bytes,
                    max_framing: limits.max_framing_per_job,
                },
            ).await?
        };
        for part in fetched {
            total = total.checked_add(
                u64::try_from(part.bytes.len()).map_err(|_| ExecutionError::BudgetExceeded)?
            ).ok_or(ExecutionError::BudgetExceeded)?;
            if total > limits.max_total_physical_bytes {
                return Err(ExecutionError::BudgetExceeded);
            }
            parts.push(part);
        }
    }
    Ok(CompletedUntrustedFetch {
        parts,
        single_range_jobs: singles,
        multipart_jobs: multiples,
        physical_bytes: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xet_fetch_schedule::{build_fetch_schedule, FetchScheduleLimits};
    use crate::xet_metadata::parse_v2_reconstruction;
    fn metadata() -> String {
        let h = "a".repeat(64);
        format!(
            r#"{{"offset_into_first_range":0,
              "terms":[{{"hash":"{h}","unpacked_length":6,"range":{{"start":0,"end":2}}}}],
              "xorbs":{{"{h}":[
                {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{h}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
                  "ranges":[{{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":10}}}}]}},
                {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{h}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
                  "ranges":[{{"chunks":{{"start":1,"end":2}},"bytes":{{"start":20,"end":30}}}}]}}
              ]}}}}"#
        )
    }
    fn schedule() -> XetFetchSchedule {
        let r = parse_v2_reconstruction(metadata().as_bytes(), 6).unwrap();
        build_fetch_schedule(&r, FetchScheduleLimits {
            max_total_payload_bytes: 1024,
            max_request_payload_bytes: 1024,
            max_jobs: 8, max_ranges: 16, max_concurrency: 2
        }).unwrap()
    }
    fn limits() -> SequentialFetchLimits {
        SequentialFetchLimits {
            max_total_physical_bytes: 1024, max_jobs: 8,
            max_framing_per_job: 512,
            connect_timeout_ms: 1000, request_timeout_ms: 2000
        }
    }

    #[test]
    fn validates_two_distinct_signed_single_range_grants() {
        let s = schedule();
        assert!(validate_schedule(&s, limits()).is_ok());
        assert_eq!(s.jobs.len(), 2);
        let part = validate_signed_single_range_body(
            &s.jobs[0].request,
            StatusCode::PARTIAL_CONTENT, "bytes 0-10/100",
            vec![0; 11], 1024
        ).unwrap();
        assert_eq!(part.chunks.start, 0);
        assert_eq!(part.physical_bytes, ByteSpan { start: 0, end: 10 });
    }

    #[test]
    fn wrong_content_range_status_and_payload_rejected() {
        let s = schedule();
        let req = &s.jobs[0].request;
        assert!(validate_signed_single_range_body(req, StatusCode::OK,
            "bytes 0-10/100", vec![0;11], 1024).is_err());
        assert!(validate_signed_single_range_body(req, StatusCode::PARTIAL_CONTENT,
            "bytes 1-11/100", vec![0;11], 1024).is_err());
        assert!(validate_signed_single_range_body(req, StatusCode::PARTIAL_CONTENT,
            "bytes 0-10/100", vec![0;10], 1024).is_err());
        assert!(validate_signed_single_range_body(req, StatusCode::PARTIAL_CONTENT,
            "bytes 0-10/100", vec![0;11], 10).is_err());
    }

    #[test]
    fn modified_public_schedule_fields_cannot_bypass_validation() {
        let mut s = schedule();
        s.total_authorized_payload_bytes = 1;
        assert!(validate_schedule(&s, limits()).is_err());
        let mut s = schedule();
        s.jobs[1].request.ranges[0].0.start = 0;
        assert!(validate_schedule(&s, limits()).is_err());
        let mut s = schedule();
        s.jobs[0].request.range_header = "bytes=0-11".to_string();
        assert!(validate_schedule(&s, limits()).is_err());
        let mut s = schedule();
        s.jobs[0].request.host = "evil.example".to_string();
        assert!(validate_schedule(&s, limits()).is_err());
        let mut s = schedule();
        s.jobs[0].ordinal = 17;
        assert!(validate_schedule(&s, limits()).is_err());
    }
}
