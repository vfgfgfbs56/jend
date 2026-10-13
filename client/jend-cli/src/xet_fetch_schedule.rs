//! M8.5.8 bounded scheduler for validated Xet reconstruction fetch entries.
//!
//! This module is deliberately transport-independent. Each reconstruction
//! fetch entry stays atomic because one signed URL may authorize a set of byte
//! ranges that must be requested together. The scheduler budgets authorized
//! xorb payload bytes and assigns deterministic concurrency waves; it does NOT
//! execute HTTP or parse multipart/byteranges responses.

use crate::xet_metadata::{ChunkSpan, ParseError, Reconstruction, SignedRangeBatchRequest};

pub const HARD_MAX_TOTAL_XORB_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_REQUEST_XORB_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;
pub const HARD_MAX_FETCH_JOBS: usize = 128;
pub const HARD_MAX_FETCH_RANGES: usize = 512;
pub const HARD_MAX_FETCH_CONCURRENCY: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchScheduleLimits {
    pub max_total_payload_bytes: u64,
    pub max_request_payload_bytes: u64,
    pub max_jobs: usize,
    pub max_ranges: usize,
    pub max_concurrency: usize,
}

impl Default for FetchScheduleLimits {
    fn default() -> Self {
        Self {
            // These are intentionally much larger than one 64 KiB Jend page,
            // but remain bounded enough to stop metadata from turning a page
            // miss into an unbounded model download.
            max_total_payload_bytes: 32 * 1024 * 1024,
            max_request_payload_bytes: 16 * 1024 * 1024,
            max_jobs: 64,
            max_ranges: 256,
            max_concurrency: 4,
        }
    }
}

impl FetchScheduleLimits {
    fn validate(self) -> Result<Self, FetchScheduleError> {
        if self.max_total_payload_bytes == 0
            || self.max_total_payload_bytes > HARD_MAX_TOTAL_XORB_PAYLOAD_BYTES
            || self.max_request_payload_bytes == 0
            || self.max_request_payload_bytes > HARD_MAX_REQUEST_XORB_PAYLOAD_BYTES
            || self.max_request_payload_bytes > self.max_total_payload_bytes
            || self.max_jobs == 0
            || self.max_jobs > HARD_MAX_FETCH_JOBS
            || self.max_ranges == 0
            || self.max_ranges > HARD_MAX_FETCH_RANGES
            || self.max_concurrency == 0
            || self.max_concurrency > HARD_MAX_FETCH_CONCURRENCY
        {
            return Err(FetchScheduleError::InvalidLimits);
        }
        Ok(self)
    }
}

/// One atomic signed Xet fetch. The request intentionally does not implement
/// Debug because it owns short-lived signed query material.
pub struct ScheduledXorbFetch {
    pub ordinal: usize,
    pub wave: usize,
    pub request: SignedRangeBatchRequest,
}

/// Deterministic fetch schedule. `jobs` preserve reconstruction fetch order;
/// `wave` only bounds which independent jobs may run concurrently.
pub struct XetFetchSchedule {
    pub jobs: Vec<ScheduledXorbFetch>,
    pub total_authorized_payload_bytes: u64,
    pub total_ranges: usize,
    pub max_concurrency: usize,
    pub wave_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FetchScheduleError {
    InvalidLimits,
    EmptySchedule,
    TooManyJobs,
    TooManyRanges,
    RequestPayloadBudgetExceeded,
    TotalPayloadBudgetExceeded,
    DuplicateChunkCoverage,
    Metadata(ParseError),
    Overflow,
}

impl std::fmt::Display for FetchScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Xet fetch schedule rejected: {self:?}")
    }
}

impl std::error::Error for FetchScheduleError {}

impl From<ParseError> for FetchScheduleError {
    fn from(value: ParseError) -> Self {
        Self::Metadata(value)
    }
}

fn reject_duplicate_chunk_coverage(
    spans: &mut Vec<(String, ChunkSpan)>,
) -> Result<(), FetchScheduleError> {
    spans.sort_by(|(hash_a, span_a), (hash_b, span_b)| {
        hash_a
            .cmp(hash_b)
            .then(span_a.start.cmp(&span_b.start))
            .then(span_a.end.cmp(&span_b.end))
    });
    for pair in spans.windows(2) {
        let (previous_hash, previous_span) = &pair[0];
        let (hash, span) = &pair[1];
        if previous_hash == hash && span.start < previous_span.end {
            return Err(FetchScheduleError::DuplicateChunkCoverage);
        }
    }
    Ok(())
}

pub fn build_fetch_schedule(
    reconstruction: &Reconstruction,
    limits: FetchScheduleLimits,
) -> Result<XetFetchSchedule, FetchScheduleError> {
    let limits = limits.validate()?;
    if reconstruction.fetches.is_empty() {
        return Err(FetchScheduleError::EmptySchedule);
    }
    if reconstruction.fetches.len() > limits.max_jobs {
        return Err(FetchScheduleError::TooManyJobs);
    }

    let mut jobs = Vec::with_capacity(reconstruction.fetches.len());
    let mut total_authorized_payload_bytes = 0u64;
    let mut total_ranges = 0usize;
    let mut chunk_coverage = Vec::new();

    for (ordinal, fetch) in reconstruction.fetches.iter().enumerate() {
        let request = fetch.range_batch_request()?;
        if request.authorized_payload_bytes > limits.max_request_payload_bytes {
            return Err(FetchScheduleError::RequestPayloadBudgetExceeded);
        }
        total_authorized_payload_bytes = total_authorized_payload_bytes
            .checked_add(request.authorized_payload_bytes)
            .ok_or(FetchScheduleError::Overflow)?;
        if total_authorized_payload_bytes > limits.max_total_payload_bytes {
            return Err(FetchScheduleError::TotalPayloadBudgetExceeded);
        }

        total_ranges = total_ranges
            .checked_add(request.ranges.len())
            .ok_or(FetchScheduleError::Overflow)?;
        if total_ranges > limits.max_ranges {
            return Err(FetchScheduleError::TooManyRanges);
        }
        for (chunks, _) in &request.ranges {
            chunk_coverage.push((request.xorb_hash.clone(), *chunks));
        }

        jobs.push(ScheduledXorbFetch {
            ordinal,
            wave: ordinal / limits.max_concurrency,
            request,
        });
    }

    reject_duplicate_chunk_coverage(&mut chunk_coverage)?;
    let wave_count = jobs
        .len()
        .checked_add(limits.max_concurrency - 1)
        .ok_or(FetchScheduleError::Overflow)?
        / limits.max_concurrency;

    Ok(XetFetchSchedule {
        jobs,
        total_authorized_payload_bytes,
        total_ranges,
        max_concurrency: limits.max_concurrency,
        wave_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xet_metadata::parse_v2_reconstruction;

    fn fixture() -> String {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        format!(
            r#"{{
              "offset_into_first_range": 0,
              "terms": [
                {{"hash":"{a}","unpacked_length":16,"range":{{"start":0,"end":2}}}},
                {{"hash":"{b}","unpacked_length":16,"range":{{"start":5,"end":7}}}}
              ],
              "xorbs": {{
                "{a}": [
                  {{"url":"https://transfer.xethub.hf.co/xorbs/default/{a}?X-Xet-Signed-Range=bytes%3D0-9&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k","ranges":[{{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":9}}}}]}},
                  {{"url":"https://transfer.xethub.hf.co/xorbs/default/{a}?X-Xet-Signed-Range=bytes%3D100-109&Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k","ranges":[{{"chunks":{{"start":1,"end":2}},"bytes":{{"start":100,"end":109}}}}]}}
                ],
                "{b}": [
                  {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{b}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k","ranges":[
                    {{"chunks":{{"start":5,"end":6}},"bytes":{{"start":0,"end":7}}}},
                    {{"chunks":{{"start":6,"end":7}},"bytes":{{"start":20,"end":27}}}}
                  ]}}
                ]
              }}
            }}"#
        )
    }

    fn parsed() -> Reconstruction {
        parse_v2_reconstruction(fixture().as_bytes(), 16).expect("fixture must parse")
    }

    #[test]
    fn schedules_atomic_fetch_entries_in_bounded_waves() {
        let schedule = build_fetch_schedule(
            &parsed(),
            FetchScheduleLimits {
                max_total_payload_bytes: 64,
                max_request_payload_bytes: 32,
                max_jobs: 8,
                max_ranges: 8,
                max_concurrency: 2,
            },
        )
        .unwrap();
        assert_eq!(schedule.jobs.len(), 3);
        assert_eq!(schedule.total_ranges, 4);
        assert_eq!(schedule.total_authorized_payload_bytes, 36);
        assert_eq!(schedule.wave_count, 2);
        assert_eq!(schedule.jobs[0].wave, 0);
        assert_eq!(schedule.jobs[1].wave, 0);
        assert_eq!(schedule.jobs[2].wave, 1);
        assert_eq!(schedule.jobs[2].request.range_header, "bytes=0-7,20-27");
        assert_eq!(schedule.jobs[2].request.ranges.len(), 2);
    }

    #[test]
    fn budgets_and_concurrency_fail_closed() {
        assert_eq!(
            build_fetch_schedule(
                &parsed(),
                FetchScheduleLimits {
                    max_total_payload_bytes: 35,
                    max_request_payload_bytes: 32,
                    max_jobs: 8,
                    max_ranges: 8,
                    max_concurrency: 2,
                },
            )
            .err(),
            Some(FetchScheduleError::TotalPayloadBudgetExceeded)
        );
        assert_eq!(
            build_fetch_schedule(
                &parsed(),
                FetchScheduleLimits {
                    max_total_payload_bytes: 64,
                    max_request_payload_bytes: 15,
                    max_jobs: 8,
                    max_ranges: 8,
                    max_concurrency: 2,
                },
            )
            .err(),
            Some(FetchScheduleError::RequestPayloadBudgetExceeded)
        );
        assert_eq!(
            build_fetch_schedule(
                &parsed(),
                FetchScheduleLimits {
                    max_total_payload_bytes: 64,
                    max_request_payload_bytes: 32,
                    max_jobs: 8,
                    max_ranges: 8,
                    max_concurrency: 0,
                },
            )
            .err(),
            Some(FetchScheduleError::InvalidLimits)
        );
    }

    #[test]
    fn duplicate_physical_chunk_coverage_is_rejected() {
        let a = "a".repeat(64);
        let body = format!(
            r#"{{"offset_into_first_range":0,"terms":[{{"hash":"{a}","unpacked_length":8,"range":{{"start":0,"end":1}}}}],"xorbs":{{"{a}":[
              {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{a}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k","ranges":[{{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":7}}}}]}},
              {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{a}?Expires=9999999999&Policy=p2&Signature=s2&Key-Pair-Id=k","ranges":[{{"chunks":{{"start":0,"end":1}},"bytes":{{"start":100,"end":107}}}}]}}
            ]}}}}"#
        );
        let reconstruction = parse_v2_reconstruction(body.as_bytes(), 1).unwrap();
        assert_eq!(
            build_fetch_schedule(
                &reconstruction,
                FetchScheduleLimits {
                    max_total_payload_bytes: 64,
                    max_request_payload_bytes: 32,
                    max_jobs: 8,
                    max_ranges: 8,
                    max_concurrency: 2,
                },
            )
            .err(),
            Some(FetchScheduleError::DuplicateChunkCoverage)
        );
    }
}
