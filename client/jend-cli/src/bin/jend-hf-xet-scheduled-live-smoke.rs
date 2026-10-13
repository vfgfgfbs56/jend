#![forbid(unsafe_code)]

// Separate, explicit opt-in live probe for *real* signed reconstruction shape:
// one or more signed fetch entries, each executed intact as singleton or
// multipart. No WeightVM publication and no signed page claims.
#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;
#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;
#[allow(dead_code)]
#[path = "../xet_fetch_schedule.rs"]
mod xet_fetch_schedule;
#[allow(dead_code)]
#[path = "../xet_multipart.rs"]
mod xet_multipart;
#[allow(dead_code)]
#[path = "../xet_multi_fetch_transport.rs"]
mod xet_multi_fetch_transport;
#[allow(dead_code)]
#[path = "../xet_signed_fetch_executor.rs"]
mod xet_signed_fetch_executor;
#[allow(dead_code)]
#[path = "../xorb_decode.rs"]
mod xorb_decode;
#[allow(dead_code)]
#[path = "../xet_multi_decode.rs"]
mod xet_multi_decode;

use source_worker_transport::{
    execute_pinned_get, ExpectedResponse, PinnedGetRequest, SecretBearer, TransportLimits,
};
use std::time::{SystemTime, UNIX_EPOCH};
use xet_fetch_schedule::{
    build_fetch_schedule, FetchScheduleError, FetchScheduleLimits,
};
use xet_metadata::{parse_read_grant, parse_v2_reconstruction};
use xet_signed_fetch_executor::{
    execute_signed_schedule_sequentially, SequentialFetchLimits,
};
use xet_multi_decode::decode_untrusted_multipart_ranges;
use xorb_decode::reconstruct_slice_from_ranges;

const REPO: &str = "openai-community/gpt2";
const COMMIT: &str = "607a30d783dfa663caf39e06633721c8d4cfcd7e";
const FILE: &str = "model.safetensors";
const LOGICAL_PROBE_BYTES: u64 = 1024 * 1024;
const MAX_PHYSICAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JOBS: usize = 8;
const MAX_RANGES: usize = 32;

fn unix_now() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("JEND_ALLOW_LIVE_HF_XET_SCHEDULE").as_deref() != Ok("1") {
        return Err("set JEND_ALLOW_LIVE_HF_XET_SCHEDULE=1 to authorize bounded live source traffic".into());
    }
    let hub_token = std::env::var("JEND_HF_TOKEN")
        .map_err(|_| "set JEND_HF_TOKEN to a read-only Hugging Face token, never on the command line")?;

    let resolve = execute_pinned_get(PinnedGetRequest {
        host: "huggingface.co".to_owned(),
        path_and_query: format!("/{REPO}/resolve/{COMMIT}/{FILE}"),
        range_header: Some("bytes=0-0".to_owned()),
        bearer: None,
        expected: ExpectedResponse::HfXetResolve,
        limits: TransportLimits {
            max_response_bytes: 4096,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 20_000,
        },
    }).await?;
    let file_id = resolve.x_xet_hash.ok_or("immutable resolve omitted X-Xet-Hash")?;

    let grant_response = execute_pinned_get(PinnedGetRequest {
        host: "huggingface.co".to_owned(),
        path_and_query: format!("/api/models/{REPO}/xet-read-token/{COMMIT}"),
        range_header: None,
        bearer: Some(SecretBearer::new(hub_token)?),
        expected: ExpectedResponse::Json200,
        limits: TransportLimits {
            max_response_bytes: 128 * 1024,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 20_000,
        },
    }).await?;
    let grant = parse_read_grant(&grant_response.body, unix_now()?)?;
    let (cas_token, cas_host, _) = grant.into_parts();

    let reconstruction_response = execute_pinned_get(PinnedGetRequest {
        host: cas_host,
        path_and_query: format!("/v2/reconstructions/{file_id}"),
        range_header: Some(format!("bytes=0-{}", LOGICAL_PROBE_BYTES - 1)),
        bearer: Some(SecretBearer::from_zeroizing(cas_token)?),
        expected: ExpectedResponse::Json200,
        limits: TransportLimits {
            max_response_bytes: 8 * 1024 * 1024,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        },
    }).await?;

    let reconstruction = parse_v2_reconstruction(
        &reconstruction_response.body, LOGICAL_PROBE_BYTES
    )?;
    let schedule = match build_fetch_schedule(
        &reconstruction,
        FetchScheduleLimits {
            max_total_payload_bytes: MAX_PHYSICAL_BYTES,
            max_request_payload_bytes: MAX_PHYSICAL_BYTES,
            max_jobs: MAX_JOBS,
            max_ranges: MAX_RANGES,
            max_concurrency: 1,
        },
    ) {
        Ok(s) => s,
        Err(FetchScheduleError::TooManyJobs
            | FetchScheduleError::TooManyRanges
            | FetchScheduleError::TotalPayloadBudgetExceeded
            | FetchScheduleError::RequestPayloadBudgetExceeded) => {
            println!("Jend live Xet signed schedule: SKIP (source needs more physical jobs/bytes than this bounded probe permits; no payload fetched)");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    // Every entry keeps its own original signed URL and byte-range header.
    // The executor runs serially, without fallback, publishing nothing on
    // partial failure. Any response above the budget aborts the entire call.
    let completed = execute_signed_schedule_sequentially(
        schedule,
        SequentialFetchLimits {
            max_total_physical_bytes: MAX_PHYSICAL_BYTES,
            max_jobs: MAX_JOBS,
            max_framing_per_job: 128 * 1024,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        },
    ).await?;
    let decoded = decode_untrusted_multipart_ranges(
        completed.parts, MAX_PHYSICAL_BYTES, MAX_DECODED_BYTES
    )?;
    let logical = reconstruct_slice_from_ranges(
        &reconstruction, &decoded, LOGICAL_PROBE_BYTES, LOGICAL_PROBE_BYTES
    )?;
    if u64::try_from(logical.len())? != LOGICAL_PROBE_BYTES {
        return Err("live bounded signed Xet logical slice length mismatch".into());
    }

    println!("Jend live Xet scheduled signed HTTP 206: PASS");
    println!("Jend live Xet physical-to-logical reconstruction: PASS");
    println!("Jend live Xet unverified bytes kept outside WeightVM: PASS");
    if completed.multipart_jobs > 0 {
        println!("Jend live Xet strict multipart network execution: PASS");
    } else {
        println!("Jend live Xet strict multipart network execution: NOT_EXERCISED (source returned singleton entries)");
    }
    if completed.single_range_jobs + completed.multipart_jobs > 1 {
        println!("Jend live Xet separate signed multi-entry fetches: PASS");
    } else {
        println!("Jend live Xet separate signed multi-entry fetches: NOT_EXERCISED (one entry)");
    }
    println!(
        "Jend live Xet fetch summary: single_jobs={}, multipart_jobs={}, physical_bytes={}, decoded_ranges={}, logical_bytes={}",
        completed.single_range_jobs,
        completed.multipart_jobs,
        completed.physical_bytes,
        decoded.len(),
        logical.len()
    );
    Ok(())
}
