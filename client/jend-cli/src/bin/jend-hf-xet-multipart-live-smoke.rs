#![forbid(unsafe_code)]

// Explicit opt-in HF/Xet network probe. No network during cargo test.
// The signed xorb authorization URL and all credentials remain non-loggable.
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
#[path = "../xorb_decode.rs"]
mod xorb_decode;
#[allow(dead_code)]
#[path = "../xet_multi_decode.rs"]
mod xet_multi_decode;

use source_worker_transport::{
    execute_pinned_get, ExpectedResponse, PinnedGetRequest, SecretBearer, TransportLimits,
};
use std::time::{SystemTime, UNIX_EPOCH};
use xet_fetch_schedule::{build_fetch_schedule, FetchScheduleLimits};
use xet_metadata::{parse_read_grant, parse_v2_reconstruction};
use xet_multi_decode::decode_untrusted_multipart_ranges;
use xet_multi_fetch_transport::execute_signed_xet_multi_range;
use xet_multipart::MultipartLimits;
use xorb_decode::reconstruct_slice_from_ranges;

const REPO: &str = "openai-community/gpt2";
const COMMIT: &str = "607a30d783dfa663caf39e06633721c8d4cfcd7e";
const FILE: &str = "model.safetensors";
const LOGICAL_PROBE_BYTES: u64 = 1024 * 1024;
const MAX_PHYSICAL_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FRAMING_BYTES: u64 = 128 * 1024;

fn unix_now() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("JEND_ALLOW_LIVE_HF_XET_MULTIPART").as_deref() != Ok("1") {
        return Err(
            "set JEND_ALLOW_LIVE_HF_XET_MULTIPART=1 to authorize this bounded live HF/Xet probe"
                .into(),
        );
    }
    // Separate opt-in to use a read token for this probe. The token is never
    // sent to an xorb CDN and never printed, dumped or passed on the CLI.
    let hub_token = std::env::var("JEND_HF_TOKEN").map_err(|_| {
        "set JEND_HF_TOKEN to a Hugging Face read token via a non-logged environment variable"
    })?;

    let resolve = execute_pinned_get(PinnedGetRequest {
        host: "huggingface.co".into(),
        path_and_query: format!("/{REPO}/resolve/{COMMIT}/{FILE}"),
        range_header: Some("bytes=0-0".into()),
        bearer: None,
        expected: ExpectedResponse::HfXetResolve,
        limits: TransportLimits {
            max_response_bytes: 4096,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 20_000,
        },
    }).await?;
    let file_id = resolve.x_xet_hash.ok_or("immutable resolve omitted X-Xet-Hash")?;

    let token_response = execute_pinned_get(PinnedGetRequest {
        host: "huggingface.co".into(),
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
    let grant = parse_read_grant(&token_response.body, unix_now()?)?;
    let (cas_token, cas_host, _) = grant.into_parts();

    // Ask the CAS for one small logical interval, not an entire weight file.
    // This probe does not execute any physical ranges until schedule validation.
    let last = LOGICAL_PROBE_BYTES - 1;
    let reconstruction_response = execute_pinned_get(PinnedGetRequest {
        host: cas_host,
        path_and_query: format!("/v2/reconstructions/{file_id}"),
        range_header: Some(format!("bytes=0-{last}")),
        bearer: Some(SecretBearer::from_zeroizing(cas_token)?),
        expected: ExpectedResponse::Json200,
        limits: TransportLimits {
            max_response_bytes: 8 * 1024 * 1024,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        },
    }).await?;
    let reconstruction = parse_v2_reconstruction(&reconstruction_response.body, LOGICAL_PROBE_BYTES)?;
    let schedule = build_fetch_schedule(
        &reconstruction,
        FetchScheduleLimits {
            max_total_payload_bytes: MAX_PHYSICAL_PAYLOAD_BYTES,
            max_request_payload_bytes: MAX_PHYSICAL_PAYLOAD_BYTES,
            max_jobs: 8,
            max_ranges: 32,
            max_concurrency: 1,
        },
    )?;

    // Real metadata may contain one large range or multiple separate signed
    // entries. That is not equivalent to a single atomic multipart request.
    // Never forge a comma-joined URL across distinct signed grants.
    if schedule.jobs.len() != 1 || schedule.jobs[0].request.ranges.len() < 2 {
        println!(
            "Jend live Xet atomic multipart probe: SKIP (no eligible single signed multi-range entry; no xorb payload fetched)"
        );
        return Ok(());
    }
    let signed = schedule.jobs.into_iter().next().ok_or("missing signed batch")?.request;

    let parts = execute_signed_xet_multi_range(
        signed,
        TransportLimits {
            max_response_bytes: MAX_PHYSICAL_PAYLOAD_BYTES + MAX_FRAMING_BYTES,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        },
        MultipartLimits {
            max_payload: MAX_PHYSICAL_PAYLOAD_BYTES,
            max_framing: MAX_FRAMING_BYTES,
        },
    ).await?;
    let physical_bytes: usize = parts.iter().map(|part| part.bytes.len()).sum();
    let decoded = decode_untrusted_multipart_ranges(
        parts, MAX_PHYSICAL_PAYLOAD_BYTES, MAX_DECODED_BYTES
    )?;
    let logical = reconstruct_slice_from_ranges(
        &reconstruction, &decoded, LOGICAL_PROBE_BYTES, LOGICAL_PROBE_BYTES
    )?;
    if u64::try_from(logical.len())? != LOGICAL_PROBE_BYTES {
        return Err("live Xet logical probe length mismatch".into());
    }

    // No independent Jend release-signed page hash is available in this
    // standalone smoke. Never write the logical bytes to a file or WeightVM.
    println!("Jend live Xet atomic multipart HTTP 206: PASS");
    println!("Jend live Xet bounded multipart xorb decode: PASS");
    println!("Jend live Xet multi-range logical slice assembly: PASS");
    println!("Jend live Xet unverified bytes kept outside WeightVM: PASS");
    println!(
        "Jend live Xet multi-range probe: fetched_bytes={physical_bytes}, decoded_ranges={}, logical_bytes={}",
        decoded.len(), logical.len()
    );
    Ok(())
}
