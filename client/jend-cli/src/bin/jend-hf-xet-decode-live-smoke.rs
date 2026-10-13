#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;
#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;
#[allow(dead_code)]
#[path = "../xorb_decode.rs"]
mod xorb_decode;

use source_worker_transport::{execute_pinned_get, ExpectedResponse, PinnedGetRequest, SecretBearer, TransportLimits};
use std::time::{SystemTime, UNIX_EPOCH};
use xet_metadata::{parse_read_grant, parse_v2_reconstruction};
use xorb_decode::{decode_xorb_single_range, reconstruct_slice_from_single_xorb};

const REPO: &str = "openai-community/gpt2";
const COMMIT: &str = "607a30d783dfa663caf39e06633721c8d4cfcd7e";
const FILE: &str = "model.safetensors";
const PROBE_RANGE: &str = "bytes=0-0";
const MAX_LIVE_XORB_FETCH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LIVE_DECODED_BYTES: u64 = 16 * 1024 * 1024;

fn unix_now() -> std::result::Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if std::env::var("JEND_ALLOW_LIVE_HF_XORB_DECODE").as_deref() != Ok("1") {
        return Err("set JEND_ALLOW_LIVE_HF_XORB_DECODE=1 to permit explicit small live xorb fetch+decode".into());
    }
    let hub_token = std::env::var("JEND_HF_TOKEN")
        .map_err(|_| "set JEND_HF_TOKEN to a Hugging Face read token; do not pass it as a CLI argument")?;

    let resolve = execute_pinned_get(PinnedGetRequest {
        host: "huggingface.co".into(), path_and_query: format!("/{REPO}/resolve/{COMMIT}/{FILE}"),
        range_header: Some(PROBE_RANGE.into()), bearer: None, expected: ExpectedResponse::HfXetResolve,
        limits: TransportLimits { max_response_bytes: 4096, connect_timeout_ms: 5_000, request_timeout_ms: 20_000 },
    }).await?;
    let file_id = resolve.x_xet_hash.ok_or("live immutable resolve omitted X-Xet-Hash")?;

    let token_response = execute_pinned_get(PinnedGetRequest {
        host: "huggingface.co".into(), path_and_query: format!("/api/models/{REPO}/xet-read-token/{COMMIT}"),
        range_header: None, bearer: Some(SecretBearer::new(hub_token)?), expected: ExpectedResponse::Json200,
        limits: TransportLimits { max_response_bytes: 128 * 1024, connect_timeout_ms: 5_000, request_timeout_ms: 20_000 },
    }).await?;
    let grant = parse_read_grant(&token_response.body, unix_now()?)
        .map_err(|e| format!("live Xet read-token metadata rejected: {e}"))?;
    let (xet_token, cas_host, _) = grant.into_parts();

    let reconstruction_response = execute_pinned_get(PinnedGetRequest {
        host: cas_host, path_and_query: format!("/v2/reconstructions/{file_id}"),
        range_header: Some(PROBE_RANGE.into()), bearer: Some(SecretBearer::from_zeroizing(xet_token)?),
        expected: ExpectedResponse::Json200,
        limits: TransportLimits { max_response_bytes: 8 * 1024 * 1024, connect_timeout_ms: 5_000, request_timeout_ms: 30_000 },
    }).await?;
    let reconstruction = parse_v2_reconstruction(&reconstruction_response.body, 1)
        .map_err(|e| format!("live Xet reconstruction metadata rejected: {e}"))?;
    if reconstruction.fetches.len() != 1 || reconstruction.fetches[0].ranges.len() != 1 {
        return Err("M8.5.5 live decoder requires exactly one fetch with one physical range".into());
    }
    let chunk_span = reconstruction.fetches[0].ranges[0].0;
    let signed = reconstruction.fetches[0].single_range_request()
        .map_err(|e| format!("live Xet fetch is not a safe single range: {e}"))?;
    if signed.expected_len > MAX_LIVE_XORB_FETCH_BYTES {
        return Err(format!("live Xet probe requested {} bytes, exceeding cap", signed.expected_len).into());
    }

    let response = execute_pinned_get(PinnedGetRequest {
        host: signed.host.clone(), path_and_query: signed.path_and_query().to_owned(),
        range_header: Some(signed.range_header.clone()), bearer: None,
        expected: ExpectedResponse::SingleRange206 { expected_len: signed.expected_len },
        limits: TransportLimits { max_response_bytes: signed.expected_len, connect_timeout_ms: 5_000, request_timeout_ms: 30_000 },
    }).await?;

    let decoded = decode_xorb_single_range(
        &signed.xorb_hash, &response.body, chunk_span.start, chunk_span.end, MAX_LIVE_DECODED_BYTES,
    ).map_err(|e| format!("live xorb payload decode rejected: {e}"))?;
    let logical = reconstruct_slice_from_single_xorb(&reconstruction, &decoded, 1)
        .map_err(|e| format!("live logical one-byte reconstruction rejected: {e}"))?;
    if logical.len() != 1 { return Err("live logical probe was not exactly one byte".into()); }

    // Still not a WeightPage: there is no signed Jend expected-page SHA-256 in
    // this standalone smoke. Do not persist/publish this logical byte.
    println!("Jend live Xet xorb v0 decode: PASS");
    println!("Jend live Xet LZ4/BG4 bounded decompression: PASS");
    println!("Jend live Xet logical one-byte reconstruction: PASS");
    println!("Jend live Xet decoded data kept outside WeightVM: PASS");
    println!(
        "Jend live Xet decode: host={}, fetched_bytes={}, decoded_bytes={}, chunks={}, raw={}, lz4={}, bg4={}",
        signed.host, response.body.len(), decoded.stats.decoded_bytes, decoded.chunks.len(),
        decoded.stats.raw_chunks, decoded.stats.lz4_chunks, decoded.stats.bg4_lz4_chunks
    );
    Ok(())
}
