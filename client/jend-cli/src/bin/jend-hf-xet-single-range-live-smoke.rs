#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;
#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;

use source_worker_transport::{
    execute_pinned_get, ExpectedResponse, PinnedGetRequest, SecretBearer, TransportLimits,
};
use std::time::{SystemTime, UNIX_EPOCH};
use xet_metadata::{parse_read_grant, parse_v2_reconstruction};

const REPO: &str = "openai-community/gpt2";
const COMMIT: &str = "607a30d783dfa663caf39e06633721c8d4cfcd7e";
const FILE: &str = "model.safetensors";
const PROBE_RANGE: &str = "bytes=0-0";
const MAX_LIVE_XORB_FETCH_BYTES: u64 = 16 * 1024 * 1024;

fn unix_now() -> std::result::Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if std::env::var("JEND_ALLOW_LIVE_HF_XORB").as_deref() != Ok("1") {
        return Err(
            "set JEND_ALLOW_LIVE_HF_XORB=1 to permit the explicit small live xorb fetch"
                .into(),
        );
    }
    let hub_token = std::env::var("JEND_HF_TOKEN").map_err(|_| {
        "set JEND_HF_TOKEN to a Hugging Face read token; do not pass it as a CLI argument"
    })?;

    let resolve = execute_pinned_get(PinnedGetRequest {
        host: "huggingface.co".into(),
        path_and_query: format!("/{REPO}/resolve/{COMMIT}/{FILE}"),
        range_header: Some(PROBE_RANGE.into()),
        bearer: None,
        expected: ExpectedResponse::HfXetResolve,
        limits: TransportLimits {
            max_response_bytes: 4096,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 20_000,
        },
    })
    .await?;
    let file_id = resolve
        .x_xet_hash
        .ok_or("live immutable resolve omitted X-Xet-Hash")?;

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
    })
    .await?;

    let now = unix_now()?;
    let grant = parse_read_grant(&token_response.body, now)
        .map_err(|error| format!("live Xet read-token metadata rejected: {error}"))?;
    let (xet_token, cas_host, _) = grant.into_parts();

    let reconstruction_response = execute_pinned_get(PinnedGetRequest {
        host: cas_host,
        path_and_query: format!("/v2/reconstructions/{file_id}"),
        range_header: Some(PROBE_RANGE.into()),
        bearer: Some(SecretBearer::from_zeroizing(xet_token)?),
        expected: ExpectedResponse::Json200,
        limits: TransportLimits {
            max_response_bytes: 8 * 1024 * 1024,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        },
    })
    .await?;

    let reconstruction = parse_v2_reconstruction(&reconstruction_response.body, 1)
        .map_err(|error| format!("live Xet reconstruction metadata rejected: {error}"))?;
    if reconstruction.fetches.len() != 1 {
        return Err(format!(
            "live one-byte probe returned {} fetch entries; M8.5.4 requires exactly one",
            reconstruction.fetches.len()
        )
        .into());
    }

    let signed = reconstruction.fetches[0]
        .single_range_request()
        .map_err(|error| format!("live Xet fetch is not a safe single range: {error}"))?;
    if signed.expected_len > MAX_LIVE_XORB_FETCH_BYTES {
        return Err(format!(
            "live Xet probe requested {} bytes, exceeding the {} byte M8.5.4 cap",
            signed.expected_len, MAX_LIVE_XORB_FETCH_BYTES
        )
        .into());
    }

    // This is the first actual signed xorb payload request in Jend. The URL is
    // not logged. The Range header comes solely from validated reconstruction
    // metadata; 200/full-object fallback and byte-count mismatch are rejected.
    let response = execute_pinned_get(PinnedGetRequest {
        host: signed.host.clone(),
        path_and_query: signed.path_and_query().to_owned(),
        range_header: Some(signed.range_header.clone()),
        bearer: None,
        expected: ExpectedResponse::SingleRange206 {
            expected_len: signed.expected_len,
        },
        limits: TransportLimits {
            max_response_bytes: signed.expected_len,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        },
    })
    .await?;

    if u64::try_from(response.body.len())? != signed.expected_len {
        return Err("live signed xorb body length changed after transport validation".into());
    }

    // M8.5.4 stops here. These are raw xorb bytes, NOT a verified WeightPage.
    // Do not persist them, do not pass them to inference, and do not claim
    // content integrity before xorb chunk deserialization/decompression lands.
    println!("Jend live Xet authorized single-range fetch: PASS");
    println!("Jend live Xet exact 206 byte-length enforcement: PASS");
    println!("Jend live Xet payload kept outside WeightVM: PASS");
    println!(
        "Jend live Xet range: host={}, fetched_bytes={}, reconstruction_probe_bytes=1",
        signed.host, signed.expected_len
    );
    Ok(())
}
