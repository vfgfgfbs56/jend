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

fn unix_now() -> std::result::Result<u64, Box<dyn std::error::Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if std::env::var("JEND_ALLOW_LIVE_HF").as_deref() != Ok("1") {
        return Err("set JEND_ALLOW_LIVE_HF=1 to permit this explicit live Hugging Face/Xet smoke".into());
    }

    // Intentionally use a dedicated environment variable instead of silently
    // inheriting HF_TOKEN. The user must explicitly opt the credential into
    // this one development smoke.
    let hub_token = std::env::var("JEND_HF_TOKEN")
        .map_err(|_| "set JEND_HF_TOKEN to a Hugging Face read token; do not pass it as a CLI argument")?;

    // Stage 0: immutable Hub resolve. Redirect execution is disabled; only the
    // X-Xet-Hash response header becomes the file identity.
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
        .ok_or("live HF immutable resolve omitted X-Xet-Hash")?;

    // Stage 1: request a short-lived Xet read grant scoped to this repository
    // and immutable commit. The Hub token is consumed into a non-Debug,
    // zeroizing transport wrapper before any network call.
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
    let (xet_token, cas_host, expires_unix) = grant.into_parts();
    if expires_unix <= now + 30 {
        return Err("live Xet read token did not retain the 30-second refresh margin".into());
    }

    // Stage 2: query only one logical byte of file reconstruction metadata.
    // This returns JSON containing signed xorb URLs, but M8.5.3 never executes
    // those URLs and therefore downloads no xorb payload or model weight bytes.
    let reconstruction_response = execute_pinned_get(PinnedGetRequest {
        host: cas_host.clone(),
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
    if reconstruction.terms.is_empty() || reconstruction.fetches.is_empty() {
        return Err("live Xet v2 reconstruction contained no terms/fetches".into());
    }
    if reconstruction.offset_into_first_range > reconstruction.terms[0].unpacked_length {
        return Err("live Xet reconstruction offset exceeds first term".into());
    }

    // Never print the Hub token, Xet token, signed xorb URL, signature, or full
    // response body. Only non-secret structural counts are emitted.
    println!("Jend live Xet scoped read-token: PASS");
    println!("Jend live Xet CAS v2 reconstruction: PASS");
    println!("Jend live Xet published-schema parse: PASS");
    println!("Jend live Xet signed xorb execution blocked: PASS");
    println!(
        "Jend live Xet metadata: cas_host={}, terms={}, fetches={}, probe_bytes=1",
        cas_host,
        reconstruction.terms.len(),
        reconstruction.fetches.len()
    );
    Ok(())
}
