#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;

use source_worker_transport::{
    execute_pinned_get, ExpectedResponse, PinnedGetRequest, TransportLimits,
};

const REPO: &str = "openai-community/gpt2";
const COMMIT: &str = "607a30d783dfa663caf39e06633721c8d4cfcd7e";
const FILE: &str = "model.safetensors";

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if std::env::var("JEND_ALLOW_LIVE_HF").as_deref() != Ok("1") {
        return Err("set JEND_ALLOW_LIVE_HF=1 to permit this explicit live Hugging Face smoke".into());
    }

    let response = execute_pinned_get(PinnedGetRequest {
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
    })
    .await?;

    let xet_hash = response
        .x_xet_hash
        .as_deref()
        .ok_or("live HF resolve omitted X-Xet-Hash")?;
    if xet_hash.len() != 64 {
        return Err("live HF X-Xet-Hash has wrong length".into());
    }
    if response.body.len() > 4096 {
        return Err("live HF metadata response exceeded the configured cap".into());
    }

    println!("Jend live HF pinned HTTPS resolve: PASS");
    println!("Jend live HF immutable X-Xet-Hash discovery: PASS");
    println!("Jend live HF full-weight download avoided: PASS");
    println!("Jend live HF pinned_public_addresses={}", response.pinned_addresses.len());
    Ok(())
}
