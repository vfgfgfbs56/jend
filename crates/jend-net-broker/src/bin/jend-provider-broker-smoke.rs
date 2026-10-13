#![forbid(unsafe_code)]

use jend_net_broker::{
    NetBrokerError, ProviderTunnelMeter, ProviderTunnelPolicy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = ProviderTunnelPolicy {
        provider_id: "provider-a".into(),
        api_host: "api.example.com".into(),
        chat_path_prefix: "/v1/chat".into(),
        max_upload_bytes: 1024 * 1024,
        max_download_bytes: 8 * 1024 * 1024,
    };

    policy.validate_adapter_request(
        "provider-a",
        "/v1/chat/messages",
        32 * 1024,
        1024 * 1024,
    )?;

    if !matches!(
        policy.validate_adapter_request(
            "provider-a",
            "/unrelated/admin",
            1,
            1,
        ),
        Err(NetBrokerError::ForbiddenProviderPath)
    ) {
        return Err("provider adapter path policy failed closed".into());
    }

    let grant = policy.authorize_tunnel(vec!["93.184.216.34".parse()?])?;
    if grant.target.url.host_str() != Some("api.example.com") {
        return Err("provider tunnel escaped the registered host".into());
    }

    if policy
        .authorize_tunnel(vec!["169.254.169.254".parse()?])
        .is_ok()
    {
        return Err("provider tunnel accepted metadata/private address".into());
    }

    let mut meter = ProviderTunnelMeter::new(&grant);
    meter.account_encrypted_upload(4096)?;
    meter.account_encrypted_download(8192)?;

    if !matches!(
        meter.account_encrypted_upload(1024 * 1024),
        Err(NetBrokerError::TunnelBudgetExceeded)
    ) {
        return Err("opaque provider tunnel upload budget did not fail closed".into());
    }

    println!("Jend provider broker host/path policy: PASS");
    println!("Jend provider opaque-TLS/byte-budget boundary: PASS");
    Ok(())
}
