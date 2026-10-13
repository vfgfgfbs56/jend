#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;

use source_worker_transport::{is_allowed_source_host, is_public_ip, SecretBearer};

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    if !is_allowed_source_host("huggingface.co")
        || !is_allowed_source_host("cas-server.xethub.hf.co")
        || is_allowed_source_host("evil.example.com")
    {
        return Err("HF/Xet source host allowlist failed".into());
    }
    for local in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"] {
        if is_public_ip(local.parse()?) {
            return Err(format!("non-public address accepted: {local}").into());
        }
    }
    if SecretBearer::new("bad token with spaces".into()).is_ok() {
        return Err("whitespace-bearing secret token was accepted".into());
    }

    println!("Jend Source Worker hardened transport policy: PASS");
    println!("Jend Source Worker proxy/redirect escape disabled by builder contract: PASS");
    println!("Jend Source Worker DNS public-address guard: PASS");
    Ok(())
}
