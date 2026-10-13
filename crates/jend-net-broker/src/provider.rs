//! Provider tunnel policy for closed/provider-backed model inference.
//!
//! The Provider Adapter owns provider HTTP/TLS semantics and sensitive prompt /
//! credential material. The Network Broker only authorizes a pinned HTTPS
//! destination and meters opaque TLS bytes. It does not parse provider prompts,
//! Authorization headers, or response plaintext.

use std::net::IpAddr;

use crate::{
    random_broker_handle, validate_and_pin_https_target, BrokerHandle, NetBrokerError,
    PinnedTarget, Result,
};

const MAX_PROVIDER_ID: usize = 96;
const MAX_HOST: usize = 253;
const MAX_PATH_PREFIX: usize = 256;
const MAX_TUNNEL_DIRECTION_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderTunnelPolicy {
    pub provider_id: String,
    pub api_host: String,
    /// Adapter-local path restriction. The Network Broker cannot inspect this
    /// once TLS is established; the provider adapter must enforce it before
    /// constructing the encrypted request.
    pub chat_path_prefix: String,
    pub max_upload_bytes: u64,
    pub max_download_bytes: u64,
}

impl ProviderTunnelPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_provider_id(&self.provider_id)?;
        validate_host(&self.api_host)?;
        validate_path_prefix(&self.chat_path_prefix)?;
        if self.max_upload_bytes == 0
            || self.max_download_bytes == 0
            || self.max_upload_bytes > MAX_TUNNEL_DIRECTION_BYTES
            || self.max_download_bytes > MAX_TUNNEL_DIRECTION_BYTES
        {
            return Err(NetBrokerError::InvalidProviderPolicy);
        }
        Ok(())
    }

    /// Validate the provider adapter's typed request metadata before it is
    /// serialized into TLS. This is defense-in-depth in the adapter boundary;
    /// the Network Broker's hard enforcement boundary remains host/443 + byte
    /// budgets because TLS payloads are intentionally opaque to it.
    pub fn validate_adapter_request(
        &self,
        provider_id: &str,
        path: &str,
        plaintext_request_bytes: u64,
        requested_plaintext_response_bytes: u64,
    ) -> Result<()> {
        self.validate()?;
        if provider_id != self.provider_id {
            return Err(NetBrokerError::ProviderMismatch);
        }
        validate_path(path)?;
        if !path_matches_prefix(path, &self.chat_path_prefix) {
            return Err(NetBrokerError::ForbiddenProviderPath);
        }
        if plaintext_request_bytes > self.max_upload_bytes {
            return Err(NetBrokerError::ProviderRequestTooLarge);
        }
        if requested_plaintext_response_bytes == 0
            || requested_plaintext_response_bytes > self.max_download_bytes
        {
            return Err(NetBrokerError::ResponseTooLarge);
        }
        Ok(())
    }

    /// Authorize only the provider's registered HTTPS host. DNS pinning and
    /// public-address checks reuse the broker's existing SSRF/rebinding guard.
    pub fn authorize_tunnel(&self, resolved: Vec<IpAddr>) -> Result<ProviderTunnelGrant> {
        self.validate()?;
        let url = format!("https://{}/", self.api_host);
        let target = validate_and_pin_https_target(&url, resolved)?;
        if target.url.host_str() != Some(self.api_host.as_str()) {
            return Err(NetBrokerError::ProviderMismatch);
        }
        let handle = random_broker_handle(&target)?;
        Ok(ProviderTunnelGrant {
            provider_id: self.provider_id.clone(),
            handle,
            target,
            max_upload_bytes: self.max_upload_bytes,
            max_download_bytes: self.max_download_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ProviderTunnelGrant {
    pub provider_id: String,
    pub handle: BrokerHandle,
    pub target: PinnedTarget,
    pub max_upload_bytes: u64,
    pub max_download_bytes: u64,
}

/// Counts only encrypted tunnel bytes. This type intentionally has no API for
/// parsing HTTP bodies, prompt text, Authorization headers, or model output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTunnelMeter {
    max_upload_bytes: u64,
    max_download_bytes: u64,
    uploaded_bytes: u64,
    downloaded_bytes: u64,
}

impl ProviderTunnelMeter {
    pub fn new(grant: &ProviderTunnelGrant) -> Self {
        Self {
            max_upload_bytes: grant.max_upload_bytes,
            max_download_bytes: grant.max_download_bytes,
            uploaded_bytes: 0,
            downloaded_bytes: 0,
        }
    }

    pub fn account_encrypted_upload(&mut self, bytes: usize) -> Result<()> {
        self.uploaded_bytes = checked_meter(
            self.uploaded_bytes,
            bytes,
            self.max_upload_bytes,
        )?;
        Ok(())
    }

    pub fn account_encrypted_download(&mut self, bytes: usize) -> Result<()> {
        self.downloaded_bytes = checked_meter(
            self.downloaded_bytes,
            bytes,
            self.max_download_bytes,
        )?;
        Ok(())
    }

    pub const fn uploaded_bytes(self) -> u64 {
        self.uploaded_bytes
    }

    pub const fn downloaded_bytes(self) -> u64 {
        self.downloaded_bytes
    }
}

fn checked_meter(current: u64, bytes: usize, max: u64) -> Result<u64> {
    let bytes = u64::try_from(bytes).map_err(|_| NetBrokerError::TunnelBudgetExceeded)?;
    let next = current
        .checked_add(bytes)
        .ok_or(NetBrokerError::TunnelBudgetExceeded)?;
    if next > max {
        return Err(NetBrokerError::TunnelBudgetExceeded);
    }
    Ok(next)
}

fn validate_provider_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_ID
        || !value.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'-' | b'_' | b'.')
        })
    {
        return Err(NetBrokerError::InvalidProviderPolicy);
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > MAX_HOST
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host.contains('.')
        || !host.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.')
        })
    {
        return Err(NetBrokerError::InvalidProviderPolicy);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(NetBrokerError::InvalidProviderPolicy);
        }
    }
    Ok(())
}

fn validate_path_prefix(path: &str) -> Result<()> {
    validate_path(path)?;
    if path.len() > MAX_PATH_PREFIX {
        return Err(NetBrokerError::InvalidProviderPolicy);
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
        || path.split('/').any(|segment| segment == "." || segment == "..")
        || !path.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'/' | b'-' | b'_' | b'.' | b'+' | b'=')
        })
    {
        return Err(NetBrokerError::ForbiddenProviderPath);
    }
    Ok(())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    path.strip_prefix(prefix)
        .is_some_and(|suffix| prefix.ends_with('/') || suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ProviderTunnelPolicy {
        ProviderTunnelPolicy {
            provider_id: "provider-a".into(),
            api_host: "api.example.com".into(),
            chat_path_prefix: "/v1/chat".into(),
            max_upload_bytes: 1024 * 1024,
            max_download_bytes: 8 * 1024 * 1024,
        }
    }

    #[test]
    fn typed_adapter_request_is_provider_and_path_bound() {
        let policy = policy();
        assert!(policy
            .validate_adapter_request(
                "provider-a",
                "/v1/chat/messages",
                4096,
                1024 * 1024,
            )
            .is_ok());
        assert!(matches!(
            policy.validate_adapter_request(
                "provider-b",
                "/v1/chat/messages",
                4096,
                1024,
            ),
            Err(NetBrokerError::ProviderMismatch)
        ));
        assert!(matches!(
            policy.validate_adapter_request(
                "provider-a",
                "/admin/secrets",
                4096,
                1024,
            ),
            Err(NetBrokerError::ForbiddenProviderPath)
        ));
    }

    #[test]
    fn provider_tunnel_reuses_public_ip_and_dns_pinning_guard() {
        let grant = policy()
            .authorize_tunnel(vec!["93.184.216.34".parse().unwrap()])
            .unwrap();
        assert_eq!(grant.target.url.host_str(), Some("api.example.com"));

        assert!(policy()
            .authorize_tunnel(vec!["127.0.0.1".parse().unwrap()])
            .is_err());
        assert!(policy()
            .authorize_tunnel(vec!["169.254.169.254".parse().unwrap()])
            .is_err());
    }

    #[test]
    fn opaque_tls_meter_enforces_both_direction_budgets() {
        let grant = policy()
            .authorize_tunnel(vec!["93.184.216.34".parse().unwrap()])
            .unwrap();
        let mut meter = ProviderTunnelMeter::new(&grant);

        assert!(meter.account_encrypted_upload(1024).is_ok());
        assert!(meter.account_encrypted_download(2048).is_ok());
        assert_eq!(meter.uploaded_bytes(), 1024);
        assert_eq!(meter.downloaded_bytes(), 2048);

        assert!(matches!(
            meter.account_encrypted_upload(1024 * 1024),
            Err(NetBrokerError::TunnelBudgetExceeded)
        ));
    }

    #[test]
    fn traversal_query_and_prefix_confusion_are_rejected() {
        let policy = policy();
        for path in [
            "/v1/chat/../admin",
            "/v1/chat?debug=1",
            "/v1/chat#fragment",
            "/v1/chatty",
        ] {
            assert!(policy
                .validate_adapter_request("provider-a", path, 1, 1)
                .is_err());
        }
    }
}
