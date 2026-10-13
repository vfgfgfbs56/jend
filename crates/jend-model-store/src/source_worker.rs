//! M8.5.0: transport-independent fail-closed source worker response gate.
//! No network, credentials, or unverified bytes are passed to WeightVM here.
use crate::{HfHttpRequestPlan, HfRedirectPolicy, ModelStoreError, Result};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceResponseKind {
    ResolveMetadata,
    JsonMetadata,
    ExactRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceWorkerLimits {
    pub max_response_bytes: u64,
    pub max_total_bytes: u64,
    pub max_concurrent_requests: u16,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
}
impl Default for SourceWorkerLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 8 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            max_concurrent_requests: 4,
            connect_timeout_ms: 5000,
            request_timeout_ms: 30000,
        }
    }
}
impl SourceWorkerLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > 512 * 1024 * 1024
            || self.max_total_bytes < self.max_response_bytes
            || self.max_total_bytes > 2 * 1024 * 1024 * 1024
            || self.max_concurrent_requests == 0
            || self.max_concurrent_requests > 16
            || self.connect_timeout_ms == 0
            || self.connect_timeout_ms > 30000
            || self.request_timeout_ms < self.connect_timeout_ms
            || self.request_timeout_ms > 120000
        {
            return Err(ModelStoreError::InvalidSourceWorkerResponse);
        }
        Ok(())
    }
}

/// DNS pinning contract: every resolved address must be globally routable.
/// The future HTTP transport must connect ONLY to one of these validated IPs,
/// retaining the original host for TLS SNI and certificate verification.
pub fn validate_resolved_addresses(addresses: &[IpAddr]) -> Result<()> {
    if addresses.is_empty() || addresses.len() > 32 || addresses.iter().any(|ip| !public_ip(*ip)) {
        return Err(ModelStoreError::InvalidSourceWorkerResponse);
    }
    Ok(())
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a,b,c,_] = v.octets();
            !(a == 0 || a == 10 || a == 127 || a >= 224
                || a == 169 && b == 254
                || a == 172 && (16..=31).contains(&b)
                || a == 192 && b == 168
                || a == 100 && (64..=127).contains(&b)
                || a == 192 && b == 0 && c == 0
                || a == 192 && b == 0 && c == 2
                || a == 198 && (b == 18 || b == 19)
                || a == 198 && b == 51 && c == 100
                || a == 203 && b == 0 && c == 113
                || a == 192 && b == 88 && c == 99)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] & 0xfff0) == 0x2000 && s[1] == 0x0db8
                || v.to_ipv4_mapped().is_some_and(|mapped| !public_ip(IpAddr::V4(mapped))))
        }
    }
}

/// State machine for an individual bounded HTTP response.
/// A response must be finalized successfully before its bytes can be consumed.
pub struct BoundedSourceResponse {
    cap: u64,
    expected: Option<u64>,
    received: u64,
    data: Vec<u8>,
    finalized: bool,
}
impl BoundedSourceResponse {
    pub fn begin(
        request: &HfHttpRequestPlan,
        limits: SourceWorkerLimits,
        kind: SourceResponseKind,
        status: u16,
        content_length: Option<u64>,
        expected_range_len: Option<u64>,
    ) -> Result<Self> {
        limits.validate()?;
        if request.redirect_policy != HfRedirectPolicy::Reject
            || request.host.is_empty()
            || request.host.contains('/')
            || request.host.contains('@')
            || request.host.contains(':')
            || request.path_and_query.starts_with("//")
            || !request.path_and_query.starts_with('/')
        {
            return Err(ModelStoreError::InvalidSourceWorkerResponse);
        }
        let expected = match kind {
            SourceResponseKind::ResolveMetadata => {
                if status != 302 || expected_range_len.is_some() {
                    return Err(ModelStoreError::InvalidSourceWorkerResponse);
                }
                None
            }
            SourceResponseKind::JsonMetadata => {
                if status != 200 || expected_range_len.is_some() {
                    return Err(ModelStoreError::InvalidSourceWorkerResponse);
                }
                None
            }
            SourceResponseKind::ExactRange => {
                if status != 206 || request.range_header.is_none() {
                    return Err(ModelStoreError::InvalidSourceWorkerResponse);
                }
                Some(expected_range_len.filter(|n| *n > 0).ok_or(ModelStoreError::InvalidSourceWorkerResponse)?)
            }
        };
        let cap = limits.max_response_bytes.min(request.max_response_bytes);
        if cap == 0 || expected.is_some_and(|n| n > cap)
            || content_length.is_some_and(|n| n > cap || expected.is_some_and(|want| n != want))
        {
            return Err(ModelStoreError::InvalidSourceWorkerResponse);
        }
        Ok(Self { cap, expected, received: 0, data: Vec::new(), finalized: false })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.finalized {
            return Err(ModelStoreError::InvalidSourceWorkerResponse);
        }
        let next = self.received.checked_add(bytes.len() as u64)
            .ok_or(ModelStoreError::Overflow)?;
        if next > self.cap || self.expected.is_some_and(|n| next > n) {
            return Err(ModelStoreError::InvalidSourceWorkerResponse);
        }
        self.data.extend_from_slice(bytes);
        self.received = next;
        Ok(())
    }
    pub fn finish(mut self) -> Result<Vec<u8>> {
        if self.expected.is_some_and(|n| n != self.received) {
            return Err(ModelStoreError::InvalidSourceWorkerResponse);
        }
        self.finalized = true;
        Ok(std::mem::take(&mut self.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HfCredentialScope;
    fn request() -> HfHttpRequestPlan {
        HfHttpRequestPlan {
            host: "cas-server.xethub.hf.co".into(),
            path_and_query: "/v2/reconstructions/abcd".into(),
            range_header: Some("bytes=0-3".into()),
            credential_scope: HfCredentialScope::XetRead,
            redirect_policy: HfRedirectPolicy::Reject,
            max_response_bytes: 1024,
        }
    }
    #[test]
    fn range_must_be_exact_and_bounded() {
        let mut r = BoundedSourceResponse::begin(
            &request(), SourceWorkerLimits::default(),
            SourceResponseKind::ExactRange, 206, Some(4), Some(4)
        ).unwrap();
        r.push(&[1,2]).unwrap();
        r.push(&[3,4]).unwrap();
        assert_eq!(r.finish().unwrap(), vec![1,2,3,4]);
        assert!(BoundedSourceResponse::begin(
            &request(), SourceWorkerLimits::default(),
            SourceResponseKind::ExactRange, 200, Some(4), Some(4)
        ).is_err());
    }
    #[test]
    fn reject_local_dns_and_overlong_body() {
        assert!(validate_resolved_addresses(&["127.0.0.1".parse().unwrap()]).is_err());
        assert!(validate_resolved_addresses(&["169.254.169.254".parse().unwrap()]).is_err());
        assert!(validate_resolved_addresses(&["::1".parse().unwrap()]).is_err());
        assert!(validate_resolved_addresses(&["8.8.8.8".parse().unwrap()]).is_ok());
        let mut r = BoundedSourceResponse::begin(
            &request(), SourceWorkerLimits::default(),
            SourceResponseKind::ExactRange, 206, None, Some(4)
        ).unwrap();
        assert!(r.push(&[0;5]).is_err());
    }
}
