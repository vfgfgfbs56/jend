//! M8.5.1 hardened HTTPS transport primitive for the future isolated model
//! source worker.
//!
//! This module intentionally lives in the already-networked `jend-cli` package
//! for this milestone so `jend-model-store` remains network-free and the
//! existing Cargo.lock can still be reused. The executable target is a distinct
//! process. A later milestone will give it private authenticated IPC and move it
//! out of the development client package without changing the security model.

use reqwest::{redirect::Policy, Client, StatusCode};
use std::{
    collections::HashSet,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    time::Duration,
};
use zeroize::Zeroizing;

const MAX_DNS_RESULTS: usize = 32;
const MAX_HEADER_VALUE: usize = 64 * 1024;
const MAX_PATH_AND_QUERY: usize = 64 * 1024;
const MAX_RESPONSE_HARD: u64 = 512 * 1024 * 1024;
const MAX_CONNECT_TIMEOUT_MS: u64 = 30_000;
const MAX_REQUEST_TIMEOUT_MS: u64 = 120_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedResponse {
    /// Hugging Face immutable resolve discovery. Redirect execution is disabled;
    /// the 3xx response is inspected for `X-Xet-Hash` instead.
    HfXetResolve,
    /// Strict JSON metadata response from an approved endpoint.
    Json200,
    /// Exact range bytes. Full-file `200 OK` fallback is forbidden.
    SingleRange206 { expected_len: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pub max_response_bytes: u64,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: 8 * 1024 * 1024,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        }
    }
}

impl TransportLimits {
    fn validate(self) -> Result<Self, TransportError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_HARD
            || self.connect_timeout_ms == 0
            || self.connect_timeout_ms > MAX_CONNECT_TIMEOUT_MS
            || self.request_timeout_ms < self.connect_timeout_ms
            || self.request_timeout_ms > MAX_REQUEST_TIMEOUT_MS
        {
            return Err(TransportError::InvalidRequest);
        }
        Ok(self)
    }
}

/// Secret bearer material is deliberately non-Debug and zeroized on drop.
pub struct SecretBearer(Zeroizing<String>);

impl SecretBearer {
    pub fn new(value: String) -> Result<Self, TransportError> {
        Self::from_zeroizing(Zeroizing::new(value))
    }

    pub fn from_zeroizing(value: Zeroizing<String>) -> Result<Self, TransportError> {
        if value.is_empty()
            || value.len() > MAX_HEADER_VALUE
            || value
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(TransportError::InvalidCredential);
        }
        Ok(Self(value))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

pub struct PinnedGetRequest {
    pub host: String,
    pub path_and_query: String,
    pub range_header: Option<String>,
    pub bearer: Option<SecretBearer>,
    pub expected: ExpectedResponse,
    pub limits: TransportLimits,
}

/// Safe response metadata. Location and signed authorization URLs are
/// intentionally not exposed or followed.
#[derive(Debug)]
pub struct PinnedGetResponse {
    pub status: StatusCode,
    pub x_xet_hash: Option<String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub pinned_addresses: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum TransportError {
    InvalidRequest,
    InvalidCredential,
    ForbiddenHost,
    DnsFailure,
    NonPublicAddress,
    ClientBuild,
    RequestFailed,
    UnexpectedStatus,
    InvalidHeader,
    ResponseTooLarge,
    RangeLengthMismatch,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidRequest => "source-worker request is invalid",
            Self::InvalidCredential => "source-worker bearer credential is invalid",
            Self::ForbiddenHost => "source-worker host is not allowlisted",
            Self::DnsFailure => "source-worker DNS resolution failed",
            Self::NonPublicAddress => "source-worker DNS resolved to a non-public address",
            Self::ClientBuild => "source-worker hardened HTTPS client build failed",
            Self::RequestFailed => "source-worker HTTPS request failed",
            Self::UnexpectedStatus => "source-worker received an unexpected HTTP status",
            Self::InvalidHeader => "source-worker received an invalid response header",
            Self::ResponseTooLarge => "source-worker response exceeded its byte budget",
            Self::RangeLengthMismatch => "source-worker exact range length did not match",
        };
        f.write_str(text)
    }
}

impl Error for TransportError {}

pub async fn execute_pinned_get(
    request: PinnedGetRequest,
) -> Result<PinnedGetResponse, TransportError> {
    validate_request_shape(&request)?;
    let limits = request.limits.validate()?;
    let pinned_addresses = resolve_and_validate(&request.host)?;

    // The URL retains the original domain, so rustls performs normal SNI and
    // certificate-name verification. `resolve_to_addrs` only overrides socket
    // destination selection after our public-IP validation.
    let client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .referer(false)
        .connect_timeout(Duration::from_millis(limits.connect_timeout_ms))
        .timeout(Duration::from_millis(limits.request_timeout_ms))
        .resolve_to_addrs(&request.host, &pinned_addresses)
        .user_agent("Jend-Source-Worker/0.1")
        .build()
        .map_err(|_| TransportError::ClientBuild)?;

    let url = format!("https://{}{}", request.host, request.path_and_query);
    let mut builder = client.get(url);
    if let Some(range) = &request.range_header {
        builder = builder.header(reqwest::header::RANGE, range);
    }
    if let Some(secret) = &request.bearer {
        builder = builder.bearer_auth(secret.expose());
    }

    let mut response = builder
        .send()
        .await
        .map_err(|_| TransportError::RequestFailed)?;
    let status = response.status();
    validate_status(request.expected, status)?;

    let announced = response.content_length();
    let expected_len = match request.expected {
        ExpectedResponse::SingleRange206 { expected_len } => Some(expected_len),
        _ => None,
    };
    if announced.is_some_and(|n| n > limits.max_response_bytes)
        || announced.is_some_and(|n| expected_len.is_some_and(|want| n != want))
    {
        return Err(TransportError::ResponseTooLarge);
    }

    let x_xet_hash = optional_header_ascii(&response, "x-xet-hash")?;
    if matches!(request.expected, ExpectedResponse::HfXetResolve)
        && x_xet_hash
            .as_deref()
            .is_none_or(|value| !is_lower_hex_64(value))
    {
        return Err(TransportError::InvalidHeader);
    }
    let content_type = optional_header_ascii(&response, reqwest::header::CONTENT_TYPE.as_str())?;

    let mut body = Vec::new();
    let mut received = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| TransportError::RequestFailed)?
    {
        received = received
            .checked_add(u64::try_from(chunk.len()).map_err(|_| TransportError::ResponseTooLarge)?)
            .ok_or(TransportError::ResponseTooLarge)?;
        if received > limits.max_response_bytes
            || expected_len.is_some_and(|want| received > want)
        {
            return Err(TransportError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    if expected_len.is_some_and(|want| received != want) {
        return Err(TransportError::RangeLengthMismatch);
    }

    Ok(PinnedGetResponse {
        status,
        x_xet_hash,
        content_type,
        body,
        pinned_addresses,
    })
}

fn validate_request_shape(request: &PinnedGetRequest) -> Result<(), TransportError> {
    if !is_allowed_source_host(&request.host)
        || request.path_and_query.is_empty()
        || !request.path_and_query.starts_with('/')
        || request.path_and_query.starts_with("//")
        || request.path_and_query.len() > MAX_PATH_AND_QUERY
        || request
            .path_and_query
            .bytes()
            .any(|b| b.is_ascii_control() || b == b'\\')
        || request
            .range_header
            .as_deref()
            .is_some_and(|value| !valid_range_header(value))
    {
        return Err(TransportError::InvalidRequest);
    }
    if matches!(request.expected, ExpectedResponse::SingleRange206 { .. }) {
        let Some(range) = request.range_header.as_deref() else {
            return Err(TransportError::InvalidRequest);
        };
        if range.contains(',') {
            // M8.5.2 owns multipart/byteranges parsing. Do not pretend the
            // single-range byte-count gate is valid for multipart bodies.
            return Err(TransportError::InvalidRequest);
        }
    }
    Ok(())
}

fn validate_status(expected: ExpectedResponse, status: StatusCode) -> Result<(), TransportError> {
    let ok = match expected {
        ExpectedResponse::HfXetResolve => status == StatusCode::FOUND,
        ExpectedResponse::Json200 => status == StatusCode::OK,
        ExpectedResponse::SingleRange206 { expected_len } => {
            expected_len > 0 && status == StatusCode::PARTIAL_CONTENT
        }
    };
    if ok {
        Ok(())
    } else {
        Err(TransportError::UnexpectedStatus)
    }
}

fn optional_header_ascii(
    response: &reqwest::Response,
    name: &str,
) -> Result<Option<String>, TransportError> {
    let Some(value) = response.headers().get(name) else {
        return Ok(None);
    };
    let text = value.to_str().map_err(|_| TransportError::InvalidHeader)?;
    if text.len() > MAX_HEADER_VALUE || text.bytes().any(|b| b.is_ascii_control()) {
        return Err(TransportError::InvalidHeader);
    }
    Ok(Some(text.to_owned()))
}

fn valid_range_header(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("bytes=") else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 8192
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b','))
        && rest.split(',').all(|item| {
            let Some((start, end)) = item.split_once('-') else {
                return false;
            };
            !start.is_empty()
                && !end.is_empty()
                && start.parse::<u64>().ok().zip(end.parse::<u64>().ok())
                    .is_some_and(|(a, b)| a <= b)
        })
}

fn resolve_and_validate(host: &str) -> Result<Vec<SocketAddr>, TransportError> {
    let iter = (host, 443)
        .to_socket_addrs()
        .map_err(|_| TransportError::DnsFailure)?;
    let mut unique = HashSet::new();
    let mut output = Vec::new();
    for addr in iter {
        if !is_public_ip(addr.ip()) {
            return Err(TransportError::NonPublicAddress);
        }
        if unique.insert(addr) {
            output.push(addr);
            if output.len() > MAX_DNS_RESULTS {
                return Err(TransportError::DnsFailure);
            }
        }
    }
    if output.is_empty() {
        return Err(TransportError::DnsFailure);
    }
    Ok(output)
}

pub fn is_allowed_source_host(host: &str) -> bool {
    matches!(
        host,
        "huggingface.co"
            | "cas-server.xethub.hf.co"
            | "cas-server.xethub-eu.hf.co"
            | "transfer.xethub.hf.co"
            | "transfer.xethub-eu.hf.co"
            | "us.aws.cdn.hf.co"
            | "us.gcp.cdn.hf.co"
    )
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let s = ip.segments();
    if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    true
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_hosts_are_closed_allowlist() {
        assert!(is_allowed_source_host("huggingface.co"));
        assert!(is_allowed_source_host("transfer.xethub.hf.co"));
        assert!(is_allowed_source_host("us.aws.cdn.hf.co"));
        assert!(is_allowed_source_host("us.gcp.cdn.hf.co"));
        assert!(!is_allowed_source_host("eu.aws.cdn.hf.co"));
        assert!(!is_allowed_source_host("evil.example.com"));
        assert!(!is_allowed_source_host("169.254.169.254"));
    }

    #[test]
    fn non_public_addresses_fail_closed() {
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn only_concrete_bounded_byte_ranges_are_accepted() {
        assert!(valid_range_header("bytes=0-0"));
        assert!(valid_range_header("bytes=0-9,20-29"));
        assert!(!valid_range_header("bytes=0-"));
        assert!(!valid_range_header("bytes=-9"));
        assert!(!valid_range_header("bytes=9-0"));
        assert!(!valid_range_header("items=0-9"));
        assert!(!valid_range_header("bytes=0-9\r\nX-Evil: 1"));
    }
}
