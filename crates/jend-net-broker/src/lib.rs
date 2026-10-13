#![forbid(unsafe_code)]

mod provider;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

pub use provider::{
    ProviderTunnelGrant, ProviderTunnelMeter, ProviderTunnelPolicy,
};

const IPC_DOMAIN: &[u8] = b"JEND/JNET-IPC/V1";
const HANDLE_DOMAIN: &[u8] = b"JEND/JNET-HANDLE/V1";
const MAX_REDIRECTS_HARD: u8 = 5;
const MAX_RESPONSE_HARD: u64 = 32 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum NetBrokerError {
    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),
    #[error("URL is malformed")]
    InvalidUrl,
    #[error("only HTTPS is allowed")]
    InsecureScheme,
    #[error("URL credentials are forbidden")]
    UrlCredentials,
    #[error("target host is forbidden")]
    ForbiddenHost,
    #[error("target resolved to a non-public address")]
    NonPublicAddress,
    #[error("DNS resolution is empty")]
    EmptyResolution,
    #[error("redirect limit exceeded")]
    RedirectLimit,
    #[error("response exceeds policy limit")]
    ResponseTooLarge,
    #[error("encrypted IPC frame is malformed")]
    MalformedFrame,
    #[error("encrypted IPC frame authentication failed")]
    Authentication,
    #[error("IPC sequence is stale or replayed")]
    Replay,
    #[error("provider tunnel policy is invalid")]
    InvalidProviderPolicy,
    #[error("provider identity does not match the registered adapter")]
    ProviderMismatch,
    #[error("provider API path is outside the registered adapter policy")]
    ForbiddenProviderPath,
    #[error("provider request exceeds the configured upload limit")]
    ProviderRequestTooLarge,
    #[error("provider encrypted tunnel byte budget exceeded")]
    TunnelBudgetExceeded,
}

pub type Result<T> = core::result::Result<T, NetBrokerError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    Search,
    OpenBrokerHandle,
    TypedConnector,
    ProviderTunnel,
}

/// A web page is never a source of authority. Tool permissions are resolved by
/// code outside the model; retrieved text must remain tagged as untrusted data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentTrust {
    UntrustedInternet,
}

#[derive(Clone, Copy, Debug)]
pub struct BrokerPolicy {
    pub max_response_bytes: u64,
    pub max_redirects: u8,
}

impl Default for BrokerPolicy {
    fn default() -> Self {
        Self {
            max_response_bytes: 8 * 1024 * 1024,
            max_redirects: 3,
        }
    }
}

impl BrokerPolicy {
    pub fn validate(self) -> Result<Self> {
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_HARD {
            return Err(NetBrokerError::ResponseTooLarge);
        }
        if self.max_redirects > MAX_REDIRECTS_HARD {
            return Err(NetBrokerError::RedirectLimit);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug)]
pub struct PinnedTarget {
    pub url: Url,
    pub resolved: Vec<IpAddr>,
}

/// The transport must connect to one of `resolved` directly and preserve the
/// original host for TLS SNI/certificate verification. Re-resolving after this
/// check would reintroduce DNS-rebinding risk.
pub fn validate_and_pin_https_target(raw_url: &str, resolved: Vec<IpAddr>) -> Result<PinnedTarget> {
    let url = Url::parse(raw_url).map_err(|_| NetBrokerError::InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(NetBrokerError::InsecureScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(NetBrokerError::UrlCredentials);
    }
    if url.port_or_known_default() != Some(443) {
        return Err(NetBrokerError::ForbiddenHost);
    }
    let host = url.host().ok_or(NetBrokerError::ForbiddenHost)?;
    match host {
        Host::Domain(name) => {
            let lower = name.to_ascii_lowercase();
            if lower == "localhost"
                || lower.ends_with(".localhost")
                || lower.ends_with(".local")
                || lower.ends_with(".home.arpa")
                || !lower.contains('.')
            {
                return Err(NetBrokerError::ForbiddenHost);
            }
        }
        Host::Ipv4(ip) => {
            if !is_public_ip(IpAddr::V4(ip)) {
                return Err(NetBrokerError::NonPublicAddress);
            }
        }
        Host::Ipv6(ip) => {
            if !is_public_ip(IpAddr::V6(ip)) {
                return Err(NetBrokerError::NonPublicAddress);
            }
        }
    }
    if resolved.is_empty() {
        return Err(NetBrokerError::EmptyResolution);
    }
    if resolved.iter().any(|ip| !is_public_ip(*ip)) {
        return Err(NetBrokerError::NonPublicAddress);
    }
    Ok(PinnedTarget { url, resolved })
}

pub fn validate_redirect(policy: BrokerPolicy, redirect_count: u8, raw_url: &str, resolved: Vec<IpAddr>) -> Result<PinnedTarget> {
    let policy = policy.validate()?;
    if redirect_count >= policy.max_redirects {
        return Err(NetBrokerError::RedirectLimit);
    }
    validate_and_pin_https_target(raw_url, resolved)
}

pub fn validate_response_size(policy: BrokerPolicy, announced: Option<u64>, bytes_seen: u64) -> Result<()> {
    let policy = policy.validate()?;
    if announced.is_some_and(|v| v > policy.max_response_bytes) || bytes_seen > policy.max_response_bytes {
        return Err(NetBrokerError::ResponseTooLarge);
    }
    Ok(())
}

/// Public-internet allowlist. Private, loopback, link-local, documentation,
/// benchmarking, multicast and other special-use ranges are rejected.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    if a == 0 || a == 10 || a == 127 || a >= 224 {
        return false;
    }
    if a == 100 && (64..=127).contains(&b) { return false; }
    if a == 169 && b == 254 { return false; }
    if a == 172 && (16..=31).contains(&b) { return false; }
    if a == 192 && b == 168 { return false; }
    if a == 192 && b == 0 && c == 0 { return false; }
    if a == 192 && b == 0 && c == 2 { return false; }
    if a == 192 && b == 88 && c == 99 { return false; }
    if a == 198 && (b == 18 || b == 19) { return false; }
    if a == 198 && b == 51 && c == 100 { return false; }
    if a == 203 && b == 0 && c == 113 { return false; }
    true
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    let segments = ip.segments();
    // fc00::/7 unique-local
    if (segments[0] & 0xfe00) == 0xfc00 { return false; }
    // fe80::/10 link-local
    if (segments[0] & 0xffc0) == 0xfe80 { return false; }
    // 2001:db8::/32 documentation
    if segments[0] == 0x2001 && segments[1] == 0x0db8 { return false; }
    // IPv4-mapped IPv6: validate the embedded v4 address as well.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct BrokerHandle(pub [u8; 32]);

pub fn random_broker_handle(target: &PinnedTarget) -> Result<BrokerHandle> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)?;
    let mut h = Sha256::new();
    h.update(HANDLE_DOMAIN);
    h.update(random);
    h.update(target.url.as_str().as_bytes());
    for ip in &target.resolved {
        h.update(ip.to_string().as_bytes());
    }
    random.zeroize();
    Ok(BrokerHandle(h.finalize().into()))
}

/// AEAD wrapper for local AI/controller <-> network-broker IPC. This protects
/// against accidental local observation/tampering, but it is not an authority
/// boundary: a compromised process that legitimately owns the session key can
/// still produce valid frames. Network authorization must therefore remain in
/// broker policy/capabilities, not in encryption alone.
pub struct JnetIpcSession {
    key: Zeroizing<[u8; 32]>,
    send_sequence: u64,
    recv_sequence: u64,
}

#[derive(Clone, Debug)]
pub struct EncryptedFrame {
    pub sequence: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl JnetIpcSession {
    pub fn from_key(mut key: [u8; 32]) -> Self {
        let stored = Zeroizing::new(key);
        key.zeroize();
        Self { key: stored, send_sequence: 0, recv_sequence: 0 }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedFrame> {
        let sequence = self.send_sequence;
        self.send_sequence = self.send_sequence.checked_add(1).ok_or(NetBrokerError::MalformedFrame)?;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let aad = frame_aad(sequence);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let ciphertext = cipher.encrypt(
            &XNonce::from(nonce),
            Payload { msg: plaintext, aad: &aad },
        ).map_err(|_| NetBrokerError::Authentication)?;
        Ok(EncryptedFrame { sequence, nonce, ciphertext })
    }

    pub fn decrypt(&mut self, frame: &EncryptedFrame) -> Result<Zeroizing<Vec<u8>>> {
        if frame.sequence != self.recv_sequence {
            return Err(NetBrokerError::Replay);
        }
        let aad = frame_aad(frame.sequence);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let plaintext = cipher.decrypt(
            &XNonce::from(frame.nonce),
            Payload { msg: &frame.ciphertext, aad: &aad },
        ).map_err(|_| NetBrokerError::Authentication)?;
        self.recv_sequence = self.recv_sequence.checked_add(1).ok_or(NetBrokerError::MalformedFrame)?;
        Ok(Zeroizing::new(plaintext))
    }
}

fn frame_aad(sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(IPC_DOMAIN.len() + 8);
    aad.extend_from_slice(IPC_DOMAIN);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_targets_are_rejected() {
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(!is_public_ip("fc00::1".parse().unwrap()));
    }

    #[test]
    fn https_target_is_pinned() {
        let target = validate_and_pin_https_target(
            "https://example.com/path",
            vec!["93.184.216.34".parse().unwrap()],
        ).unwrap();
        assert_eq!(target.url.host_str(), Some("example.com"));
    }

    #[test]
    fn ipc_rejects_replay() {
        let mut a = JnetIpcSession::from_key([9u8; 32]);
        let mut b = JnetIpcSession::from_key([9u8; 32]);
        let frame = a.encrypt(b"hello").unwrap();
        assert_eq!(&*b.decrypt(&frame).unwrap(), b"hello");
        assert!(matches!(b.decrypt(&frame), Err(NetBrokerError::Replay)));
    }
}
