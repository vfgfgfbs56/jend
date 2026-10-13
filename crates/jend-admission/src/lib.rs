#![forbid(unsafe_code)]

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const CHALLENGE_DOMAIN: &[u8] = b"JEND/REGISTRATION-ADMISSION/V1";
const POW_DOMAIN: &[u8] = b"JEND/REGISTRATION-POW/V1";
const USERNAME_DOMAIN: &[u8] = b"JEND/REGISTRATION-USERNAME/V1";
const MAX_CHALLENGE_LIFETIME_MS: i64 = 5 * 60 * 1000;
const MAX_DIFFICULTY_BITS: u8 = 24;

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),
    #[error("registration challenge is malformed")]
    Malformed,
    #[error("registration challenge signature is invalid")]
    Signature,
    #[error("registration challenge is expired or not yet valid")]
    Expired,
    #[error("registration challenge is bound to a different username")]
    UsernameMismatch,
    #[error("proof of work is invalid")]
    InvalidProof,
    #[error("rate limit exceeded")]
    RateLimited,
}

pub type Result<T> = core::result::Result<T, AdmissionError>;

/// Privacy-normalized rate key. The HTTP edge should derive this from an IP,
/// network prefix, ASN or other signal using a rotating server-side secret.
/// The admission core therefore never needs to retain raw client addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RateKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug)]
pub struct TokenBucketConfig {
    pub capacity: u32,
    pub refill_tokens: u32,
    pub refill_period_ms: u64,
    pub idle_ttl_ms: u64,
}

impl TokenBucketConfig {
    pub const fn registration_default() -> Self {
        Self {
            capacity: 5,
            refill_tokens: 1,
            refill_period_ms: 60_000,
            idle_ttl_ms: 30 * 60_000,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens_milli: u64,
    last_ms: u64,
    last_seen_ms: u64,
}

/// Per-edge token bucket. Production deployments should apply several keys
/// (for example privacy-normalized IP and network-prefix buckets) and keep a
/// database/account-creation backstop. This is intentionally not presented as
/// a globally coordinated distributed limiter.
pub struct LocalRateLimiter {
    config: TokenBucketConfig,
    buckets: HashMap<RateKey, Bucket>,
}

impl LocalRateLimiter {
    pub fn new(config: TokenBucketConfig) -> Self {
        Self { config, buckets: HashMap::new() }
    }

    pub fn check(&mut self, key: RateKey, now_ms: u64) -> Result<()> {
        let capacity_milli = u64::from(self.config.capacity) * 1000;
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            tokens_milli: capacity_milli,
            last_ms: now_ms,
            last_seen_ms: now_ms,
        });

        let elapsed = now_ms.saturating_sub(bucket.last_ms);
        if self.config.refill_period_ms > 0 {
            let added = elapsed
                .saturating_mul(u64::from(self.config.refill_tokens))
                .saturating_mul(1000)
                / self.config.refill_period_ms;
            bucket.tokens_milli = bucket.tokens_milli.saturating_add(added).min(capacity_milli);
        }
        bucket.last_ms = now_ms;
        bucket.last_seen_ms = now_ms;

        if bucket.tokens_milli < 1000 {
            return Err(AdmissionError::RateLimited);
        }
        bucket.tokens_milli -= 1000;
        Ok(())
    }

    pub fn prune(&mut self, now_ms: u64) {
        let ttl = self.config.idle_ttl_ms;
        self.buckets.retain(|_, b| now_ms.saturating_sub(b.last_seen_ms) <= ttl);
    }
}

/// Signals are deliberately coarse. They are computed outside the crypto core
/// so deployments may combine local velocity, network-prefix pressure and an
/// optional edge-provider signal without making a third party a trust anchor.
#[derive(Clone, Copy, Debug, Default)]
pub struct RiskSignals {
    pub ip_creation_pressure: u8,
    pub network_creation_pressure: u8,
    pub failed_challenge_pressure: u8,
    pub automation_signal: u8,
}

impl RiskSignals {
    pub fn score(self) -> u8 {
        let weighted = u16::from(self.ip_creation_pressure)
            .saturating_mul(3)
            .saturating_add(u16::from(self.network_creation_pressure).saturating_mul(2))
            .saturating_add(u16::from(self.failed_challenge_pressure).saturating_mul(2))
            .saturating_add(u16::from(self.automation_signal).saturating_mul(3));
        (weighted / 10).min(100) as u8
    }

    pub fn proof_difficulty(self) -> u8 {
        match self.score() {
            0..=19 => 0,
            20..=49 => 14,
            50..=79 => 18,
            _ => 21,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationChallenge {
    pub challenge_id: [u8; 16],
    pub username_digest: [u8; 32],
    pub issued_unix_ms: i64,
    pub expires_unix_ms: i64,
    pub difficulty_bits: u8,
    pub nonce: [u8; 32],
    pub signature: [u8; 64],
}

const CHALLENGE_MAGIC: &[u8; 4] = b"JADM";
const CHALLENGE_VERSION: u16 = 1;
const CHALLENGE_WIRE_LEN: usize = 4 + 2 + 16 + 32 + 8 + 8 + 1 + 32 + 64;

impl RegistrationChallenge {
    /// Stable opaque wire representation for HTTP transport. Decoding checks
    /// framing only; AdmissionVerifier still authenticates signature, expiry,
    /// username binding and PoW.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHALLENGE_WIRE_LEN);
        out.extend_from_slice(CHALLENGE_MAGIC);
        out.extend_from_slice(&CHALLENGE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.challenge_id);
        out.extend_from_slice(&self.username_digest);
        out.extend_from_slice(&self.issued_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_unix_ms.to_be_bytes());
        out.push(self.difficulty_bits);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CHALLENGE_WIRE_LEN || &bytes[..4] != CHALLENGE_MAGIC {
            return Err(AdmissionError::Malformed);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != CHALLENGE_VERSION {
            return Err(AdmissionError::Malformed);
        }
        let mut pos = 6usize;
        let challenge_id = bytes[pos..pos+16].try_into().map_err(|_| AdmissionError::Malformed)?; pos += 16;
        let username_digest = bytes[pos..pos+32].try_into().map_err(|_| AdmissionError::Malformed)?; pos += 32;
        let issued_unix_ms = i64::from_be_bytes(bytes[pos..pos+8].try_into().map_err(|_| AdmissionError::Malformed)?); pos += 8;
        let expires_unix_ms = i64::from_be_bytes(bytes[pos..pos+8].try_into().map_err(|_| AdmissionError::Malformed)?); pos += 8;
        let difficulty_bits = bytes[pos]; pos += 1;
        let nonce = bytes[pos..pos+32].try_into().map_err(|_| AdmissionError::Malformed)?; pos += 32;
        let signature = bytes[pos..pos+64].try_into().map_err(|_| AdmissionError::Malformed)?;
        Ok(Self { challenge_id, username_digest, issued_unix_ms, expires_unix_ms, difficulty_bits, nonce, signature })
    }
}

pub struct AdmissionIssuer {
    signing_key: SigningKey,
}

#[derive(Clone)]
pub struct AdmissionVerifier {
    public_key: [u8; 32],
}

impl AdmissionIssuer {
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)?;
        Ok(Self::from_secret_bytes(&mut secret))
    }

    pub fn from_secret_bytes(secret: &mut [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        secret.zeroize();
        Self { signing_key }
    }

    pub fn verifier(&self) -> AdmissionVerifier {
        AdmissionVerifier { public_key: self.signing_key.verifying_key().to_bytes() }
    }

    pub fn issue_for_username(
        &self,
        canonical_username: &str,
        difficulty_bits: u8,
        now_unix_ms: i64,
        lifetime_ms: i64,
    ) -> Result<RegistrationChallenge> {
        if difficulty_bits > MAX_DIFFICULTY_BITS
            || lifetime_ms <= 0
            || lifetime_ms > MAX_CHALLENGE_LIFETIME_MS
        {
            return Err(AdmissionError::Malformed);
        }
        let expires_unix_ms = now_unix_ms.checked_add(lifetime_ms).ok_or(AdmissionError::Malformed)?;
        let mut challenge_id = [0u8; 16];
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut challenge_id)?;
        getrandom::fill(&mut nonce)?;
        let username_digest = username_digest(canonical_username);
        let body = challenge_body(
            &challenge_id,
            &username_digest,
            now_unix_ms,
            expires_unix_ms,
            difficulty_bits,
            &nonce,
        );
        let signature = self.signing_key.sign(&signed_digest(&body)).to_bytes();
        Ok(RegistrationChallenge {
            challenge_id,
            username_digest,
            issued_unix_ms: now_unix_ms,
            expires_unix_ms,
            difficulty_bits,
            nonce,
            signature,
        })
    }
}

impl AdmissionVerifier {
    pub fn verify(
        &self,
        challenge: &RegistrationChallenge,
        canonical_username: &str,
        solution: u64,
        now_unix_ms: i64,
    ) -> Result<()> {
        if challenge.difficulty_bits > MAX_DIFFICULTY_BITS {
            return Err(AdmissionError::Malformed);
        }
        if challenge.issued_unix_ms > now_unix_ms
            || now_unix_ms > challenge.expires_unix_ms
            || challenge.expires_unix_ms.saturating_sub(challenge.issued_unix_ms) > MAX_CHALLENGE_LIFETIME_MS
        {
            return Err(AdmissionError::Expired);
        }
        if username_digest(canonical_username) != challenge.username_digest {
            return Err(AdmissionError::UsernameMismatch);
        }
        let body = challenge_body(
            &challenge.challenge_id,
            &challenge.username_digest,
            challenge.issued_unix_ms,
            challenge.expires_unix_ms,
            challenge.difficulty_bits,
            &challenge.nonce,
        );
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| AdmissionError::Signature)?;
        key.verify_strict(&signed_digest(&body), &Signature::from_bytes(&challenge.signature))
            .map_err(|_| AdmissionError::Signature)?;

        if challenge.difficulty_bits == 0 {
            return Ok(());
        }
        let mut h = Sha256::new();
        h.update(POW_DOMAIN);
        h.update(body);
        h.update(solution.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        if leading_zero_bits(&digest) < challenge.difficulty_bits {
            return Err(AdmissionError::InvalidProof);
        }
        Ok(())
    }
}

pub fn solve_for_testing(challenge: &RegistrationChallenge, max_iterations: u64) -> Option<u64> {
    let body = challenge_body(
        &challenge.challenge_id,
        &challenge.username_digest,
        challenge.issued_unix_ms,
        challenge.expires_unix_ms,
        challenge.difficulty_bits,
        &challenge.nonce,
    );
    for solution in 0..max_iterations {
        let mut h = Sha256::new();
        h.update(POW_DOMAIN);
        h.update(&body);
        h.update(solution.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        if leading_zero_bits(&digest) >= challenge.difficulty_bits {
            return Some(solution);
        }
    }
    None
}

fn username_digest(username: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(USERNAME_DOMAIN);
    h.update(username.as_bytes());
    h.finalize().into()
}

fn challenge_body(
    challenge_id: &[u8; 16],
    username_digest: &[u8; 32],
    issued_unix_ms: i64,
    expires_unix_ms: i64,
    difficulty_bits: u8,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 32 + 8 + 8 + 1 + 32);
    out.extend_from_slice(challenge_id);
    out.extend_from_slice(username_digest);
    out.extend_from_slice(&issued_unix_ms.to_be_bytes());
    out.extend_from_slice(&expires_unix_ms.to_be_bytes());
    out.push(difficulty_bits);
    out.extend_from_slice(nonce);
    out
}

fn signed_digest(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHALLENGE_DOMAIN);
    h.update(body);
    h.finalize().into()
}

fn leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut total = 0u8;
    for byte in bytes {
        if *byte == 0 {
            total = total.saturating_add(8);
        } else {
            total = total.saturating_add(byte.leading_zeros() as u8);
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_difficulty_challenge_is_username_bound() {
        let issuer = AdmissionIssuer::generate().unwrap();
        let verifier = issuer.verifier();
        let c = issuer.issue_for_username("alice", 0, 1000, 60_000).unwrap();
        verifier.verify(&c, "alice", 0, 2000).unwrap();
        assert!(matches!(verifier.verify(&c, "bob", 0, 2000), Err(AdmissionError::UsernameMismatch)));
    }

    #[test]
    fn challenge_wire_round_trip() {
        let issuer = AdmissionIssuer::generate().unwrap();
        let verifier = issuer.verifier();
        let challenge = issuer.issue_for_username("alice", 0, 1000, 60_000).unwrap();
        let decoded = RegistrationChallenge::decode(&challenge.encode()).unwrap();
        assert_eq!(decoded, challenge);
        verifier.verify(&decoded, "alice", 0, 2000).unwrap();
    }

    #[test]
    fn token_bucket_blocks_burst() {
        let mut limiter = LocalRateLimiter::new(TokenBucketConfig {
            capacity: 2,
            refill_tokens: 1,
            refill_period_ms: 1000,
            idle_ttl_ms: 10_000,
        });
        let key = RateKey([7u8; 32]);
        limiter.check(key, 0).unwrap();
        limiter.check(key, 0).unwrap();
        assert!(matches!(limiter.check(key, 0), Err(AdmissionError::RateLimited)));
        limiter.check(key, 1000).unwrap();
    }
}
