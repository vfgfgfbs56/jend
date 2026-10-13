#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use jend_sync::{AccountId, SyncDeviceId};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"JCAP";
const VERSION: u16 = 1;
const SIGN_DOMAIN: &[u8] = b"JEND/CAPABILITY/V1";
const KEY_ID_DOMAIN: &[u8] = b"JEND/CAPABILITY-KEY-ID/V1";
const MAX_LIFETIME_MS: i64 = 60 * 60 * 1000;
const BODY_LEN: usize = 16 + 8 + 1 + 16 + 8 + 8 + 4 + 16;

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),
    #[error("capability token is malformed")]
    Malformed,
    #[error("capability signature is invalid")]
    Signature,
    #[error("capability is expired or not yet valid")]
    Expired,
    #[error("capability lacks required permission")]
    Permission,
    #[error("capability device binding mismatch")]
    DeviceMismatch,
    #[error("capability auth epoch is stale")]
    StaleAuthEpoch,
}

pub type Result<T> = core::result::Result<T, CapabilityError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CapabilityKeyId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permissions(u32);

impl Permissions {
    pub const NONE: Self = Self(0);
    pub const SYNC_RELAY: Self = Self(1 << 0);
    pub const MODEL_CATALOG: Self = Self(1 << 1);
    pub const MODEL_DOWNLOAD: Self = Self(1 << 2);
    pub const ACCOUNT_MANAGE: Self = Self(1 << 3);
    pub const DEVICE_ENROLL: Self = Self(1 << 4);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    pub const fn bits(self) -> u32 { self.0 }
    pub const fn from_bits(bits: u32) -> Self { Self(bits) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityClaims {
    pub account_id: AccountId,
    pub auth_epoch: u64,
    /// None allows a pre-enrollment account-management capability. Normal sync
    /// and model-download capabilities should be device-bound.
    pub device_id: Option<SyncDeviceId>,
    pub issued_unix_ms: i64,
    pub expires_unix_ms: i64,
    pub permissions: Permissions,
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCapability {
    pub key_id: CapabilityKeyId,
    pub claims: CapabilityClaims,
    pub signature: [u8; 64],
}

pub struct CapabilityIssuer {
    key: SigningKey,
    key_id: CapabilityKeyId,
}

#[derive(Clone)]
pub struct CapabilityVerifier {
    key_id: CapabilityKeyId,
    public_key: [u8; 32],
}

impl CapabilityIssuer {
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)?;
        Ok(Self::from_secret_bytes(&mut secret))
    }

    pub fn from_secret_bytes(secret: &mut [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(secret);
        secret.zeroize();
        let key_id = key_id(&key.verifying_key().to_bytes());
        Self { key, key_id }
    }

    pub fn verifier(&self) -> CapabilityVerifier {
        CapabilityVerifier {
            key_id: self.key_id,
            public_key: self.key.verifying_key().to_bytes(),
        }
    }

    pub fn issue(
        &self,
        account_id: AccountId,
        auth_epoch: u64,
        device_id: Option<SyncDeviceId>,
        permissions: Permissions,
        now_unix_ms: i64,
        lifetime_ms: i64,
    ) -> Result<SignedCapability> {
        if lifetime_ms <= 0 || lifetime_ms > MAX_LIFETIME_MS {
            return Err(CapabilityError::Malformed);
        }
        let expires_unix_ms = now_unix_ms.checked_add(lifetime_ms).ok_or(CapabilityError::Malformed)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)?;
        let claims = CapabilityClaims {
            account_id,
            auth_epoch,
            device_id,
            issued_unix_ms: now_unix_ms,
            expires_unix_ms,
            permissions,
            nonce,
        };
        let body = encode_claims(&claims);
        let digest = sign_digest(&self.key_id, &body);
        let signature = self.key.sign(&digest).to_bytes();
        Ok(SignedCapability { key_id: self.key_id, claims, signature })
    }
}

impl CapabilityVerifier {
    pub fn key_id(&self) -> CapabilityKeyId { self.key_id }

    pub fn verify(
        &self,
        capability: &SignedCapability,
        now_unix_ms: i64,
        required: Permissions,
        expected_device: Option<SyncDeviceId>,
        minimum_auth_epoch: Option<u64>,
    ) -> Result<()> {
        if capability.key_id != self.key_id {
            return Err(CapabilityError::Signature);
        }
        if capability.claims.issued_unix_ms > now_unix_ms
            || now_unix_ms > capability.claims.expires_unix_ms
            || capability.claims.expires_unix_ms.saturating_sub(capability.claims.issued_unix_ms) > MAX_LIFETIME_MS
        {
            return Err(CapabilityError::Expired);
        }
        if !capability.claims.permissions.contains(required) {
            return Err(CapabilityError::Permission);
        }
        if let Some(device) = expected_device {
            if capability.claims.device_id != Some(device) {
                return Err(CapabilityError::DeviceMismatch);
            }
        }
        if let Some(epoch) = minimum_auth_epoch {
            if capability.claims.auth_epoch < epoch {
                return Err(CapabilityError::StaleAuthEpoch);
            }
        }
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| CapabilityError::Signature)?;
        let body = encode_claims(&capability.claims);
        let digest = sign_digest(&capability.key_id, &body);
        key.verify_strict(&digest, &Signature::from_bytes(&capability.signature))
            .map_err(|_| CapabilityError::Signature)
    }
}

impl SignedCapability {
    pub fn encode(&self) -> Vec<u8> {
        let body = encode_claims(&self.claims);
        let mut out = Vec::with_capacity(4 + 2 + 16 + BODY_LEN + 64);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.key_id.0);
        out.extend_from_slice(&body);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let expected = 4 + 2 + 16 + BODY_LEN + 64;
        if bytes.len() != expected || &bytes[..4] != MAGIC {
            return Err(CapabilityError::Malformed);
        }
        if u16::from_be_bytes([bytes[4], bytes[5]]) != VERSION {
            return Err(CapabilityError::Malformed);
        }
        let key_id = CapabilityKeyId(bytes[6..22].try_into().map_err(|_| CapabilityError::Malformed)?);
        let claims = decode_claims(&bytes[22..22 + BODY_LEN])?;
        let signature = bytes[22 + BODY_LEN..].try_into().map_err(|_| CapabilityError::Malformed)?;
        Ok(Self { key_id, claims, signature })
    }
}

fn encode_claims(claims: &CapabilityClaims) -> [u8; BODY_LEN] {
    let mut out = [0u8; BODY_LEN];
    let mut pos = 0usize;
    out[pos..pos+16].copy_from_slice(&claims.account_id.0); pos += 16;
    out[pos..pos+8].copy_from_slice(&claims.auth_epoch.to_be_bytes()); pos += 8;
    match claims.device_id {
        Some(id) => { out[pos] = 1; pos += 1; out[pos..pos+16].copy_from_slice(&id.0); }
        None => { out[pos] = 0; pos += 1; }
    }
    pos += 16;
    out[pos..pos+8].copy_from_slice(&claims.issued_unix_ms.to_be_bytes()); pos += 8;
    out[pos..pos+8].copy_from_slice(&claims.expires_unix_ms.to_be_bytes()); pos += 8;
    out[pos..pos+4].copy_from_slice(&claims.permissions.bits().to_be_bytes()); pos += 4;
    out[pos..pos+16].copy_from_slice(&claims.nonce);
    out
}

fn decode_claims(bytes: &[u8]) -> Result<CapabilityClaims> {
    if bytes.len() != BODY_LEN { return Err(CapabilityError::Malformed); }
    let mut pos = 0usize;
    let account_id = AccountId(bytes[pos..pos+16].try_into().map_err(|_| CapabilityError::Malformed)?); pos += 16;
    let auth_epoch = u64::from_be_bytes(bytes[pos..pos+8].try_into().map_err(|_| CapabilityError::Malformed)?); pos += 8;
    let has_device = bytes[pos]; pos += 1;
    let raw_device: [u8;16] = bytes[pos..pos+16].try_into().map_err(|_| CapabilityError::Malformed)?; pos += 16;
    let device_id = match has_device { 0 => None, 1 => Some(SyncDeviceId(raw_device)), _ => return Err(CapabilityError::Malformed) };
    let issued_unix_ms = i64::from_be_bytes(bytes[pos..pos+8].try_into().map_err(|_| CapabilityError::Malformed)?); pos += 8;
    let expires_unix_ms = i64::from_be_bytes(bytes[pos..pos+8].try_into().map_err(|_| CapabilityError::Malformed)?); pos += 8;
    let permissions = Permissions::from_bits(u32::from_be_bytes(bytes[pos..pos+4].try_into().map_err(|_| CapabilityError::Malformed)?)); pos += 4;
    let nonce = bytes[pos..pos+16].try_into().map_err(|_| CapabilityError::Malformed)?;
    Ok(CapabilityClaims { account_id, auth_epoch, device_id, issued_unix_ms, expires_unix_ms, permissions, nonce })
}

fn sign_digest(key_id: &CapabilityKeyId, body: &[u8; BODY_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SIGN_DOMAIN);
    h.update(key_id.0);
    h.update(body);
    h.finalize().into()
}

fn key_id(public: &[u8; 32]) -> CapabilityKeyId {
    let mut h = Sha256::new();
    h.update(KEY_ID_DOMAIN);
    h.update(public);
    let digest = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    CapabilityKeyId(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_is_locally_verifiable() {
        let issuer = CapabilityIssuer::generate().unwrap();
        let verifier = issuer.verifier();
        let account = AccountId([3u8; 16]);
        let device = SyncDeviceId([4u8; 16]);
        let permissions = Permissions::SYNC_RELAY.union(Permissions::MODEL_DOWNLOAD);
        let cap = issuer.issue(account, 7, Some(device), permissions, 1000, 60_000).unwrap();
        verifier.verify(&cap, 2000, Permissions::SYNC_RELAY, Some(device), Some(7)).unwrap();
        let encoded = cap.encode();
        let decoded = SignedCapability::decode(&encoded).unwrap();
        verifier.verify(&decoded, 2000, Permissions::MODEL_DOWNLOAD, Some(device), Some(7)).unwrap();
    }
}
