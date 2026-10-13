#![forbid(unsafe_code)]
//! JREQ v1: request-bound Ed25519 proof of possession.
//! Callers must authenticate JCAP, resolve the current trusted DeviceSet,
//! and atomically consume the nonce before executing the operation.

use jend_sync::{SyncDeviceIdentity, SyncDevicePublic};
use sha2::{Digest, Sha256};

pub const MAX_PATH: usize = 2048;
pub const MAX_METHOD: usize = 12;
pub const CLOCK_SKEW_MS: u64 = 120_000;
pub const NONCE_TTL_MS: u64 = 300_000;

const MAGIC: &[u8; 4] = b"JREQ";
const VERSION: u16 = 1;
const PROOF_LEN: usize = 4 + 2 + 16 + 32 + 8 + 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub device_id: [u8; 16],
    pub nonce: [u8; 32],
    pub timestamp_ms: u64,
    pub signature: [u8; 64],
}

impl Proof {
    pub fn encode(&self) -> [u8; PROOF_LEN] {
        let mut out = [0u8; PROOF_LEN];
        let mut p = 0usize;
        out[p..p+4].copy_from_slice(MAGIC); p += 4;
        out[p..p+2].copy_from_slice(&VERSION.to_be_bytes()); p += 2;
        out[p..p+16].copy_from_slice(&self.device_id); p += 16;
        out[p..p+32].copy_from_slice(&self.nonce); p += 32;
        out[p..p+8].copy_from_slice(&self.timestamp_ms.to_be_bytes()); p += 8;
        out[p..p+64].copy_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PROOF_LEN || &bytes[..4] != MAGIC {
            return Err(Error::InvalidRequest);
        }
        let version = u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| Error::InvalidRequest)?);
        if version != VERSION {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            device_id: bytes[6..22].try_into().map_err(|_| Error::InvalidRequest)?,
            nonce: bytes[22..54].try_into().map_err(|_| Error::InvalidRequest)?,
            timestamp_ms: u64::from_be_bytes(bytes[54..62].try_into().map_err(|_| Error::InvalidRequest)?),
            signature: bytes[62..126].try_into().map_err(|_| Error::InvalidRequest)?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid canonical request")]
    InvalidRequest,
    #[error("timestamp outside allowed window")]
    Stale,
    #[error("invalid device signature")]
    Signature,
}

#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub method: &'a str,
    /// Exact path and query as sent over the wire; no fragments.
    pub path_and_query: &'a str,
    pub body: &'a [u8],
    /// SHA256 of the *entire* serialized JCAP token.
    pub capability_digest: [u8; 32],
    pub device_id: [u8; 16],
    pub nonce: [u8; 32],
    pub timestamp_ms: u64,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn signing_bytes(req: &Request<'_>) -> Result<Vec<u8>, Error> {
    if req.method.is_empty() || req.method.len() > MAX_METHOD ||
        !req.method.bytes().all(|c| c.is_ascii_uppercase()) ||
        req.path_and_query.is_empty() || req.path_and_query.len() > MAX_PATH ||
        !req.path_and_query.starts_with('/') ||
        req.path_and_query.contains('#') ||
        req.path_and_query.bytes().any(|c| c == b'\r' || c == b'\n')
    {
        return Err(Error::InvalidRequest);
    }
    let mut out = Vec::with_capacity(128 + req.path_and_query.len());
    out.extend_from_slice(b"JEND/JREQ/v1\0");
    out.push(req.method.len() as u8);
    out.extend_from_slice(req.method.as_bytes());
    out.extend_from_slice(&(req.path_and_query.len() as u16).to_be_bytes());
    out.extend_from_slice(req.path_and_query.as_bytes());
    out.extend_from_slice(&sha256(req.body));
    out.extend_from_slice(&req.capability_digest);
    out.extend_from_slice(&req.device_id);
    out.extend_from_slice(&req.nonce);
    out.extend_from_slice(&req.timestamp_ms.to_be_bytes());
    Ok(out)
}

pub fn sign(req: &Request<'_>, device: &SyncDeviceIdentity) -> Result<Proof, Error> {
    if req.device_id != device.public_identity().device_id.0 {
        return Err(Error::InvalidRequest);
    }
    let canonical = signing_bytes(req)?;
    Ok(Proof {
        device_id: req.device_id,
        nonce: req.nonce,
        timestamp_ms: req.timestamp_ms,
        signature: device.sign_jreq_payload(&canonical),
    })
}

pub fn verify(
    req: &Request<'_>,
    signature_bytes: &[u8; 64],
    device: &SyncDevicePublic,
    server_time_ms: u64,
) -> Result<(), Error> {
    if req.timestamp_ms.abs_diff(server_time_ms) > CLOCK_SKEW_MS {
        return Err(Error::Stale);
    }
    if req.device_id != device.device_id.0 {
        return Err(Error::Signature);
    }
    let canonical = signing_bytes(req)?;
    device.verify_jreq_payload(&canonical, signature_bytes)
        .map_err(|_| Error::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changes_to_request_change_signed_payload() {
        let digest = [3u8;32];
        let base = Request {
            method: "POST", path_and_query: "/v1/sync?a=1", body: b"hello",
            capability_digest: digest, device_id: [1;16],
            nonce: [2;32], timestamp_ms: 42,
        };
        let a = signing_bytes(&base).unwrap();
        let modified = Request { body: b"goodbye", ..base };
        assert_ne!(a, signing_bytes(&modified).unwrap());
    }
    #[test]
    fn signed_proof_verifies_for_same_device() {
        let device = SyncDeviceIdentity::generate().unwrap();
        let req = Request {
            method: "POST", path_and_query: "/v1/test", body: b"abc",
            capability_digest: [9;32],
            device_id: device.public_identity().device_id.0,
            nonce: [7;32], timestamp_ms: 1000,
        };
        let proof = sign(&req, &device).unwrap();
        verify(&req, &proof.signature, &device.public_identity(), 1000).unwrap();
    }

    #[test]
    fn proof_roundtrip() {
        let proof = Proof {
            device_id: [1;16], nonce: [2;32], timestamp_ms: 123,
            signature: [3;64],
        };
        assert_eq!(Proof::decode(&proof.encode()).unwrap(), proof);
    }

    #[test]
    fn rejects_body_and_capability_tampering() {
        let device = SyncDeviceIdentity::generate().unwrap();
        let req = Request {
            method: "POST", path_and_query: "/v1/devices/set", body: b"original",
            capability_digest: [5; 32],
            device_id: device.public_identity().device_id.0,
            nonce: [7; 32], timestamp_ms: 1000,
        };
        let proof = sign(&req, &device).unwrap();
        let tampered_body = Request { body: b"tampered", ..req };
        assert!(verify(&tampered_body, &proof.signature, &device.public_identity(), 1000).is_err());
        let tampered_cap = Request { capability_digest: [6; 32], ..req };
        assert!(verify(&tampered_cap, &proof.signature, &device.public_identity(), 1000).is_err());
    }

    #[test]
    fn rejects_expired_and_wrong_device() {
        let device = SyncDeviceIdentity::generate().unwrap();
        let other = SyncDeviceIdentity::generate().unwrap();
        let req = Request {
            method: "GET", path_and_query: "/v1/devices/current", body: b"",
            capability_digest: [5; 32],
            device_id: device.public_identity().device_id.0,
            nonce: [7; 32], timestamp_ms: 1000,
        };
        let proof = sign(&req, &device).unwrap();
        assert!(matches!(verify(&req, &proof.signature, &device.public_identity(), 1000 + CLOCK_SKEW_MS + 1), Err(Error::Stale)));
        assert!(verify(&req, &proof.signature, &other.public_identity(), 1000).is_err());
    }

    #[test]
    fn rejects_noncanonical_inputs() {
        let req = Request {
            method: "post", path_and_query: "/v1/sync", body: b"",
            capability_digest: [0;32], device_id: [0;16],
            nonce: [0;32], timestamp_ms: 0,
        };
        assert!(signing_bytes(&req).is_err());
    }
}
