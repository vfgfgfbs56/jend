use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{ids::derive_device_id, Result, SyncDeviceId, SyncError};

const SIGN_DOMAIN: &[u8] = b"JEND/SYNC-SIGNATURE/V1";
const JREQ_SIGNATURE_DOMAIN: &[u8] = b"JEND/JREQ-SIGNATURE/V1";

pub struct SyncDeviceIdentity {
    signing_key: SigningKey,
    kex_secret: Zeroizing<[u8; 32]>,
    message_signing_public: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncDevicePublic {
    pub device_id: SyncDeviceId,
    pub signing_public: [u8; 32],
    pub kex_public: [u8; 32],
    /// Ed25519 public key used by jend-core to sign encrypted message records.
    pub message_signing_public: [u8; 32],
}

impl SyncDeviceIdentity {
    pub fn generate() -> Result<Self> {
        let mut signing = [0u8; 32];
        let mut kex = [0u8; 32];
        getrandom::fill(&mut signing)?;
        getrandom::fill(&mut kex)?;
        let signing_key = SigningKey::from_bytes(&signing);
        signing.zeroize();
        let message_signing_public = signing_key.verifying_key().to_bytes();
        Ok(Self {
            signing_key,
            kex_secret: Zeroizing::new(kex),
            message_signing_public,
        })
    }

    /// Imports Vault/OS-keystore material and clears both caller buffers.
    /// There is intentionally no inverse secret-export API.
    pub fn from_secret_bytes(signing: &mut [u8; 32], kex: &mut [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(signing);
        let message_signing_public = signing_key.verifying_key().to_bytes();
        let kex_secret = Zeroizing::new(*kex);
        signing.zeroize();
        kex.zeroize();
        Self { signing_key, kex_secret, message_signing_public }
    }

    /// Vault constructor binding this sync identity to the independent
    /// jend-core message-signing public key for the same physical device.
    pub fn from_secret_bytes_with_message_key(
        signing: &mut [u8; 32],
        kex: &mut [u8; 32],
        message_signing_public: [u8; 32],
    ) -> Self {
        let signing_key = SigningKey::from_bytes(signing);
        let kex_secret = Zeroizing::new(*kex);
        signing.zeroize();
        kex.zeroize();
        Self { signing_key, kex_secret, message_signing_public }
    }

    /// Signs only JREQ canonical request payloads. This deliberately avoids
    /// exposing a generic arbitrary-message signing API for the device key.
    pub fn sign_jreq_payload(&self, canonical_request: &[u8]) -> [u8; 64] {
        self.sign(JREQ_SIGNATURE_DOMAIN, canonical_request)
    }

    pub fn public_identity(&self) -> SyncDevicePublic {
        let signing_public = self.signing_key.verifying_key().to_bytes();
        let secret = StaticSecret::from(*self.kex_secret);
        let kex_public = X25519PublicKey::from(&secret).to_bytes();
        SyncDevicePublic::new(signing_public, kex_public, self.message_signing_public)
    }

    pub(crate) fn sign(&self, domain: &[u8], bytes: &[u8]) -> [u8; 64] {
        let digest = signing_digest(domain, bytes);
        let mut msg = Vec::with_capacity(SIGN_DOMAIN.len() + digest.len());
        msg.extend_from_slice(SIGN_DOMAIN);
        msg.extend_from_slice(&digest);
        self.signing_key.sign(&msg).to_bytes()
    }

    pub(crate) fn diffie_hellman(&self, peer_kex_public: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(*self.kex_secret);
        let peer = X25519PublicKey::from(*peer_kex_public);
        secret.diffie_hellman(&peer).to_bytes()
    }
}

impl SyncDevicePublic {
    pub fn new(
        signing_public: [u8; 32],
        kex_public: [u8; 32],
        message_signing_public: [u8; 32],
    ) -> Self {
        let device_id = derive_device_id(&signing_public, &kex_public, &message_signing_public);
        Self {
            device_id,
            signing_public,
            kex_public,
            message_signing_public,
        }
    }

    /// Verifies a JREQ canonical request payload using this device identity.
    pub fn verify_jreq_payload(
        &self,
        canonical_request: &[u8],
        signature: &[u8; 64],
    ) -> Result<()> {
        self.verify(JREQ_SIGNATURE_DOMAIN, canonical_request, signature)
    }

    pub fn message_public_identity(&self) -> Result<jend_core::DevicePublicIdentity> {
        jend_core::DevicePublicIdentity::from_bytes(&self.message_signing_public)
            .map_err(SyncError::Core)
    }

    pub(crate) fn verify(&self, domain: &[u8], bytes: &[u8], signature: &[u8; 64]) -> Result<()> {
        if derive_device_id(
            &self.signing_public,
            &self.kex_public,
            &self.message_signing_public,
        ) != self.device_id {
            return Err(SyncError::InvalidSignature);
        }
        let key = VerifyingKey::from_bytes(&self.signing_public)
            .map_err(|_| SyncError::InvalidSignature)?;
        let digest = signing_digest(domain, bytes);
        let mut msg = Vec::with_capacity(SIGN_DOMAIN.len() + digest.len());
        msg.extend_from_slice(SIGN_DOMAIN);
        msg.extend_from_slice(&digest);
        let signature = Signature::from_bytes(signature);
        key.verify_strict(&msg, &signature)
            .map_err(|_| SyncError::InvalidSignature)
    }
}

fn signing_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((domain.len() as u32).to_be_bytes());
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}
