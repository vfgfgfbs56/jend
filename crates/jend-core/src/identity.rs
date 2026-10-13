use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{JendError, Result};

const KEY_ID_DOMAIN: &[u8] = b"JEND/DEVICE-KEY-ID/V1";
const SIGNATURE_DOMAIN: &[u8] = b"JEND/SIGNATURE/V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceKeyId(pub [u8; 16]);

pub struct DeviceIdentity {
    signing_key: SigningKey,
}

#[derive(Clone, Debug)]
pub struct DevicePublicIdentity {
    verifying_key: VerifyingKey,
    key_id: DeviceKeyId,
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret)?;
        Ok(Self::from_secret_bytes(&mut secret))
    }

    /// Imports a device signing secret and clears the caller-provided bytes.
    /// There is intentionally no inverse secret-export operation.
    pub fn from_secret_bytes(secret: &mut [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        secret.zeroize();
        Self { signing_key }
    }

    pub fn public_identity(&self) -> DevicePublicIdentity {
        DevicePublicIdentity::new(self.signing_key.verifying_key())
    }

    pub(crate) fn sign_commitment(&self, commitment: &[u8; 32]) -> [u8; 64] {
        let mut msg = Vec::with_capacity(SIGNATURE_DOMAIN.len() + commitment.len());
        msg.extend_from_slice(SIGNATURE_DOMAIN);
        msg.extend_from_slice(commitment);
        self.signing_key.sign(&msg).to_bytes()
    }
}

impl DevicePublicIdentity {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes).map_err(|_| JendError::InvalidSignature)?;
        Ok(Self::new(verifying_key))
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn key_id(&self) -> DeviceKeyId {
        self.key_id
    }

    pub(crate) fn verify_commitment(
        &self,
        claimed_key_id: DeviceKeyId,
        commitment: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<()> {
        if self.key_id != claimed_key_id {
            return Err(JendError::SignerMismatch);
        }

        let mut msg = Vec::with_capacity(SIGNATURE_DOMAIN.len() + commitment.len());
        msg.extend_from_slice(SIGNATURE_DOMAIN);
        msg.extend_from_slice(commitment);

        let signature = Signature::from_bytes(signature);
        self.verifying_key
            .verify_strict(&msg, &signature)
            .map_err(|_| JendError::InvalidSignature)
    }

    fn new(verifying_key: VerifyingKey) -> Self {
        let key_id = derive_key_id(&verifying_key);
        Self {
            verifying_key,
            key_id,
        }
    }
}

fn derive_key_id(key: &VerifyingKey) -> DeviceKeyId {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    DeviceKeyId(id)
}
