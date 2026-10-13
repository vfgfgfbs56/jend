use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use jend_sync::SyncDeviceId;

use crate::{ManifestId, ModelChunk, ModelId, ModelManifest, ModelObjectId, ModelSlot, ModelStoreError, Result};

const GRANT_DOMAIN: &[u8] = b"JEND/MODEL/DOWNLOAD-GRANT/V1";
const GRANT_MAGIC: &[u8; 4] = b"JMDG";
const GRANT_VERSION: u16 = 1;
const MAX_GRANT_LIFETIME_SECS: u64 = 15 * 60;

pub struct OnlineGrantSigningKey {
    signing_key: SigningKey,
}

#[derive(Clone, Debug)]
pub struct OnlineGrantPublicKey {
    verifying_key: VerifyingKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadGrant {
    pub grant_id: [u8; 16],
    pub device_id: SyncDeviceId,
    pub model_id: ModelId,
    pub manifest_id: ManifestId,
    pub slot: ModelSlot,
    pub entitlement_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl OnlineGrantSigningKey {
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

    pub fn public_key(&self) -> OnlineGrantPublicKey {
        OnlineGrantPublicKey { verifying_key: self.signing_key.verifying_key() }
    }

    pub fn issue(
        &self,
        device_id: SyncDeviceId,
        model_id: ModelId,
        manifest_id: ManifestId,
        slot: ModelSlot,
        entitlement_epoch: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<DownloadGrant> {
        validate_lifetime(issued_at, expires_at)?;
        let mut grant_id = [0u8; 16];
        getrandom::fill(&mut grant_id)?;
        let unsigned = encode_unsigned(
            grant_id,
            device_id,
            model_id,
            manifest_id,
            slot,
            entitlement_epoch,
            issued_at,
            expires_at,
        );
        let signature = self.signing_key.sign(&signature_message(&unsigned)).to_bytes();
        Ok(DownloadGrant {
            grant_id,
            device_id,
            model_id,
            manifest_id,
            slot,
            entitlement_epoch,
            issued_at,
            expires_at,
            signature,
        })
    }
}

impl OnlineGrantPublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes).map_err(|_| ModelStoreError::InvalidSignature)?;
        Ok(Self { verifying_key })
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn verify(&self, grant: &DownloadGrant, now: u64) -> Result<()> {
        validate_lifetime(grant.issued_at, grant.expires_at)?;
        if now < grant.issued_at {
            return Err(ModelStoreError::GrantNotYetValid);
        }
        if now > grant.expires_at {
            return Err(ModelStoreError::GrantExpired);
        }
        let unsigned = grant.unsigned_bytes();
        let signature = Signature::from_bytes(&grant.signature);
        self.verifying_key
            .verify_strict(&signature_message(&unsigned), &signature)
            .map_err(|_| ModelStoreError::InvalidSignature)
    }

    /// Verifies both the online grant and its binding to one object listed in
    /// the signed model manifest. An edge/CDN adapter should call this before
    /// serving bytes from the object store.
    pub fn authorize_object<'a>(
        &self,
        grant: &DownloadGrant,
        manifest: &'a ModelManifest,
        object_id: ModelObjectId,
        now: u64,
    ) -> Result<&'a ModelChunk> {
        self.verify(grant, now)?;
        if grant.model_id != manifest.model_id || grant.manifest_id != manifest.manifest_id()? {
            return Err(ModelStoreError::GrantBindingMismatch);
        }
        manifest
            .chunk_by_object_id(object_id)
            .map_err(|_| ModelStoreError::GrantBindingMismatch)
    }
}

impl DownloadGrant {
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        encode_unsigned(
            self.grant_id,
            self.device_id,
            self.model_id,
            self.manifest_id,
            self.slot,
            self.entitlement_epoch,
            self.issued_at,
            self.expires_at,
        )
    }

    pub fn encode_wire(&self) -> Vec<u8> {
        let mut out = self.unsigned_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        const UNSIGNED_LEN: usize = 4 + 2 + 16 + 16 + 16 + 32 + 1 + 8 + 8 + 8;
        const WIRE_LEN: usize = UNSIGNED_LEN + 64;
        if bytes.len() != WIRE_LEN || &bytes[..4] != GRANT_MAGIC {
            return Err(ModelStoreError::InvalidGrant);
        }
        let mut pos = 4;
        let version = u16::from_be_bytes(take_array::<2>(bytes, &mut pos)?);
        if version != GRANT_VERSION {
            return Err(ModelStoreError::InvalidGrant);
        }
        let grant_id = take_array(bytes, &mut pos)?;
        let device_id = SyncDeviceId(take_array(bytes, &mut pos)?);
        let model_id = ModelId(take_array(bytes, &mut pos)?);
        let manifest_id = ManifestId(take_array(bytes, &mut pos)?);
        let slot = ModelSlot::new(take_array::<1>(bytes, &mut pos)?[0])?;
        let entitlement_epoch = u64::from_be_bytes(take_array(bytes, &mut pos)?);
        let issued_at = u64::from_be_bytes(take_array(bytes, &mut pos)?);
        let expires_at = u64::from_be_bytes(take_array(bytes, &mut pos)?);
        let signature = take_array(bytes, &mut pos)?;
        if pos != bytes.len() { return Err(ModelStoreError::InvalidGrant); }
        validate_lifetime(issued_at, expires_at)?;
        Ok(Self {
            grant_id,
            device_id,
            model_id,
            manifest_id,
            slot,
            entitlement_epoch,
            issued_at,
            expires_at,
            signature,
        })
    }
}

fn validate_lifetime(issued_at: u64, expires_at: u64) -> Result<()> {
    let lifetime = expires_at.checked_sub(issued_at).ok_or(ModelStoreError::InvalidGrant)?;
    if lifetime == 0 || lifetime > MAX_GRANT_LIFETIME_SECS {
        return Err(ModelStoreError::GrantLifetimeTooLong);
    }
    Ok(())
}

fn encode_unsigned(
    grant_id: [u8; 16],
    device_id: SyncDeviceId,
    model_id: ModelId,
    manifest_id: ManifestId,
    slot: ModelSlot,
    entitlement_epoch: u64,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(111);
    out.extend_from_slice(GRANT_MAGIC);
    out.extend_from_slice(&GRANT_VERSION.to_be_bytes());
    out.extend_from_slice(&grant_id);
    out.extend_from_slice(&device_id.0);
    out.extend_from_slice(&model_id.0);
    out.extend_from_slice(&manifest_id.0);
    out.push(slot.as_u8());
    out.extend_from_slice(&entitlement_epoch.to_be_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out
}

fn signature_message(unsigned: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(GRANT_DOMAIN.len() + unsigned.len());
    out.extend_from_slice(GRANT_DOMAIN);
    out.extend_from_slice(unsigned);
    out
}

fn take_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    let end = pos.checked_add(N).ok_or(ModelStoreError::Overflow)?;
    if end > bytes.len() { return Err(ModelStoreError::InvalidGrant); }
    let out = bytes[*pos..end].try_into().map_err(|_| ModelStoreError::InvalidGrant)?;
    *pos = end;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_is_short_lived_and_tamper_evident() {
        let key = OnlineGrantSigningKey::generate().unwrap();
        let public = key.public_key();
        let grant = key.issue(
            SyncDeviceId([1u8; 16]),
            ModelId([2u8; 16]),
            ManifestId([3u8; 32]),
            ModelSlot::ONE,
            9,
            100,
            400,
        ).unwrap();
        public.verify(&grant, 200).unwrap();
        let mut wire = grant.encode_wire();
        wire[30] ^= 1;
        let tampered = DownloadGrant::decode_wire(&wire).unwrap();
        assert!(public.verify(&tampered, 200).is_err());
    }
}
