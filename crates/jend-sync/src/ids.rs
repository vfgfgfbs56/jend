use sha2::{Digest, Sha256};

use crate::Result;

const DEVICE_ID_DOMAIN: &[u8] = b"JEND/SYNC-DEVICE-ID/V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AccountId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SyncDeviceId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SyncObjectId(pub [u8; 32]);

impl AccountId {
    pub fn generate() -> Result<Self> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }
}

impl SyncObjectId {
    pub fn generate() -> Result<Self> {
        let mut id = [0u8; 32];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }
}

pub(crate) fn derive_device_id(
    signing_public: &[u8; 32],
    kex_public: &[u8; 32],
    message_signing_public: &[u8; 32],
) -> SyncDeviceId {
    let mut h = Sha256::new();
    h.update(DEVICE_ID_DOMAIN);
    h.update(signing_public);
    h.update(kex_public);
    h.update(message_signing_public);
    let digest = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    SyncDeviceId(id)
}
