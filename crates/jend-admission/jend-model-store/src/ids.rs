use sha2::{Digest, Sha256};

use crate::Result;

const RELEASE_KEY_ID_DOMAIN: &[u8] = b"JEND/MODEL/RELEASE-KEY-ID/V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ModelId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ModelObjectId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ManifestId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReleaseKeyId(pub [u8; 16]);

impl ModelId {
    pub fn generate() -> Result<Self> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }
}

impl ModelObjectId {
    pub fn generate() -> Result<Self> {
        let mut id = [0u8; 32];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }
}

pub(crate) fn derive_release_key_id(public_key: &[u8; 32]) -> ReleaseKeyId {
    let mut h = Sha256::new();
    h.update(RELEASE_KEY_ID_DOMAIN);
    h.update(public_key);
    let digest = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    ReleaseKeyId(id)
}
