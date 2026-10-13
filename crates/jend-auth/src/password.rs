use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AuthError, Result};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitivePassword(Vec<u8>);

impl SensitivePassword {
    pub const MIN_CHARS: usize = 12;
    pub const MAX_BYTES: usize = 256;

    pub fn from_utf8(password: &str) -> Result<Self> {
        if password.chars().count() < Self::MIN_CHARS || password.len() > Self::MAX_BYTES {
            return Err(AuthError::InvalidPassword);
        }
        Ok(Self(password.as_bytes().to_vec()))
    }

    pub(crate) fn from_high_entropy_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() < 16 || secret.len() > Self::MAX_BYTES {
            return Err(AuthError::InvalidPassword);
        }
        Ok(Self(secret.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SensitivePassword {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SensitivePassword")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}
