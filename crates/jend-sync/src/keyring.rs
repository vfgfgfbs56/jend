use hkdf::Hkdf;
use jend_core::{ConversationSeed, SyncWrappingKey, WrappedConversationSeed};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, SyncError, SyncObjectId};

const OBJECT_KEY_INFO: &[u8] = b"JEND/SYNC-OBJECT-KEY/V1";
const CONVERSATION_WRAP_KEY_INFO: &[u8] = b"JEND/SYNC-EPOCH/CONVERSATION-WRAP/V1";
const MAX_EPOCH_KEYS: usize = 256;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SyncEpochSecret([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
struct EpochEntry {
    epoch: u64,
    key: [u8; 32],
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
pub struct SyncKeyring {
    entries: Vec<EpochEntry>,
}

impl SyncEpochSecret {
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self(key))
    }

    pub(crate) fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let out = Self(bytes);
        bytes.zeroize();
        out
    }

    pub(crate) fn derive_object_key(&self, object_id: &SyncObjectId) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(&object_id.0), &self.0);
        let mut out = [0u8; 32];
        hk.expand(OBJECT_KEY_INFO, &mut out).map_err(|_| SyncError::Kdf)?;
        Ok(out)
    }

    fn conversation_wrapping_key(&self, conversation_id: &[u8; 16]) -> Result<SyncWrappingKey> {
        let hk = Hkdf::<Sha256>::new(Some(conversation_id), &self.0);
        let mut out = [0u8; 32];
        hk.expand(CONVERSATION_WRAP_KEY_INFO, &mut out)
            .map_err(|_| SyncError::Kdf)?;
        Ok(SyncWrappingKey::from_secret_bytes(&mut out))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SyncKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, epoch: u64, secret: SyncEpochSecret) -> Result<()> {
        if let Some(existing) = self.entries.iter_mut().find(|e| e.epoch == epoch) {
            existing.key.zeroize();
            existing.key.copy_from_slice(secret.as_bytes());
            return Ok(());
        }
        if self.entries.len() >= MAX_EPOCH_KEYS {
            return Err(SyncError::KeyringLimit);
        }
        self.entries.push(EpochEntry {
            epoch,
            key: *secret.as_bytes(),
        });
        self.entries.sort_by_key(|entry| entry.epoch);
        Ok(())
    }

    pub fn wrap_conversation_seed(
        &self,
        epoch: u64,
        conversation_id: &[u8; 16],
        seed: &ConversationSeed,
    ) -> Result<WrappedConversationSeed> {
        self.with_epoch_secret(epoch, |secret| {
            let key = secret.conversation_wrapping_key(conversation_id)?;
            Ok(key.wrap_conversation_seed(conversation_id, seed)?)
        })
    }

    pub fn unwrap_conversation_seed(
        &self,
        epoch: u64,
        conversation_id: &[u8; 16],
        envelope: &WrappedConversationSeed,
    ) -> Result<ConversationSeed> {
        self.with_epoch_secret(epoch, |secret| {
            let key = secret.conversation_wrapping_key(conversation_id)?;
            Ok(key.unwrap_conversation_seed(conversation_id, envelope)?)
        })
    }

    pub fn contains_epoch(&self, epoch: u64) -> bool {
        self.entries.iter().any(|entry| entry.epoch == epoch)
    }

    pub fn newest_epoch(&self) -> Option<u64> {
        self.entries.last().map(|entry| entry.epoch)
    }

    pub(crate) fn staged_with(&self, epoch: u64, secret: SyncEpochSecret) -> Result<Self> {
        let mut staged = Self::new();
        for entry in &self.entries {
            staged.insert(entry.epoch, SyncEpochSecret(entry.key))?;
        }
        staged.insert(epoch, secret)?;
        Ok(staged)
    }

    pub(crate) fn with_epoch_secret<T>(
        &self,
        epoch: u64,
        f: impl FnOnce(&SyncEpochSecret) -> Result<T>,
    ) -> Result<T> {
        let entry = self.entries.iter().find(|entry| entry.epoch == epoch)
            .ok_or(SyncError::MissingEpochKey)?;
        let secret = SyncEpochSecret(entry.key);
        f(&secret)
    }

    pub(crate) fn for_each_newest<T>(
        &self,
        mut f: impl FnMut(u64, &SyncEpochSecret) -> Option<Result<T>>,
    ) -> Option<Result<T>> {
        for entry in self.entries.iter().rev() {
            let secret = SyncEpochSecret(entry.key);
            if let Some(result) = f(entry.epoch, &secret) {
                return Some(result);
            }
        }
        None
    }

    pub(crate) fn encode_sensitive(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.entries.len() * 40);
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(&entry.epoch.to_be_bytes());
            out.extend_from_slice(&entry.key);
        }
        out
    }

    pub(crate) fn decode_sensitive(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(SyncError::Malformed);
        }
        let count = u16::from_be_bytes(bytes[0..2].try_into().map_err(|_| SyncError::Malformed)?) as usize;
        if count > MAX_EPOCH_KEYS || bytes.len() != 2 + count * 40 {
            return Err(SyncError::Malformed);
        }
        let mut ring = Self::new();
        let mut pos = 2;
        for _ in 0..count {
            let epoch = u64::from_be_bytes(bytes[pos..pos + 8].try_into().map_err(|_| SyncError::Malformed)?);
            pos += 8;
            let key: [u8; 32] = bytes[pos..pos + 32].try_into().map_err(|_| SyncError::Malformed)?;
            pos += 32;
            ring.insert(epoch, SyncEpochSecret::from_bytes(key))?;
        }
        Ok(ring)
    }
}
