use std::collections::BTreeMap;

use crate::{Result, SignedDeviceSet, SyncDevicePublic, SyncError};

/// Client-held, encrypted history of the account's DeviceSet transitions.
///
/// This history is not a server trust root. It is carried inside JESP
/// ciphertext / Vault-local sealed state and lets old message signatures stay
/// verifiable after a device is later revoked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceSetHistory {
    by_epoch: BTreeMap<u64, SignedDeviceSet>,
}

impl DeviceSetHistory {
    pub fn from_genesis(genesis: SignedDeviceSet) -> Result<Self> {
        genesis.verify_genesis()?;
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(0, genesis);
        Ok(Self { by_epoch })
    }

    pub fn append(&mut self, next: SignedDeviceSet) -> Result<()> {
        let expected_epoch = self
            .by_epoch
            .last_key_value()
            .map(|(epoch, _)| epoch.checked_add(1).ok_or(SyncError::InvalidDeviceSetHistory))
            .transpose()?
            .ok_or(SyncError::InvalidDeviceSetHistory)?;
        if next.set.epoch != expected_epoch || self.by_epoch.contains_key(&next.set.epoch) {
            return Err(SyncError::InvalidDeviceSetHistory);
        }
        let previous = self
            .by_epoch
            .get(&(expected_epoch - 1))
            .ok_or(SyncError::InvalidDeviceSetHistory)?;
        next.verify_transition(previous)?;
        self.by_epoch.insert(next.set.epoch, next);
        Ok(())
    }

    pub fn get(&self, epoch: u64) -> Option<&SignedDeviceSet> {
        self.by_epoch.get(&epoch)
    }

    pub fn trusted_device(&self, epoch: u64, id: crate::SyncDeviceId) -> Result<&SyncDevicePublic> {
        self.by_epoch
            .get(&epoch)
            .ok_or(SyncError::InvalidDeviceSetHistory)?
            .set
            .get(id)
            .ok_or(SyncError::UntrustedDevice)
    }

    pub fn latest(&self) -> Option<&SignedDeviceSet> {
        self.by_epoch.last_key_value().map(|(_, set)| set)
    }

    pub fn len(&self) -> usize {
        self.by_epoch.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_epoch.is_empty()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.by_epoch.len() > u16::MAX as usize {
            return Err(SyncError::ObjectTooLarge);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(self.by_epoch.len() as u16).to_be_bytes());
        for (epoch, set) in &self.by_epoch {
            if set.set.epoch != *epoch {
                return Err(SyncError::InvalidDeviceSetHistory);
            }
            let encoded = set.encode()?;
            if encoded.len() > u32::MAX as usize {
                return Err(SyncError::ObjectTooLarge);
            }
            out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            out.extend_from_slice(&encoded);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(SyncError::Malformed);
        }
        let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if count == 0 {
            return Err(SyncError::InvalidDeviceSetHistory);
        }
        let mut pos = 2usize;
        let mut decoded = Vec::with_capacity(count);
        for _ in 0..count {
            let end = pos.checked_add(4).ok_or(SyncError::Malformed)?;
            if end > bytes.len() { return Err(SyncError::Malformed); }
            let len = u32::from_be_bytes(bytes[pos..end].try_into().map_err(|_| SyncError::Malformed)?) as usize;
            pos = end;
            let end = pos.checked_add(len).ok_or(SyncError::Malformed)?;
            if end > bytes.len() { return Err(SyncError::Malformed); }
            decoded.push(SignedDeviceSet::decode(&bytes[pos..end])?);
            pos = end;
        }
        if pos != bytes.len() { return Err(SyncError::Malformed); }
        let mut iter = decoded.into_iter();
        let genesis = iter.next().ok_or(SyncError::InvalidDeviceSetHistory)?;
        let mut history = Self::from_genesis(genesis)?;
        for set in iter { history.append(set)?; }
        Ok(history)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SignedDeviceSet> {
        self.by_epoch.values()
    }
}
