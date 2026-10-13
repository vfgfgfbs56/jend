use sha2::{Digest, Sha256};

use crate::{
    codec::{put_u16, put_u32, put_u64, Reader}, AccountId, Result, SyncDeviceId, SyncDeviceIdentity,
    SyncDevicePublic, SyncError,
};

const DEVICE_SET_DOMAIN: &[u8] = b"JEND/SYNC-DEVICE-SET/V1";
const DEVICE_SET_HASH_DOMAIN: &[u8] = b"JEND/SYNC-DEVICE-SET-HASH/V1";
const MAX_DEVICES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSet {
    pub account_id: AccountId,
    pub epoch: u64,
    pub previous_hash: [u8; 32],
    pub devices: Vec<SyncDevicePublic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedDeviceSet {
    pub set: DeviceSet,
    pub author: SyncDeviceId,
    pub signature: [u8; 64],
}

impl DeviceSet {
    pub fn genesis(account_id: AccountId, first: SyncDevicePublic) -> Self {
        Self {
            account_id,
            epoch: 0,
            previous_hash: [0u8; 32],
            devices: vec![first],
        }
    }

    pub fn transition_from(previous: &SignedDeviceSet, mut devices: Vec<SyncDevicePublic>) -> Result<Self> {
        canonicalize_devices(&mut devices)?;
        Ok(Self {
            account_id: previous.set.account_id,
            epoch: previous.set.epoch.checked_add(1).ok_or(SyncError::InvalidDeviceSetTransition)?,
            previous_hash: previous.hash(),
            devices,
        })
    }

    pub fn contains(&self, id: SyncDeviceId) -> bool {
        self.devices.iter().any(|device| device.device_id == id)
    }

    pub fn get(&self, id: SyncDeviceId) -> Option<&SyncDevicePublic> {
        self.devices.iter().find(|device| device.device_id == id)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.devices.is_empty() || self.devices.len() > MAX_DEVICES {
            return Err(SyncError::Malformed);
        }
        let mut devices = self.devices.clone();
        canonicalize_devices(&mut devices)?;
        let mut out = Vec::with_capacity(16 + 8 + 32 + 2 + devices.len() * 112);
        out.extend_from_slice(&self.account_id.0);
        put_u64(&mut out, self.epoch);
        out.extend_from_slice(&self.previous_hash);
        put_u16(&mut out, devices.len() as u16);
        for device in devices {
            out.extend_from_slice(&device.device_id.0);
            out.extend_from_slice(&device.signing_public);
            out.extend_from_slice(&device.kex_public);
            out.extend_from_slice(&device.message_signing_public);
        }
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let account_id = AccountId(r.array()?);
        let epoch = r.u64()?;
        let previous_hash = r.array()?;
        let count = r.u16()? as usize;
        if count == 0 || count > MAX_DEVICES {
            return Err(SyncError::Malformed);
        }
        let mut devices = Vec::with_capacity(count);
        for _ in 0..count {
            let claimed_id = SyncDeviceId(r.array()?);
            let signing_public = r.array()?;
            let kex_public = r.array()?;
            let message_signing_public = r.array()?;
            let device = SyncDevicePublic::new(signing_public, kex_public, message_signing_public);
            if device.device_id != claimed_id {
                return Err(SyncError::Malformed);
            }
            devices.push(device);
        }
        r.finish()?;
        if !devices.windows(2).all(|pair| pair[0].device_id < pair[1].device_id) {
            return Err(SyncError::Malformed);
        }
        Ok(Self {
            account_id,
            epoch,
            previous_hash,
            devices,
        })
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes().expect("validated DeviceSet");
        let mut h = Sha256::new();
        h.update(DEVICE_SET_HASH_DOMAIN);
        h.update(bytes);
        h.finalize().into()
    }
}

impl SignedDeviceSet {
    pub fn sign_genesis(set: DeviceSet, signer: &SyncDeviceIdentity) -> Result<Self> {
        if set.epoch != 0 || set.previous_hash != [0u8; 32] {
            return Err(SyncError::InvalidDeviceSetTransition);
        }
        let public = signer.public_identity();
        if !set.contains(public.device_id) || set.devices.len() != 1 {
            return Err(SyncError::InvalidDeviceSetTransition);
        }
        let bytes = set.canonical_bytes()?;
        let signature = signer.sign(DEVICE_SET_DOMAIN, &bytes);
        Ok(Self {
            set,
            author: public.device_id,
            signature,
        })
    }

    pub fn sign_transition(
        previous: &SignedDeviceSet,
        set: DeviceSet,
        signer: &SyncDeviceIdentity,
    ) -> Result<Self> {
        validate_transition_shape(previous, &set)?;
        let public = signer.public_identity();
        if !previous.set.contains(public.device_id) {
            return Err(SyncError::UntrustedDevice);
        }
        let bytes = set.canonical_bytes()?;
        let signature = signer.sign(DEVICE_SET_DOMAIN, &bytes);
        Ok(Self {
            set,
            author: public.device_id,
            signature,
        })
    }

    pub fn verify_genesis(&self) -> Result<()> {
        if self.set.epoch != 0 || self.set.previous_hash != [0u8; 32] || self.set.devices.len() != 1 {
            return Err(SyncError::InvalidDeviceSetTransition);
        }
        let signer = self.set.get(self.author).ok_or(SyncError::UntrustedDevice)?;
        signer.verify(DEVICE_SET_DOMAIN, &self.set.canonical_bytes()?, &self.signature)
    }

    pub fn verify_transition(&self, previous: &SignedDeviceSet) -> Result<()> {
        validate_transition_shape(previous, &self.set)?;
        let signer = previous.set.get(self.author).ok_or(SyncError::UntrustedDevice)?;
        signer.verify(DEVICE_SET_DOMAIN, &self.set.canonical_bytes()?, &self.signature)
    }

    /// Verification used by a newly joining device after it authenticates one
    /// existing device out-of-band (QR/fingerprint). The existing device's
    /// public identity becomes the trust anchor for this bootstrap only.
    pub fn verify_bootstrap_from(&self, trusted_existing: &SyncDevicePublic) -> Result<()> {
        if self.author != trusted_existing.device_id || !self.set.contains(self.author) {
            return Err(SyncError::UntrustedDevice);
        }
        trusted_existing.verify(DEVICE_SET_DOMAIN, &self.set.canonical_bytes()?, &self.signature)
    }

    pub fn hash(&self) -> [u8; 32] {
        self.set.hash()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let set = self.set.canonical_bytes()?;
        let mut out = Vec::with_capacity(4 + set.len() + 16 + 64);
        put_u32(&mut out, set.len() as u32);
        out.extend_from_slice(&set);
        out.extend_from_slice(&self.author.0);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let len = r.u32()? as usize;
        let set = DeviceSet::from_canonical_bytes(r.take(len)?)?;
        let author = SyncDeviceId(r.array()?);
        let signature = r.array()?;
        r.finish()?;
        Ok(Self { set, author, signature })
    }
}

fn validate_transition_shape(previous: &SignedDeviceSet, next: &DeviceSet) -> Result<()> {
    if next.account_id != previous.set.account_id
        || next.epoch != previous.set.epoch.checked_add(1).ok_or(SyncError::InvalidDeviceSetTransition)?
        || next.previous_hash != previous.hash()
        || next.devices.is_empty()
        || next.devices.len() > MAX_DEVICES
    {
        return Err(SyncError::InvalidDeviceSetTransition);
    }
    let mut devices = next.devices.clone();
    canonicalize_devices(&mut devices)?;
    Ok(())
}

fn canonicalize_devices(devices: &mut Vec<SyncDevicePublic>) -> Result<()> {
    devices.sort_by_key(|device| device.device_id);
    if devices.windows(2).any(|pair| pair[0].device_id == pair[1].device_id) {
        return Err(SyncError::Malformed);
    }
    Ok(())
}
