use jend_core::{AccountRootKey, SealedLocalBlob};
use zeroize::Zeroizing;

use crate::{
    codec::{put_u32, put_u64, Reader}, AccountId, BootstrapPayload, DeviceJoinRequest, DeviceSet,
    DeviceSetHistory, KeyEnvelope, Result, SignedDeviceSet, SyncDeviceIdentity, SyncDevicePublic,
    SignedSyncIndex, SyncEpochSecret, SyncError, SyncKeyring, SyncObjectId,
};

const LOCAL_STATE_CONTEXT: &[u8] = b"JEND-SYNC/LOCAL-STATE/V1";
const LOCAL_STATE_VERSION: u16 = 2;
const MAX_DEVICE_SET_BYTES: usize = 64 * 1024;
const MAX_KEYRING_BYTES: usize = 64 * 1024;
const MAX_DEVICE_HISTORY_BYTES: usize = 2 * 1024 * 1024;

/// Vault-local synchronization state. It must be sealed under the Account Root
/// Key before persistence; raw keyring bytes are never part of a server API.
pub struct LocalSyncState {
    pub account_id: AccountId,
    pub current_device_set: SignedDeviceSet,
    pub device_history: DeviceSetHistory,
    pub keyring: SyncKeyring,
    pub latest_index: Option<SyncObjectId>,
    pub index_generation: u64,
}

impl LocalSyncState {
    pub fn seal_local(&self, ark: &AccountRootKey) -> Result<SealedLocalBlob> {
        let bytes = Zeroizing::new(self.encode_sensitive()?);
        ark.seal_local_metadata(LOCAL_STATE_CONTEXT, bytes.as_ref())
            .map_err(|_| SyncError::Aead)
    }

    pub fn open_local(ark: &AccountRootKey, blob: &SealedLocalBlob) -> Result<Self> {
        let bytes = ark
            .open_local_metadata(LOCAL_STATE_CONTEXT, blob)
            .map_err(|_| SyncError::Aead)?;
        Self::decode_sensitive(bytes.as_ref())
    }

    pub fn stage_join_request(
        &self,
        signer: &SyncDeviceIdentity,
        request: &DeviceJoinRequest,
        now_unix_ms: i64,
    ) -> Result<Self> {
        request.verify(now_unix_ms)?;
        if request.account_id != self.account_id {
            return Err(SyncError::Malformed);
        }
        if self.current_device_set.set.contains(request.candidate.device_id) {
            return Err(SyncError::InvalidDeviceSetTransition);
        }
        let mut devices = self.current_device_set.set.devices.clone();
        devices.push(request.candidate.clone());
        self.stage_device_set_change(signer, devices)
    }

    /// Constructs local state on the newly approved device. The caller must
    /// have authenticated `trusted_existing` out of band and opened the key
    /// envelope with the new device's private key first.
    pub fn from_join_bootstrap(
        approved_set: SignedDeviceSet,
        trusted_existing: &SyncDevicePublic,
        request: &DeviceJoinRequest,
        bootstrap: BootstrapPayload,
    ) -> Result<Self> {
        approved_set.verify_bootstrap_from(trusted_existing)?;
        if approved_set.set.account_id != request.account_id
            || !approved_set.set.contains(request.candidate.device_id)
            || approved_set.set.epoch != bootstrap.envelope_epoch
            || approved_set.hash() != bootstrap.device_set_hash
            || bootstrap.request_binding != request.commitment()
            || !approved_set.set.contains(trusted_existing.device_id)
            || !bootstrap.keyring.contains_epoch(approved_set.set.epoch)
        {
            return Err(SyncError::InvalidDeviceSetTransition);
        }
        let state = Self {
            account_id: approved_set.set.account_id,
            current_device_set: approved_set,
            device_history: bootstrap.device_history,
            keyring: bootstrap.keyring,
            latest_index: bootstrap.latest_index,
            index_generation: bootstrap.index_generation,
        };
        state.validate()?;
        Ok(state)
    }

    /// Builds a new local state for a DeviceSet change without mutating the
    /// current state. The caller can persist the sealed result first and only
    /// then replace the in-memory state.
    pub fn stage_device_set_change(
        &self,
        signer: &SyncDeviceIdentity,
        devices: Vec<SyncDevicePublic>,
    ) -> Result<Self> {
        let signer_public = signer.public_identity();
        if !self.current_device_set.set.contains(signer_public.device_id) {
            return Err(SyncError::UntrustedDevice);
        }
        if !devices.iter().any(|device| device.device_id == signer_public.device_id) {
            // Self-removal is a separate explicit flow because it must wipe
            // local future-sync access after another device confirms commit.
            return Err(SyncError::InvalidDeviceSetTransition);
        }
        let mut current_ids: Vec<_> = self.current_device_set.set.devices.iter().map(|d| d.device_id).collect();
        let mut next_ids: Vec<_> = devices.iter().map(|d| d.device_id).collect();
        current_ids.sort();
        next_ids.sort();
        if current_ids == next_ids {
            return Err(SyncError::InvalidDeviceSetTransition);
        }

        let set = DeviceSet::transition_from(&self.current_device_set, devices)?;
        let signed = SignedDeviceSet::sign_transition(&self.current_device_set, set, signer)?;
        let secret = SyncEpochSecret::generate()?;
        let keyring = self.keyring.staged_with(signed.set.epoch, secret)?;
        let mut device_history = self.device_history.clone();
        device_history.append(signed.clone())?;
        Ok(Self {
            account_id: self.account_id,
            current_device_set: signed,
            device_history,
            keyring,
            latest_index: self.latest_index,
            index_generation: self.index_generation,
        })
    }

    /// Encrypts the authorized historical sync keyring to a currently trusted
    /// recipient device. The server can relay the returned bytes but cannot
    /// open them.
    pub fn bootstrap_envelope(
        &self,
        sender: &SyncDeviceIdentity,
        recipient: &SyncDevicePublic,
    ) -> Result<KeyEnvelope> {
        let sender_id = sender.public_identity().device_id;
        if !self.current_device_set.set.contains(sender_id)
            || !self.current_device_set.set.contains(recipient.device_id)
        {
            return Err(SyncError::UntrustedDevice);
        }
        self.bootstrap_envelope_bound(sender, recipient, [0u8; 32])
    }

    pub fn bootstrap_envelope_bound(
        &self,
        sender: &SyncDeviceIdentity,
        recipient: &SyncDevicePublic,
        request_binding: [u8; 32],
    ) -> Result<KeyEnvelope> {
        let sender_id = sender.public_identity().device_id;
        if !self.current_device_set.set.contains(sender_id)
            || !self.current_device_set.set.contains(recipient.device_id)
        {
            return Err(SyncError::UntrustedDevice);
        }
        KeyEnvelope::seal(
            self.account_id,
            self.current_device_set.set.epoch,
            sender,
            recipient,
            &self.keyring,
            &self.device_history,
            self.current_device_set.hash(),
            request_binding,
            self.latest_index,
            self.index_generation,
        )
    }

    /// Stages acceptance of a decrypted, signed sync index without mutating
    /// local state. Persist the returned state before replacing the live one.
    /// This is the anti-rollback boundary for the untrusted relay.
    pub fn stage_accept_index(
        &self,
        object_id: SyncObjectId,
        signed_index: &SignedSyncIndex,
    ) -> Result<Self> {
        let index = &signed_index.index;
        let historical_set = self
            .device_history
            .get(index.device_set_epoch)
            .ok_or(SyncError::InvalidDeviceSetHistory)?;
        if historical_set.hash() != index.device_set_hash {
            return Err(SyncError::InvalidDeviceSetHistory);
        }
        let signer = historical_set
            .set
            .get(index.author)
            .ok_or(SyncError::UntrustedDevice)?;
        signed_index.verify(signer)?;

        if index.generation < self.index_generation {
            return Err(SyncError::SyncRollback);
        }
        if index.generation == self.index_generation {
            return match self.latest_index {
                Some(existing) if existing == object_id => Ok(self.clone_for_staging()?),
                None if self.index_generation == 0 => {
                    let mut staged = self.clone_for_staging()?;
                    staged.latest_index = Some(object_id);
                    Ok(staged)
                }
                _ => Err(SyncError::SyncIndexFork),
            };
        }

        let mut staged = self.clone_for_staging()?;
        staged.latest_index = Some(object_id);
        staged.index_generation = index.generation;
        Ok(staged)
    }

    fn clone_for_staging(&self) -> Result<Self> {
        // Re-encode/decode intentionally passes through the same canonical
        // sensitive representation used for persistence, avoiding ad-hoc key
        // cloning helpers outside this module.
        let bytes = Zeroizing::new(self.encode_sensitive()?);
        Self::decode_sensitive(bytes.as_ref())
    }

    pub fn validate(&self) -> Result<()> {
        if self.current_device_set.set.account_id != self.account_id
            || !self.keyring.contains_epoch(self.current_device_set.set.epoch)
        {
            return Err(SyncError::Malformed);
        }
        let latest = self
            .device_history
            .latest()
            .ok_or(SyncError::InvalidDeviceSetHistory)?;
        if latest.hash() != self.current_device_set.hash()
            || latest.set.epoch != self.current_device_set.set.epoch
            || latest.set.account_id != self.account_id
        {
            return Err(SyncError::InvalidDeviceSetHistory);
        }
        Ok(())
    }

    fn encode_sensitive(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let set = self.current_device_set.encode()?;
        let history = self.device_history.encode()?;
        let keyring = Zeroizing::new(self.keyring.encode_sensitive());
        if set.len() > MAX_DEVICE_SET_BYTES
            || history.len() > MAX_DEVICE_HISTORY_BYTES
            || keyring.len() > MAX_KEYRING_BYTES
        {
            return Err(SyncError::ObjectTooLarge);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&LOCAL_STATE_VERSION.to_be_bytes());
        out.extend_from_slice(&self.account_id.0);
        put_u32(&mut out, set.len() as u32);
        out.extend_from_slice(&set);
        put_u32(&mut out, history.len() as u32);
        out.extend_from_slice(&history);
        put_u32(&mut out, keyring.len() as u32);
        out.extend_from_slice(keyring.as_ref());
        match self.latest_index {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id.0);
            }
            None => out.push(0),
        }
        put_u64(&mut out, self.index_generation);
        Ok(out)
    }

    fn decode_sensitive(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != LOCAL_STATE_VERSION {
            return Err(SyncError::UnsupportedVersion(version));
        }
        let account_id = AccountId(r.array()?);
        let set_len = r.u32()? as usize;
        if set_len > MAX_DEVICE_SET_BYTES {
            return Err(SyncError::ObjectTooLarge);
        }
        let current_device_set = SignedDeviceSet::decode(r.take(set_len)?)?;
        let history_len = r.u32()? as usize;
        if history_len > MAX_DEVICE_HISTORY_BYTES {
            return Err(SyncError::ObjectTooLarge);
        }
        let device_history = DeviceSetHistory::decode(r.take(history_len)?)?;
        let keyring_len = r.u32()? as usize;
        if keyring_len > MAX_KEYRING_BYTES {
            return Err(SyncError::ObjectTooLarge);
        }
        let keyring_bytes = Zeroizing::new(r.take(keyring_len)?.to_vec());
        let keyring = SyncKeyring::decode_sensitive(keyring_bytes.as_ref())?;
        let latest_index = match r.u8()? {
            0 => None,
            1 => Some(SyncObjectId(r.array()?)),
            _ => return Err(SyncError::Malformed),
        };
        let index_generation = r.u64()?;
        r.finish()?;
        let state = Self {
            account_id,
            current_device_set,
            device_history,
            keyring,
            latest_index,
            index_generation,
        };
        state.validate()?;
        Ok(state)
    }
}
