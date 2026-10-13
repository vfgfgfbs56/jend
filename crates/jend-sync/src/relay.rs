use std::collections::BTreeSet;

use crate::{
    codec::{put_i64, put_u32, put_u64, Reader}, Result, SyncDeviceId, SyncDeviceIdentity,
    SyncDevicePublic, SyncError, SyncObjectId,
};

const ACK_DOMAIN: &[u8] = b"JEND/RELAY-ACK/V1";
const MAX_RELAY_BLOB: usize = 16 * 1024 * 1024;
const MAX_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RelayMailboxId(pub [u8; 32]);

/// Minimal server-visible relay envelope. `blob` is expected to be an already
/// encrypted JESP object/envelope; the relay never parses it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayUpload {
    pub mailbox_id: RelayMailboxId,
    pub object_id: SyncObjectId,
    pub device_set_epoch: u64,
    pub expires_unix_ms: i64,
    pub blob: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAck {
    pub mailbox_id: RelayMailboxId,
    pub object_id: SyncObjectId,
    pub device_set_epoch: u64,
    pub device_id: SyncDeviceId,
    pub ack_nonce: [u8; 32],
    pub signature: [u8; 64],
}

impl RelayMailboxId {
    pub fn generate() -> Result<Self> {
        let mut id = [0u8; 32];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }
}

impl RelayUpload {
    pub fn new(
        mailbox_id: RelayMailboxId,
        object_id: SyncObjectId,
        device_set_epoch: u64,
        now_unix_ms: i64,
        ttl_ms: i64,
        blob: Vec<u8>,
    ) -> Result<Self> {
        if ttl_ms <= 0 || ttl_ms > MAX_TTL_MS || blob.len() > MAX_RELAY_BLOB {
            return Err(SyncError::Malformed);
        }
        let expires_unix_ms = now_unix_ms.checked_add(ttl_ms).ok_or(SyncError::Malformed)?;
        Ok(Self {
            mailbox_id,
            object_id,
            device_set_epoch,
            expires_unix_ms,
            blob,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.blob.len() > MAX_RELAY_BLOB || self.blob.len() > u32::MAX as usize {
            return Err(SyncError::ObjectTooLarge);
        }
        let mut out = Vec::with_capacity(32 + 32 + 8 + 8 + 4 + self.blob.len());
        out.extend_from_slice(&self.mailbox_id.0);
        out.extend_from_slice(&self.object_id.0);
        put_u64(&mut out, self.device_set_epoch);
        put_i64(&mut out, self.expires_unix_ms);
        put_u32(&mut out, self.blob.len() as u32);
        out.extend_from_slice(&self.blob);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let mailbox_id = RelayMailboxId(r.array()?);
        let object_id = SyncObjectId(r.array()?);
        let device_set_epoch = r.u64()?;
        let expires_unix_ms = r.i64()?;
        let len = r.u32()? as usize;
        if len > MAX_RELAY_BLOB {
            return Err(SyncError::ObjectTooLarge);
        }
        let blob = r.take(len)?.to_vec();
        r.finish()?;
        Ok(Self {
            mailbox_id,
            object_id,
            device_set_epoch,
            expires_unix_ms,
            blob,
        })
    }
}

impl RelayAck {
    pub fn sign(
        mailbox_id: RelayMailboxId,
        object_id: SyncObjectId,
        device_set_epoch: u64,
        device: &SyncDeviceIdentity,
    ) -> Result<Self> {
        let public = device.public_identity();
        let mut ack_nonce = [0u8; 32];
        getrandom::fill(&mut ack_nonce)?;
        let unsigned = encode_ack_unsigned(
            mailbox_id,
            object_id,
            device_set_epoch,
            public.device_id,
            ack_nonce,
        );
        let signature = device.sign(ACK_DOMAIN, &unsigned);
        Ok(Self {
            mailbox_id,
            object_id,
            device_set_epoch,
            device_id: public.device_id,
            ack_nonce,
            signature,
        })
    }

    pub fn verify(&self, device: &SyncDevicePublic) -> Result<()> {
        if device.device_id != self.device_id {
            return Err(SyncError::UntrustedDevice);
        }
        device.verify(
            ACK_DOMAIN,
            &encode_ack_unsigned(
                self.mailbox_id,
                self.object_id,
                self.device_set_epoch,
                self.device_id,
                self.ack_nonce,
            ),
            &self.signature,
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_ack_unsigned(
            self.mailbox_id,
            self.object_id,
            self.device_set_epoch,
            self.device_id,
            self.ack_nonce,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let mailbox_id = RelayMailboxId(r.array()?);
        let object_id = SyncObjectId(r.array()?);
        let device_set_epoch = r.u64()?;
        let device_id = SyncDeviceId(r.array()?);
        let ack_nonce = r.array()?;
        let signature = r.array()?;
        r.finish()?;
        Ok(Self {
            mailbox_id,
            object_id,
            device_set_epoch,
            device_id,
            ack_nonce,
            signature,
        })
    }
}

/// Honest-relay deletion rule. A malicious relay can always delete data early
/// (availability attack), but it cannot forge a trusted device ACK.
pub fn all_devices_acked(
    active_devices: impl IntoIterator<Item = SyncDeviceId>,
    object_id: SyncObjectId,
    device_set_epoch: u64,
    acks: &[RelayAck],
) -> bool {
    let required: BTreeSet<_> = active_devices.into_iter().collect();
    if required.is_empty() {
        return false;
    }
    let received: BTreeSet<_> = acks
        .iter()
        .filter(|ack| ack.object_id == object_id && ack.device_set_epoch == device_set_epoch)
        .map(|ack| ack.device_id)
        .collect();
    required.is_subset(&received)
}

fn encode_ack_unsigned(
    mailbox_id: RelayMailboxId,
    object_id: SyncObjectId,
    device_set_epoch: u64,
    device_id: SyncDeviceId,
    ack_nonce: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 8 + 16 + 32);
    out.extend_from_slice(&mailbox_id.0);
    out.extend_from_slice(&object_id.0);
    put_u64(&mut out, device_set_epoch);
    out.extend_from_slice(&device_id.0);
    out.extend_from_slice(&ack_nonce);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ack_is_device_signed() {
        let a = SyncDeviceIdentity::generate().unwrap();
        let ack = RelayAck::sign(
            RelayMailboxId::generate().unwrap(),
            SyncObjectId::generate().unwrap(),
            7,
            &a,
        )
        .unwrap();
        ack.verify(&a.public_identity()).unwrap();
    }
}
