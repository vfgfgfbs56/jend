use sha2::{Digest, Sha256};

use crate::{
    codec::{put_i64, Reader}, AccountId, Result, SyncDeviceIdentity, SyncDevicePublic, SyncError,
};

const JOIN_DOMAIN: &[u8] = b"JEND/SYNC-JOIN-REQUEST/V1";
const FINGERPRINT_DOMAIN: &[u8] = b"JEND/SYNC-PAIRING-FINGERPRINT/V1";
const MAX_JOIN_LIFETIME_MS: i64 = 15 * 60 * 1000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceJoinRequest {
    pub account_id: AccountId,
    pub candidate: SyncDevicePublic,
    pub nonce: [u8; 32],
    pub expires_unix_ms: i64,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingFingerprint(pub [u8; 8]);

impl DeviceJoinRequest {
    pub fn create(
        account_id: AccountId,
        candidate: &SyncDeviceIdentity,
        now_unix_ms: i64,
    ) -> Result<Self> {
        let expires_unix_ms = now_unix_ms
            .checked_add(MAX_JOIN_LIFETIME_MS)
            .ok_or(SyncError::Malformed)?;
        let public = candidate.public_identity();
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce)?;
        let unsigned = encode_unsigned(account_id, &public, &nonce, expires_unix_ms);
        let signature = candidate.sign(JOIN_DOMAIN, &unsigned);
        Ok(Self {
            account_id,
            candidate: public,
            nonce,
            expires_unix_ms,
            signature,
        })
    }

    pub fn verify(&self, now_unix_ms: i64) -> Result<()> {
        if now_unix_ms > self.expires_unix_ms
            || self.expires_unix_ms.saturating_sub(now_unix_ms) > MAX_JOIN_LIFETIME_MS
        {
            return Err(SyncError::Malformed);
        }
        self.candidate.verify(
            JOIN_DOMAIN,
            &encode_unsigned(
                self.account_id,
                &self.candidate,
                &self.nonce,
                self.expires_unix_ms,
            ),
            &self.signature,
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_unsigned(
            self.account_id,
            &self.candidate,
            &self.nonce,
            self.expires_unix_ms,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let account_id = AccountId(r.array()?);
        let claimed_device_id = crate::SyncDeviceId(r.array()?);
        let signing_public = r.array()?;
        let kex_public = r.array()?;
        let message_signing_public = r.array()?;
        let candidate = SyncDevicePublic::new(signing_public, kex_public, message_signing_public);
        if candidate.device_id != claimed_device_id {
            return Err(SyncError::Malformed);
        }
        let nonce = r.array()?;
        let expires_unix_ms = r.i64()?;
        let signature = r.array()?;
        r.finish()?;
        Ok(Self {
            account_id,
            candidate,
            nonce,
            expires_unix_ms,
            signature,
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(JOIN_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }

    /// 64-bit out-of-band comparison value. Preferred UX is a direct QR scan;
    /// this formatted fingerprint is the fallback manual comparison.
    pub fn pairing_fingerprint(&self, trusted_existing_device: &SyncDevicePublic) -> PairingFingerprint {
        let mut h = Sha256::new();
        h.update(FINGERPRINT_DOMAIN);
        h.update(trusted_existing_device.device_id.0);
        h.update(trusted_existing_device.signing_public);
        h.update(trusted_existing_device.kex_public);
        h.update(self.encode());
        let digest = h.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        PairingFingerprint(out)
    }
}

impl PairingFingerprint {
    pub fn display(&self) -> String {
        const LUT: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = String::with_capacity(19);
        for (i, byte) in self.0.iter().enumerate() {
            if i != 0 && i % 2 == 0 {
                out.push('-');
            }
            out.push(LUT[(byte >> 4) as usize] as char);
            out.push(LUT[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

fn encode_unsigned(
    account_id: AccountId,
    candidate: &SyncDevicePublic,
    nonce: &[u8; 32],
    expires_unix_ms: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 16 + 32 + 32 + 32 + 32 + 8);
    out.extend_from_slice(&account_id.0);
    out.extend_from_slice(&candidate.device_id.0);
    out.extend_from_slice(&candidate.signing_public);
    out.extend_from_slice(&candidate.kex_public);
    out.extend_from_slice(&candidate.message_signing_public);
    out.extend_from_slice(nonce);
    put_i64(&mut out, expires_unix_ms);
    out
}
