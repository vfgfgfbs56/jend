use crate::{codec::{put_i64, Reader}, AccountId, Result, SyncDeviceId, SyncDeviceIdentity, SyncDevicePublic, SyncError};

const SESSION_PROOF_DOMAIN: &[u8] = b"JEND/DEVICE-SESSION-PROOF/V1";
const MAX_CHALLENGE_LIFETIME_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSessionChallenge {
    pub account_id: AccountId,
    pub nonce: [u8; 32],
    /// Binds the proof to the post-OPAQUE account capability/session.
    pub session_binding: [u8; 16],
    pub expires_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSessionProof {
    pub device_id: SyncDeviceId,
    pub signature: [u8; 64],
}

impl DeviceSessionChallenge {
    pub fn generate(
        account_id: AccountId,
        session_binding: [u8; 16],
        now_unix_ms: i64,
    ) -> Result<Self> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce)?;
        let expires_unix_ms = now_unix_ms
            .checked_add(MAX_CHALLENGE_LIFETIME_MS)
            .ok_or(SyncError::Malformed)?;
        Ok(Self { account_id, nonce, session_binding, expires_unix_ms })
    }

    pub fn validate_time(&self, now_unix_ms: i64) -> Result<()> {
        if now_unix_ms > self.expires_unix_ms
            || self.expires_unix_ms.saturating_sub(now_unix_ms) > MAX_CHALLENGE_LIFETIME_MS
        {
            return Err(SyncError::Malformed);
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 32 + 16 + 8);
        out.extend_from_slice(&self.account_id.0);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.session_binding);
        put_i64(&mut out, self.expires_unix_ms);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let account_id = AccountId(r.array()?);
        let nonce = r.array()?;
        let session_binding = r.array()?;
        let expires_unix_ms = r.i64()?;
        r.finish()?;
        Ok(Self { account_id, nonce, session_binding, expires_unix_ms })
    }
}

impl DeviceSessionProof {
    pub fn sign(challenge: &DeviceSessionChallenge, device: &SyncDeviceIdentity) -> Self {
        let public = device.public_identity();
        let signature = device.sign(SESSION_PROOF_DOMAIN, &challenge.encode());
        Self { device_id: public.device_id, signature }
    }

    pub fn verify(
        &self,
        challenge: &DeviceSessionChallenge,
        device: &SyncDevicePublic,
        now_unix_ms: i64,
    ) -> Result<()> {
        challenge.validate_time(now_unix_ms)?;
        if device.device_id != self.device_id {
            return Err(SyncError::UntrustedDevice);
        }
        device.verify(SESSION_PROOF_DOMAIN, &challenge.encode(), &self.signature)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 64);
        out.extend_from_slice(&self.device_id.0);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let device_id = SyncDeviceId(r.array()?);
        let signature = r.array()?;
        r.finish()?;
        Ok(Self { device_id, signature })
    }
}
