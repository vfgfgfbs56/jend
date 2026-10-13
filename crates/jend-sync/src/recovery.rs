use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    codec::{put_i64, put_u32, put_u64, Reader}, AccountId, Result, SignedDeviceSet,
    SyncDeviceId, SyncDeviceIdentity, SyncDevicePublic, SyncError,
};

const REQUEST_DOMAIN: &[u8] = b"JEND/RECOVERY-REQUEST/V1";
const REQUEST_HASH_DOMAIN: &[u8] = b"JEND/RECOVERY-REQUEST-HASH/V1";
const APPROVAL_DOMAIN: &[u8] = b"JEND/RECOVERY-APPROVAL/V1";
const APPROVAL_KDF_INFO: &[u8] = b"JEND/RECOVERY-CODE-BOUND-APPROVAL/V1";
const APPROVAL_AAD_DOMAIN: &[u8] = b"JEND/RECOVERY-APPROVAL-AAD/V1";
const MAX_REQUEST_LIFETIME_MS: i64 = 10 * 60 * 1000;
const MAX_APPROVAL_LIFETIME_MS: i64 = 5 * 60 * 1000;
const APPROVAL_PLAINTEXT_LEN: usize = 32 + 16 + 8 + 32 + 8 + 8 + 32 + 64;

/// User-entered six-digit comparison code. It is deliberately *not* an
/// account secret and must never be accepted as sufficient authorization.
/// Its purpose is to bind a recovery approval to possession of an already
/// trusted device. The cryptographic strength comes from X25519 + the trusted
/// device signature; the code prevents a remote requester from silently using
/// an approval the user did not compare out of band.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode([u8; 6]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRequest {
    pub account_id: AccountId,
    pub candidate: SyncDevicePublic,
    pub request_id: [u8; 32],
    pub expires_unix_ms: i64,
    pub signature: [u8; 64],
}

/// Opaque relay payload returned by a trusted device. The server can route it
/// using `request_id`, but does not receive the six-digit code or the signed
/// approval plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryApprovalEnvelope {
    pub request_id: [u8; 32],
    pub approver: SyncDeviceId,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryApproval {
    pub request_commitment: [u8; 32],
    pub approver: SyncDeviceId,
    pub device_set_epoch: u64,
    pub device_set_hash: [u8; 32],
    pub issued_unix_ms: i64,
    pub expires_unix_ms: i64,
    pub grant_nonce: [u8; 32],
    pub signature: [u8; 64],
}

impl RecoveryCode {
    pub fn generate() -> Result<Self> {
        // Rejection sampling avoids modulo bias while keeping exactly six
        // decimal digits. 2^24 is large enough for efficient sampling.
        const LIMIT: u32 = 16_000_000; // largest multiple of 1_000_000 < 2^24
        loop {
            let mut bytes = [0u8; 3];
            getrandom::fill(&mut bytes)?;
            let value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
            bytes.zeroize();
            if value < LIMIT {
                let number = value % 1_000_000;
                let text = format!("{number:06}");
                let mut digits = [0u8; 6];
                digits.copy_from_slice(text.as_bytes());
                return Ok(Self(digits));
            }
        }
    }

    pub fn parse(input: &str) -> Result<Self> {
        let bytes = input.as_bytes();
        if bytes.len() != 6 || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(SyncError::Malformed);
        }
        let mut digits = [0u8; 6];
        digits.copy_from_slice(bytes);
        Ok(Self(digits))
    }

    pub fn display(&self) -> String {
        // Deliberate user-visible exposure; callers should avoid logging this.
        core::str::from_utf8(&self.0).expect("digits are ASCII").to_owned()
    }

    fn bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCode([REDACTED])")
    }
}

impl RecoveryRequest {
    pub fn create(
        account_id: AccountId,
        candidate: &SyncDeviceIdentity,
        now_unix_ms: i64,
    ) -> Result<Self> {
        let expires_unix_ms = now_unix_ms
            .checked_add(MAX_REQUEST_LIFETIME_MS)
            .ok_or(SyncError::Malformed)?;
        let mut request_id = [0u8; 32];
        getrandom::fill(&mut request_id)?;
        let candidate_public = candidate.public_identity();
        let unsigned = encode_request_unsigned(
            account_id,
            &candidate_public,
            request_id,
            expires_unix_ms,
        );
        let signature = candidate.sign(REQUEST_DOMAIN, &unsigned);
        Ok(Self {
            account_id,
            candidate: candidate_public,
            request_id,
            expires_unix_ms,
            signature,
        })
    }

    pub fn verify(&self, now_unix_ms: i64) -> Result<()> {
        if now_unix_ms > self.expires_unix_ms
            || self.expires_unix_ms.saturating_sub(now_unix_ms) > MAX_REQUEST_LIFETIME_MS
        {
            return Err(SyncError::RecoveryExpired);
        }
        self.candidate.verify(
            REQUEST_DOMAIN,
            &encode_request_unsigned(
                self.account_id,
                &self.candidate,
                self.request_id,
                self.expires_unix_ms,
            ),
            &self.signature,
        )
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(REQUEST_HASH_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_request_unsigned(
            self.account_id,
            &self.candidate,
            self.request_id,
            self.expires_unix_ms,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let account_id = AccountId(r.array()?);
        let claimed_id = SyncDeviceId(r.array()?);
        let signing_public = r.array()?;
        let kex_public = r.array()?;
        let message_signing_public = r.array()?;
        let candidate = SyncDevicePublic::new(signing_public, kex_public, message_signing_public);
        if candidate.device_id != claimed_id {
            return Err(SyncError::Malformed);
        }
        let request_id = r.array()?;
        let expires_unix_ms = r.i64()?;
        let signature = r.array()?;
        r.finish()?;
        Ok(Self {
            account_id,
            candidate,
            request_id,
            expires_unix_ms,
            signature,
        })
    }
}

impl RecoveryApprovalEnvelope {
    /// Creates a code-bound recovery approval on an already trusted device.
    ///
    /// The returned `RecoveryCode` is displayed locally and is NOT included in
    /// the relay envelope. The new device must receive it out of band from the
    /// user and combine it with its candidate private key to decrypt.
    pub fn approve(
        request: &RecoveryRequest,
        device_set: &SignedDeviceSet,
        approver: &SyncDeviceIdentity,
        now_unix_ms: i64,
    ) -> Result<(Self, RecoveryCode)> {
        request.verify(now_unix_ms)?;
        if request.account_id != device_set.set.account_id {
            return Err(SyncError::Malformed);
        }
        let approver_public = approver.public_identity();
        if !device_set.set.contains(approver_public.device_id)
            || device_set.set.contains(request.candidate.device_id)
        {
            return Err(SyncError::UntrustedDevice);
        }

        let code = RecoveryCode::generate()?;
        let expires_unix_ms = now_unix_ms
            .checked_add(MAX_APPROVAL_LIFETIME_MS)
            .ok_or(SyncError::Malformed)?;
        let mut grant_nonce = [0u8; 32];
        getrandom::fill(&mut grant_nonce)?;
        let request_commitment = request.commitment();
        let device_set_hash = device_set.hash();
        let unsigned = encode_approval_unsigned(
            request_commitment,
            approver_public.device_id,
            device_set.set.epoch,
            device_set_hash,
            now_unix_ms,
            expires_unix_ms,
            grant_nonce,
        );
        let signature = approver.sign(APPROVAL_DOMAIN, &unsigned);
        let plaintext = Zeroizing::new(encode_approval_plaintext(&unsigned, signature));

        let shared = Zeroizing::new(approver.diffie_hellman(&request.candidate.kex_public));
        let key = Zeroizing::new(derive_approval_key(
            &*shared,
            code.bytes(),
            &request_commitment,
            &approver_public.device_id,
            &request.candidate.device_id,
        )?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let aad = approval_aad(
            &request.request_id,
            approver_public.device_id,
            request.candidate.device_id,
        );
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| SyncError::Aead)?;

        Ok((
            Self {
                request_id: request.request_id,
                approver: approver_public.device_id,
                nonce,
                ciphertext,
            },
            code,
        ))
    }

    pub fn open(
        &self,
        request: &RecoveryRequest,
        candidate: &SyncDeviceIdentity,
        approver_public: &SyncDevicePublic,
        code: &RecoveryCode,
        now_unix_ms: i64,
    ) -> Result<RecoveryApproval> {
        request.verify(now_unix_ms)?;
        let candidate_public = candidate.public_identity();
        if self.request_id != request.request_id
            || candidate_public.device_id != request.candidate.device_id
            || candidate_public != request.candidate
            || self.approver != approver_public.device_id
        {
            return Err(SyncError::RecoveryBindingMismatch);
        }

        let request_commitment = request.commitment();
        let shared = Zeroizing::new(candidate.diffie_hellman(&approver_public.kex_public));
        let key = Zeroizing::new(derive_approval_key(
            &*shared,
            code.bytes(),
            &request_commitment,
            &approver_public.device_id,
            &candidate_public.device_id,
        )?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let aad = approval_aad(
            &request.request_id,
            approver_public.device_id,
            candidate_public.device_id,
        );
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| SyncError::RecoveryCodeMismatch)?,
        );
        let approval = decode_approval_plaintext(plaintext.as_ref())?;
        if approval.request_commitment != request_commitment
            || approval.approver != approver_public.device_id
            || now_unix_ms > approval.expires_unix_ms
            || approval.expires_unix_ms.saturating_sub(approval.issued_unix_ms)
                > MAX_APPROVAL_LIFETIME_MS
        {
            return Err(SyncError::RecoveryBindingMismatch);
        }
        approver_public.verify(
            APPROVAL_DOMAIN,
            &encode_approval_unsigned(
                approval.request_commitment,
                approval.approver,
                approval.device_set_epoch,
                approval.device_set_hash,
                approval.issued_unix_ms,
                approval.expires_unix_ms,
                approval.grant_nonce,
            ),
            &approval.signature,
        )?;
        Ok(approval)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.ciphertext.len() > u32::MAX as usize {
            return Err(SyncError::ObjectTooLarge);
        }
        let mut out = Vec::with_capacity(32 + 16 + 24 + 4 + self.ciphertext.len());
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.approver.0);
        out.extend_from_slice(&self.nonce);
        put_u32(&mut out, self.ciphertext.len() as u32);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let request_id = r.array()?;
        let approver = SyncDeviceId(r.array()?);
        let nonce = r.array()?;
        let len = r.u32()? as usize;
        if len > APPROVAL_PLAINTEXT_LEN + 16 {
            return Err(SyncError::ObjectTooLarge);
        }
        let ciphertext = r.take(len)?.to_vec();
        r.finish()?;
        Ok(Self {
            request_id,
            approver,
            nonce,
            ciphertext,
        })
    }
}

impl RecoveryApproval {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = encode_approval_unsigned(
            self.request_commitment,
            self.approver,
            self.device_set_epoch,
            self.device_set_hash,
            self.issued_unix_ms,
            self.expires_unix_ms,
            self.grant_nonce,
        );
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_approval_plaintext(bytes)
    }

    /// Verification suitable for the auth/control-plane before allowing OPAQUE
    /// password credential rotation. `device_set` must be the pinned/current
    /// signed DeviceSet for this account, not a server-invented device list.
    pub fn verify_for_password_reset(
        &self,
        request: &RecoveryRequest,
        device_set: &SignedDeviceSet,
        now_unix_ms: i64,
    ) -> Result<()> {
        if self.request_commitment != request.commitment()
            || self.device_set_epoch != device_set.set.epoch
            || self.device_set_hash != device_set.hash()
            || now_unix_ms > self.expires_unix_ms
        {
            return Err(SyncError::RecoveryBindingMismatch);
        }
        let signer = device_set
            .set
            .get(self.approver)
            .ok_or(SyncError::UntrustedDevice)?;
        signer.verify(
            APPROVAL_DOMAIN,
            &encode_approval_unsigned(
                self.request_commitment,
                self.approver,
                self.device_set_epoch,
                self.device_set_hash,
                self.issued_unix_ms,
                self.expires_unix_ms,
                self.grant_nonce,
            ),
            &self.signature,
        )
    }
}

fn encode_request_unsigned(
    account_id: AccountId,
    candidate: &SyncDevicePublic,
    request_id: [u8; 32],
    expires_unix_ms: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 16 + 32 + 32 + 32 + 32 + 8);
    out.extend_from_slice(&account_id.0);
    out.extend_from_slice(&candidate.device_id.0);
    out.extend_from_slice(&candidate.signing_public);
    out.extend_from_slice(&candidate.kex_public);
    out.extend_from_slice(&candidate.message_signing_public);
    out.extend_from_slice(&request_id);
    put_i64(&mut out, expires_unix_ms);
    out
}

fn encode_approval_unsigned(
    request_commitment: [u8; 32],
    approver: SyncDeviceId,
    device_set_epoch: u64,
    device_set_hash: [u8; 32],
    issued_unix_ms: i64,
    expires_unix_ms: i64,
    grant_nonce: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 16 + 8 + 32 + 8 + 8 + 32);
    out.extend_from_slice(&request_commitment);
    out.extend_from_slice(&approver.0);
    put_u64(&mut out, device_set_epoch);
    out.extend_from_slice(&device_set_hash);
    put_i64(&mut out, issued_unix_ms);
    put_i64(&mut out, expires_unix_ms);
    out.extend_from_slice(&grant_nonce);
    out
}

fn encode_approval_plaintext(unsigned: &[u8], signature: [u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(unsigned.len() + 64);
    out.extend_from_slice(unsigned);
    out.extend_from_slice(&signature);
    out
}

fn decode_approval_plaintext(bytes: &[u8]) -> Result<RecoveryApproval> {
    if bytes.len() != APPROVAL_PLAINTEXT_LEN {
        return Err(SyncError::Malformed);
    }
    let mut r = Reader::new(bytes);
    let request_commitment = r.array()?;
    let approver = SyncDeviceId(r.array()?);
    let device_set_epoch = r.u64()?;
    let device_set_hash = r.array()?;
    let issued_unix_ms = r.i64()?;
    let expires_unix_ms = r.i64()?;
    let grant_nonce = r.array()?;
    let signature = r.array()?;
    r.finish()?;
    Ok(RecoveryApproval {
        request_commitment,
        approver,
        device_set_epoch,
        device_set_hash,
        issued_unix_ms,
        expires_unix_ms,
        grant_nonce,
        signature,
    })
}

fn derive_approval_key(
    shared: &[u8; 32],
    code: &[u8; 6],
    request_commitment: &[u8; 32],
    approver: &SyncDeviceId,
    candidate: &SyncDeviceId,
) -> Result<[u8; 32]> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(APPROVAL_KDF_INFO);
    salt_hasher.update(code);
    salt_hasher.update(request_commitment);
    salt_hasher.update(approver.0);
    salt_hasher.update(candidate.0);
    let salt: [u8; 32] = salt_hasher.finalize().into();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut out = [0u8; 32];
    hk.expand(APPROVAL_KDF_INFO, &mut out)
        .map_err(|_| SyncError::Kdf)?;
    Ok(out)
}

fn approval_aad(
    request_id: &[u8; 32],
    approver: SyncDeviceId,
    candidate: SyncDeviceId,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(APPROVAL_AAD_DOMAIN.len() + 32 + 16 + 16);
    out.extend_from_slice(APPROVAL_AAD_DOMAIN);
    out.extend_from_slice(request_id);
    out.extend_from_slice(&approver.0);
    out.extend_from_slice(&candidate.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceSet, SignedDeviceSet};

    #[test]
    fn six_digit_code_roundtrip() {
        let code = RecoveryCode::generate().unwrap();
        let text = code.display();
        assert_eq!(text.len(), 6);
        assert!(text.as_bytes().iter().all(u8::is_ascii_digit));
        let parsed = RecoveryCode::parse(&text).unwrap();
        assert_eq!(parsed.display(), text);
    }

    #[test]
    fn approval_requires_code_and_candidate_private_key() {
        let trusted = SyncDeviceIdentity::generate().unwrap();
        let candidate = SyncDeviceIdentity::generate().unwrap();
        let wrong_candidate = SyncDeviceIdentity::generate().unwrap();
        let account = AccountId::generate().unwrap();
        let set = SignedDeviceSet::sign_genesis(
            DeviceSet::genesis(account, trusted.public_identity()),
            &trusted,
        )
        .unwrap();
        let request = RecoveryRequest::create(account, &candidate, 1_000_000).unwrap();
        let (envelope, code) = RecoveryApprovalEnvelope::approve(
            &request,
            &set,
            &trusted,
            1_000_100,
        )
        .unwrap();

        let approval = envelope
            .open(
                &request,
                &candidate,
                &trusted.public_identity(),
                &code,
                1_000_200,
            )
            .unwrap();
        approval
            .verify_for_password_reset(&request, &set, 1_000_200)
            .unwrap();

        let wrong_code = RecoveryCode::parse("000000").unwrap();
        if wrong_code.display() != code.display() {
            assert!(envelope
                .open(
                    &request,
                    &candidate,
                    &trusted.public_identity(),
                    &wrong_code,
                    1_000_200,
                )
                .is_err());
        }

        assert!(envelope
            .open(
                &request,
                &wrong_candidate,
                &trusted.public_identity(),
                &code,
                1_000_200,
            )
            .is_err());
    }
}
