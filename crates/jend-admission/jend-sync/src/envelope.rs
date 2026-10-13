use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    codec::{put_u32, put_u64, Reader}, AccountId, DeviceSetHistory, Result, SyncDeviceId,
    SyncDeviceIdentity, SyncDevicePublic, SyncError, SyncKeyring, SyncObjectId,
};

const ENVELOPE_DOMAIN: &[u8] = b"JEND/SYNC-KEY-ENVELOPE/V1";
const KDF_INFO: &[u8] = b"JEND/SYNC-KEY-ENVELOPE-KDF/V1";
const MAX_PAYLOAD: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEnvelope {
    pub account_id: AccountId,
    pub epoch: u64,
    pub sender: SyncDeviceId,
    pub recipient: SyncDeviceId,
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}

pub struct BootstrapPayload {
    pub envelope_epoch: u64,
    pub keyring: SyncKeyring,
    pub device_history: DeviceSetHistory,
    pub device_set_hash: [u8; 32],
    pub request_binding: [u8; 32],
    pub latest_index: Option<SyncObjectId>,
    pub index_generation: u64,
}

impl KeyEnvelope {
    pub fn seal(
        account_id: AccountId,
        epoch: u64,
        sender: &SyncDeviceIdentity,
        recipient: &SyncDevicePublic,
        keyring: &SyncKeyring,
        device_history: &DeviceSetHistory,
        device_set_hash: [u8; 32],
        request_binding: [u8; 32],
        latest_index: Option<SyncObjectId>,
        index_generation: u64,
    ) -> Result<Self> {
        let sender_public = sender.public_identity();
        let mut ephemeral_bytes = [0u8; 32];
        getrandom::fill(&mut ephemeral_bytes)?;
        let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
        ephemeral_bytes.zeroize();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret).to_bytes();
        let recipient_public = X25519PublicKey::from(recipient.kex_public);
        let shared = Zeroizing::new(ephemeral_secret.diffie_hellman(&recipient_public).to_bytes());
        let key = Zeroizing::new(derive_envelope_key(
            &*shared,
            &account_id,
            epoch,
            &sender_public.device_id,
            &recipient.device_id,
            &ephemeral_public,
            &recipient.kex_public,
        )?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let plaintext = Zeroizing::new(encode_bootstrap_parts(
            keyring,
            device_history,
            device_set_hash,
            request_binding,
            latest_index,
            index_generation,
        )?);
        if plaintext.len() > MAX_PAYLOAD {
            return Err(SyncError::ObjectTooLarge);
        }
        let aad = envelope_aad(
            &account_id,
            epoch,
            sender_public.device_id,
            recipient.device_id,
            &ephemeral_public,
        );
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload { msg: plaintext.as_ref(), aad: &aad },
            )
            .map_err(|_| SyncError::Aead)?;
        let unsigned = encode_unsigned(
            account_id,
            epoch,
            sender_public.device_id,
            recipient.device_id,
            ephemeral_public,
            nonce,
            &ciphertext,
        )?;
        let signature = sender.sign(ENVELOPE_DOMAIN, &unsigned);
        Ok(Self {
            account_id,
            epoch,
            sender: sender_public.device_id,
            recipient: recipient.device_id,
            ephemeral_public,
            nonce,
            ciphertext,
            signature,
        })
    }

    pub fn open(
        &self,
        recipient: &SyncDeviceIdentity,
        trusted_sender: &SyncDevicePublic,
    ) -> Result<BootstrapPayload> {
        let recipient_public = recipient.public_identity();
        if recipient_public.device_id != self.recipient || trusted_sender.device_id != self.sender {
            return Err(SyncError::UntrustedDevice);
        }
        let unsigned = encode_unsigned(
            self.account_id,
            self.epoch,
            self.sender,
            self.recipient,
            self.ephemeral_public,
            self.nonce,
            &self.ciphertext,
        )?;
        trusted_sender.verify(ENVELOPE_DOMAIN, &unsigned, &self.signature)?;
        let ephemeral_public = X25519PublicKey::from(self.ephemeral_public);
        let shared = Zeroizing::new(recipient.diffie_hellman(&ephemeral_public.to_bytes()));
        let key = Zeroizing::new(derive_envelope_key(
            &*shared,
            &self.account_id,
            self.epoch,
            &self.sender,
            &self.recipient,
            &self.ephemeral_public,
            &recipient_public.kex_public,
        )?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let aad = envelope_aad(
            &self.account_id,
            self.epoch,
            self.sender,
            self.recipient,
            &self.ephemeral_public,
        );
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(self.nonce),
                    Payload { msg: &self.ciphertext, aad: &aad },
                )
                .map_err(|_| SyncError::Aead)?,
        );
        let mut bootstrap = decode_bootstrap(plaintext.as_ref())?;
        bootstrap.envelope_epoch = self.epoch;
        Ok(bootstrap)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = encode_unsigned(
            self.account_id,
            self.epoch,
            self.sender,
            self.recipient,
            self.ephemeral_public,
            self.nonce,
            &self.ciphertext,
        )?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let account_id = AccountId(r.array()?);
        let epoch = r.u64()?;
        let sender = SyncDeviceId(r.array()?);
        let recipient = SyncDeviceId(r.array()?);
        let ephemeral_public = r.array()?;
        let nonce = r.array()?;
        let len = r.u32()? as usize;
        if len > MAX_PAYLOAD + 32 {
            return Err(SyncError::ObjectTooLarge);
        }
        let ciphertext = r.take(len)?.to_vec();
        let signature = r.array()?;
        r.finish()?;
        Ok(Self {
            account_id,
            epoch,
            sender,
            recipient,
            ephemeral_public,
            nonce,
            ciphertext,
            signature,
        })
    }
}

fn derive_envelope_key(
    shared: &[u8; 32],
    account_id: &AccountId,
    epoch: u64,
    sender: &SyncDeviceId,
    recipient: &SyncDeviceId,
    ephemeral_public: &[u8; 32],
    recipient_kex_public: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(ENVELOPE_DOMAIN);
    salt_hasher.update(account_id.0);
    salt_hasher.update(epoch.to_be_bytes());
    salt_hasher.update(sender.0);
    salt_hasher.update(recipient.0);
    salt_hasher.update(ephemeral_public);
    salt_hasher.update(recipient_kex_public);
    let salt: [u8; 32] = salt_hasher.finalize().into();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut out = [0u8; 32];
    hk.expand(KDF_INFO, &mut out).map_err(|_| SyncError::Kdf)?;
    Ok(out)
}

fn envelope_aad(
    account_id: &AccountId,
    epoch: u64,
    sender: SyncDeviceId,
    recipient: SyncDeviceId,
    ephemeral_public: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENVELOPE_DOMAIN.len() + 16 + 8 + 16 + 16 + 32);
    out.extend_from_slice(ENVELOPE_DOMAIN);
    out.extend_from_slice(&account_id.0);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&sender.0);
    out.extend_from_slice(&recipient.0);
    out.extend_from_slice(ephemeral_public);
    out
}

fn encode_unsigned(
    account_id: AccountId,
    epoch: u64,
    sender: SyncDeviceId,
    recipient: SyncDeviceId,
    ephemeral_public: [u8; 32],
    nonce: [u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() > MAX_PAYLOAD + 32 {
        return Err(SyncError::ObjectTooLarge);
    }
    let mut out = Vec::with_capacity(16 + 8 + 16 + 16 + 32 + 24 + 4 + ciphertext.len());
    out.extend_from_slice(&account_id.0);
    put_u64(&mut out, epoch);
    out.extend_from_slice(&sender.0);
    out.extend_from_slice(&recipient.0);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&nonce);
    put_u32(&mut out, ciphertext.len() as u32);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

fn encode_bootstrap_parts(
    source_keyring: &SyncKeyring,
    device_history: &DeviceSetHistory,
    device_set_hash: [u8; 32],
    request_binding: [u8; 32],
    latest_index: Option<SyncObjectId>,
    index_generation: u64,
) -> Result<Vec<u8>> {
    let keyring = Zeroizing::new(source_keyring.encode_sensitive());
    let history = device_history.encode()?;
    if keyring.len() > u16::MAX as usize || history.len() > u32::MAX as usize {
        return Err(SyncError::ObjectTooLarge);
    }
    let mut out = Vec::with_capacity(2 + keyring.len() + 4 + history.len() + 32 + 32 + 1 + 32 + 8);
    out.extend_from_slice(&(keyring.len() as u16).to_be_bytes());
    out.extend_from_slice(keyring.as_ref());
    put_u32(&mut out, history.len() as u32);
    out.extend_from_slice(&history);
    out.extend_from_slice(&device_set_hash);
    out.extend_from_slice(&request_binding);
    match latest_index {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id.0);
        }
        None => out.push(0),
    }
    put_u64(&mut out, index_generation);
    Ok(out)
}

fn decode_bootstrap(bytes: &[u8]) -> Result<BootstrapPayload> {
    let mut r = Reader::new(bytes);
    let keyring_len = r.u16()? as usize;
    let keyring_bytes = Zeroizing::new(r.take(keyring_len)?.to_vec());
    let keyring = SyncKeyring::decode_sensitive(keyring_bytes.as_ref())?;
    let history_len = r.u32()? as usize;
    if history_len > MAX_PAYLOAD { return Err(SyncError::ObjectTooLarge); }
    let device_history = DeviceSetHistory::decode(r.take(history_len)?)?;
    let device_set_hash = r.array()?;
    let request_binding = r.array()?;
    let latest_index = match r.u8()? {
        0 => None,
        1 => Some(SyncObjectId(r.array()?)),
        _ => return Err(SyncError::Malformed),
    };
    let index_generation = r.u64()?;
    r.finish()?;
    Ok(BootstrapPayload {
        envelope_epoch: 0,
        keyring,
        device_history,
        device_set_hash,
        request_binding,
        latest_index,
        index_generation,
    })
}
