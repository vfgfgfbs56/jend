use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::{
    codec::{put_u32, put_u64, Reader}, Result, SyncError, SyncKeyring, SyncObjectId,
};

const MAGIC: &[u8; 4] = b"JESO";
const VERSION: u16 = 1;
const AAD_DOMAIN: &[u8] = b"JEND/SYNC-OBJECT-AAD/V1";
const INNER_DOMAIN: &[u8] = b"JEND/SYNC-OBJECT-INNER/V1";
const MAX_PLAINTEXT: usize = 8 * 1024 * 1024;
const MAX_WIRE: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SyncObjectKind {
    MessageNode = 1,
    SyncIndex = 2,
    DeviceSet = 3,
    Snapshot = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncObject {
    pub object_id: SyncObjectId,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

pub struct OpenedSyncObject {
    pub epoch: u64,
    pub kind: SyncObjectKind,
    pub payload: Zeroizing<Vec<u8>>,
}

impl SyncObject {
    pub fn seal(
        keyring: &SyncKeyring,
        epoch: u64,
        kind: SyncObjectKind,
        payload: &[u8],
    ) -> Result<Self> {
        if payload.len() > MAX_PLAINTEXT {
            return Err(SyncError::ObjectTooLarge);
        }
        let object_id = SyncObjectId::generate()?;
        keyring.with_epoch_secret(epoch, |secret| {
            let key = Zeroizing::new(secret.derive_object_key(&object_id)?);
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
            let mut nonce = [0u8; 24];
            getrandom::fill(&mut nonce)?;
            let inner = Zeroizing::new(encode_inner(epoch, kind, payload)?);
            let aad = object_aad(&object_id);
            let ciphertext = cipher
                .encrypt(
                    &XNonce::from(nonce),
                    Payload { msg: inner.as_ref(), aad: &aad },
                )
                .map_err(|_| SyncError::Aead)?;
            Ok(Self {
                object_id,
                nonce,
                ciphertext,
            })
        })
    }

    pub fn open(&self, keyring: &SyncKeyring) -> Result<OpenedSyncObject> {
        if self.ciphertext.len() > MAX_WIRE {
            return Err(SyncError::ObjectTooLarge);
        }
        let aad = object_aad(&self.object_id);
        let result = keyring.for_each_newest(|epoch, secret| {
            let key = match secret.derive_object_key(&self.object_id) {
                Ok(key) => Zeroizing::new(key),
                Err(err) => return Some(Err(err)),
            };
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
            match cipher.decrypt(
                &XNonce::from(self.nonce),
                Payload { msg: &self.ciphertext, aad: &aad },
            ) {
                Ok(plaintext) => {
                    let plaintext = Zeroizing::new(plaintext);
                    let parsed = decode_inner(plaintext.as_ref());
                    Some(parsed.and_then(|opened| {
                        if opened.epoch != epoch {
                            return Err(SyncError::Malformed);
                        }
                        Ok(opened)
                    }))
                }
                Err(_) => None,
            }
        });
        result.unwrap_or(Err(SyncError::MissingEpochKey))
    }

    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        if self.ciphertext.len() > MAX_WIRE {
            return Err(SyncError::ObjectTooLarge);
        }
        let mut out = Vec::with_capacity(4 + 2 + 24 + 4 + self.ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        put_u32(&mut out, self.ciphertext.len() as u32);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode_wire(object_id: SyncObjectId, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_WIRE {
            return Err(SyncError::ObjectTooLarge);
        }
        let mut r = Reader::new(bytes);
        if r.array::<4>()? != *MAGIC {
            return Err(SyncError::Malformed);
        }
        let version = r.u16()?;
        if version != VERSION {
            return Err(SyncError::UnsupportedVersion(version));
        }
        let nonce = r.array()?;
        let len = r.u32()? as usize;
        let ciphertext = r.take(len)?.to_vec();
        r.finish()?;
        Ok(Self {
            object_id,
            nonce,
            ciphertext,
        })
    }
}

fn encode_inner(epoch: u64, kind: SyncObjectKind, payload: &[u8]) -> Result<Vec<u8>> {
    let base = INNER_DOMAIN.len() + 8 + 1 + 4 + payload.len() + 4;
    let padded = size_bucket(base).ok_or(SyncError::ObjectTooLarge)?;
    let padding_len = padded - base;
    let mut padding = vec![0u8; padding_len];
    if !padding.is_empty() {
        getrandom::fill(&mut padding)?;
    }
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(INNER_DOMAIN);
    put_u64(&mut out, epoch);
    out.push(kind as u8);
    put_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    put_u32(&mut out, padding_len as u32);
    out.extend_from_slice(&padding);
    Ok(out)
}

fn decode_inner(bytes: &[u8]) -> Result<OpenedSyncObject> {
    let mut r = Reader::new(bytes);
    if r.take(INNER_DOMAIN.len())? != INNER_DOMAIN {
        return Err(SyncError::Malformed);
    }
    let epoch = r.u64()?;
    let kind = match r.u8()? {
        1 => SyncObjectKind::MessageNode,
        2 => SyncObjectKind::SyncIndex,
        3 => SyncObjectKind::DeviceSet,
        4 => SyncObjectKind::Snapshot,
        other => return Err(SyncError::UnsupportedKind(other)),
    };
    let payload_len = r.u32()? as usize;
    if payload_len > MAX_PLAINTEXT {
        return Err(SyncError::ObjectTooLarge);
    }
    let payload = Zeroizing::new(r.take(payload_len)?.to_vec());
    let padding_len = r.u32()? as usize;
    let _padding = r.take(padding_len)?;
    r.finish()?;
    Ok(OpenedSyncObject { epoch, kind, payload })
}

fn object_aad(object_id: &SyncObjectId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 32);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&object_id.0);
    aad
}

fn size_bucket(size: usize) -> Option<usize> {
    const BUCKETS: &[usize] = &[
        256, 512, 1024, 2048, 4096, 8192, 16_384, 32_768, 65_536, 131_072,
        262_144, 524_288, 1_048_576, 2_097_152, 4_194_304, 8_388_608,
    ];
    BUCKETS.iter().copied().find(|bucket| *bucket >= size)
}
