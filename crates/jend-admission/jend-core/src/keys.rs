use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{JendError, Result};

const WRAP_INFO: &[u8] = b"JEND/ARK/CONVERSATION-WRAP/V1";
const WRAP_AAD_DOMAIN: &[u8] = b"JEND/CONVERSATION-SEED-ENVELOPE/V1";
const LOCAL_META_INFO: &[u8] = b"JEND/ARK/LOCAL-METADATA-KEY/V1";
const SYNC_WRAP_INFO: &[u8] = b"JEND/SYNC/CONVERSATION-WRAP-KEY/V1";
const SYNC_WRAP_AAD_DOMAIN: &[u8] = b"JEND/SYNC/CONVERSATION-SEED-ENVELOPE/V1";
const LOCAL_META_AAD_DOMAIN: &[u8] = b"JEND/LOCAL-METADATA/V1";
const MAX_LOCAL_CONTEXT: usize = 256;
const MAX_LOCAL_METADATA: usize = 16 * 1024 * 1024;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AccountRootKey([u8; 32]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ConversationSeed(pub(crate) [u8; 32]);

/// Narrow key-encryption-key type used by the encrypted sync layer.
/// Raw key bytes can be imported but cannot be exported.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SyncWrappingKey([u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedConversationSeed {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedLocalBlob {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl AccountRootKey {
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self(key))
    }

    /// Imports an account root key into the cryptographic boundary and clears
    /// the caller-provided buffer before returning.
    ///
    /// This exists for Vault/OS-keystore adapters. There is intentionally no
    /// inverse `export` operation on `AccountRootKey`.
    pub fn from_secret_bytes(bytes: &mut [u8; 32]) -> Self {
        let key = *bytes;
        bytes.zeroize();
        Self(key)
    }

    pub fn wrap_conversation_seed(
        &self,
        conversation_id: &[u8; 16],
        seed: &ConversationSeed,
    ) -> Result<WrappedConversationSeed> {
        let wrapping_key = Zeroizing::new(derive_wrapping_key(&self.0, conversation_id)?);
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");

        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let aad = wrap_aad(conversation_id);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &seed.0,
                    aad: &aad,
                },
            )
            .map_err(|_| JendError::Aead)?;

        Ok(WrappedConversationSeed { nonce, ciphertext })
    }

    pub fn unwrap_conversation_seed(
        &self,
        conversation_id: &[u8; 16],
        envelope: &WrappedConversationSeed,
    ) -> Result<ConversationSeed> {
        if envelope.ciphertext.len() != 48 {
            return Err(JendError::MalformedEnvelope);
        }

        let wrapping_key = Zeroizing::new(derive_wrapping_key(&self.0, conversation_id)?);
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let aad = wrap_aad(conversation_id);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(envelope.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| JendError::Aead)?,
        );

        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| JendError::MalformedEnvelope)?;
        Ok(ConversationSeed(bytes))
    }

    /// Encrypts Vault-local metadata without exposing a metadata key.
    /// `context` is authenticated and domain-separated, and must be stable.
    pub fn seal_local_metadata(&self, context: &[u8], plaintext: &[u8]) -> Result<SealedLocalBlob> {
        validate_local_metadata_input(context, plaintext.len())?;
        let key = Zeroizing::new(derive_local_metadata_key(&self.0, context)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let aad = local_metadata_aad(context);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload { msg: plaintext, aad: &aad },
            )
            .map_err(|_| JendError::Aead)?;
        Ok(SealedLocalBlob { nonce, ciphertext })
    }

    pub fn open_local_metadata(&self, context: &[u8], blob: &SealedLocalBlob) -> Result<Zeroizing<Vec<u8>>> {
        validate_local_metadata_input(context, blob.ciphertext.len())?;
        let key = Zeroizing::new(derive_local_metadata_key(&self.0, context)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let aad = local_metadata_aad(context);
        let plaintext = cipher
            .decrypt(
                &XNonce::from(blob.nonce),
                Payload { msg: &blob.ciphertext, aad: &aad },
            )
            .map_err(|_| JendError::Aead)?;
        Ok(Zeroizing::new(plaintext))
    }
}

impl SyncWrappingKey {
    pub fn from_secret_bytes(bytes: &mut [u8; 32]) -> Self {
        let key = *bytes;
        bytes.zeroize();
        Self(key)
    }

    pub fn wrap_conversation_seed(
        &self,
        conversation_id: &[u8; 16],
        seed: &ConversationSeed,
    ) -> Result<WrappedConversationSeed> {
        let key = Zeroizing::new(derive_sync_wrapping_key(&self.0, conversation_id)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let aad = sync_wrap_aad(conversation_id);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload { msg: &seed.0, aad: &aad },
            )
            .map_err(|_| JendError::Aead)?;
        Ok(WrappedConversationSeed { nonce, ciphertext })
    }

    pub fn unwrap_conversation_seed(
        &self,
        conversation_id: &[u8; 16],
        envelope: &WrappedConversationSeed,
    ) -> Result<ConversationSeed> {
        if envelope.ciphertext.len() != 48 {
            return Err(JendError::MalformedEnvelope);
        }
        let key = Zeroizing::new(derive_sync_wrapping_key(&self.0, conversation_id)?);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let aad = sync_wrap_aad(conversation_id);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(envelope.nonce),
                    Payload { msg: &envelope.ciphertext, aad: &aad },
                )
                .map_err(|_| JendError::Aead)?,
        );
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| JendError::MalformedEnvelope)?;
        Ok(ConversationSeed(bytes))
    }
}

impl ConversationSeed {
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self(key))
    }
}

fn derive_wrapping_key(ark: &[u8; 32], conversation_id: &[u8; 16]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(conversation_id), ark);
    let mut out = [0u8; 32];
    hk.expand(WRAP_INFO, &mut out).map_err(|_| JendError::Kdf)?;
    Ok(out)
}

fn wrap_aad(conversation_id: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(WRAP_AAD_DOMAIN.len() + 16);
    out.extend_from_slice(WRAP_AAD_DOMAIN);
    out.extend_from_slice(conversation_id);
    out
}

fn derive_sync_wrapping_key(base: &[u8; 32], conversation_id: &[u8; 16]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(conversation_id), base);
    let mut out = [0u8; 32];
    hk.expand(SYNC_WRAP_INFO, &mut out).map_err(|_| JendError::Kdf)?;
    Ok(out)
}

fn sync_wrap_aad(conversation_id: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SYNC_WRAP_AAD_DOMAIN.len() + 16);
    out.extend_from_slice(SYNC_WRAP_AAD_DOMAIN);
    out.extend_from_slice(conversation_id);
    out
}

fn validate_local_metadata_input(context: &[u8], size: usize) -> Result<()> {
    if context.is_empty() || context.len() > MAX_LOCAL_CONTEXT || size > MAX_LOCAL_METADATA {
        return Err(JendError::MalformedEnvelope);
    }
    Ok(())
}

fn derive_local_metadata_key(ark: &[u8; 32], context: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(context), ark);
    let mut info = Vec::with_capacity(LOCAL_META_INFO.len() + context.len());
    info.extend_from_slice(LOCAL_META_INFO);
    info.extend_from_slice(context);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).map_err(|_| JendError::Kdf)?;
    Ok(out)
}

fn local_metadata_aad(context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LOCAL_META_AAD_DOMAIN.len() + context.len());
    out.extend_from_slice(LOCAL_META_AAD_DOMAIN);
    out.extend_from_slice(context);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_root_key_wraps_and_unwraps_conversation_seed() {
        let ark = AccountRootKey::generate().unwrap();
        let seed = ConversationSeed::generate().unwrap();
        let conversation_id = [7u8; 16];

        let envelope = ark
            .wrap_conversation_seed(&conversation_id, &seed)
            .unwrap();
        let recovered = ark
            .unwrap_conversation_seed(&conversation_id, &envelope)
            .unwrap();

        assert_eq!(seed.0, recovered.0);
    }

    #[test]
    fn envelope_is_bound_to_conversation_id() {
        let ark = AccountRootKey::generate().unwrap();
        let seed = ConversationSeed::generate().unwrap();
        let envelope = ark
            .wrap_conversation_seed(&[1u8; 16], &seed)
            .unwrap();

        let result = ark.unwrap_conversation_seed(&[2u8; 16], &envelope);
        assert!(matches!(result, Err(JendError::Aead)));
    }

    #[test]
    fn local_metadata_is_context_bound() {
        let ark = AccountRootKey::generate().unwrap();
        let blob = ark.seal_local_metadata(b"vault-index", b"secret metadata").unwrap();
        let opened = ark.open_local_metadata(b"vault-index", &blob).unwrap();
        assert_eq!(opened.as_slice(), b"secret metadata");
        assert!(matches!(ark.open_local_metadata(b"other-context", &blob), Err(JendError::Aead)));
    }

    #[test]
    fn importing_root_key_clears_input_buffer() {
        let mut bytes = [7u8; 32];
        let _key = AccountRootKey::from_secret_bytes(&mut bytes);
        assert_eq!(bytes, [0u8; 32]);
    }
    #[test]
    fn sync_wrapping_key_roundtrip_is_context_bound() {
        let seed = ConversationSeed::generate().unwrap();
        let mut raw = [3u8; 32];
        let key = SyncWrappingKey::from_secret_bytes(&mut raw);
        assert_eq!(raw, [0u8; 32]);
        let envelope = key.wrap_conversation_seed(&[4u8; 16], &seed).unwrap();
        let recovered = key.unwrap_conversation_seed(&[4u8; 16], &envelope).unwrap();
        assert_eq!(seed.0, recovered.0);
        assert!(key.unwrap_conversation_seed(&[5u8; 16], &envelope).is_err());
    }

}
