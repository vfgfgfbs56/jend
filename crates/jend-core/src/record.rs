use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::codec::{put_i64, put_u16, put_u32, put_u64, Reader};
use crate::{
    DeviceIdentity, DeviceKeyId, DevicePublicIdentity, JendError, MessageKey, Result,
};

const MAGIC: &[u8; 4] = b"JEND";
const VERSION: u16 = 1;
const CRYPTO_SUITE: u16 = 1;
const RECORD_TYPE_MESSAGE: u8 = 1;
const OUTER_HEADER_LEN: usize = 72;
const TRAILER_LEN: usize = 96;
const INNER_FIXED_LEN: usize = 76;
const AEAD_TAG_LEN: usize = 16;
const PADDING_GRANULARITY: usize = 256;
const MAX_CIPHERTEXT_LEN: usize = 16 * 1024 * 1024 + PADDING_GRANULARITY + AEAD_TAG_LEN;
const COMMITMENT_DOMAIN: &[u8] = b"JEND/COMMITMENT/V1";

pub const ZERO_COMMITMENT: RecordCommitment = RecordCommitment([0u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConversationId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecordCommitment(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageRole {
    User = 1,
    Assistant = 2,
    System = 3,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SensitiveBytes")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for SensitiveBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SensitiveBytes {}

pub struct InnerMessage {
    pub conversation_id: ConversationId,
    pub sequence: u64,
    pub epoch: u32,
    pub local_unix_ms: i64,
    pub previous_commitment: RecordCommitment,
    pub role: MessageRole,
    pub plaintext: SensitiveBytes,
}

impl core::fmt::Debug for InnerMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InnerMessage")
            .field("conversation_id", &self.conversation_id)
            .field("sequence", &self.sequence)
            .field("epoch", &self.epoch)
            .field("local_unix_ms", &self.local_unix_ms)
            .field("previous_commitment", &self.previous_commitment)
            .field("role", &self.role)
            .field("plaintext", &self.plaintext)
            .finish()
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JendRecord {
    packet_id: [u8; 16],
    signer_key_id: DeviceKeyId,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    commitment: RecordCommitment,
    signature: [u8; 64],
}

impl ConversationId {
    pub fn generate() -> Result<Self> {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id)?;
        Ok(Self(id))
    }
}

impl JendRecord {
    pub fn seal(
        inner: &InnerMessage,
        message_key: &MessageKey,
        signer: &DeviceIdentity,
    ) -> Result<Self> {
        let mut packet_id = [0u8; 16];
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut packet_id)?;
        getrandom::fill(&mut nonce)?;

        let signer_key_id = signer.public_identity().key_id();
        let inner_bytes = Zeroizing::new(encode_inner_padded(inner)?);
        let ciphertext_len = inner_bytes
            .len()
            .checked_add(AEAD_TAG_LEN)
            .ok_or(JendError::RecordTooLarge)?;
        if ciphertext_len > MAX_CIPHERTEXT_LEN || ciphertext_len > u32::MAX as usize {
            return Err(JendError::RecordTooLarge);
        }

        let header = encode_outer_header(
            packet_id,
            signer_key_id,
            nonce,
            ciphertext_len as u32,
        );

        let cipher = XChaCha20Poly1305::new_from_slice(&message_key.0)
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: inner_bytes.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| JendError::Aead)?;

        let commitment = compute_commitment(&header, &ciphertext);
        let signature = signer.sign_commitment(&commitment.0);

        Ok(Self {
            packet_id,
            signer_key_id,
            nonce,
            ciphertext,
            commitment,
            signature,
        })
    }

    pub fn open(
        &self,
        message_key: &MessageKey,
        trusted_signer: &DevicePublicIdentity,
    ) -> Result<InnerMessage> {
        let header = self.outer_header()?;
        let expected = compute_commitment(&header, &self.ciphertext);
        if expected != self.commitment {
            return Err(JendError::CommitmentMismatch);
        }

        trusted_signer.verify_commitment(
            self.signer_key_id,
            &self.commitment.0,
            &self.signature,
        )?;

        let cipher = XChaCha20Poly1305::new_from_slice(&message_key.0)
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let plaintext = Zeroizing::new(
            cipher
            .decrypt(
                &XNonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &header,
                },
            )
            .map_err(|_| JendError::Aead)?,
        );

        decode_inner(plaintext.as_slice())
    }

    pub fn open_checked(
        &self,
        message_key: &MessageKey,
        trusted_signer: &DevicePublicIdentity,
        expected_sequence: u64,
        expected_previous: RecordCommitment,
    ) -> Result<InnerMessage> {
        let inner = self.open(message_key, trusted_signer)?;
        if inner.sequence != expected_sequence {
            return Err(JendError::SequenceMismatch {
                expected: expected_sequence,
                got: inner.sequence,
            });
        }
        if inner.previous_commitment != expected_previous {
            return Err(JendError::ChainMismatch);
        }
        Ok(inner)
    }

    pub fn commitment(&self) -> RecordCommitment {
        self.commitment
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let header = self.outer_header()?;
        let total = header
            .len()
            .checked_add(self.ciphertext.len())
            .and_then(|n| n.checked_add(TRAILER_LEN))
            .ok_or(JendError::RecordTooLarge)?;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.commitment.0);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < OUTER_HEADER_LEN + TRAILER_LEN {
            return Err(JendError::Truncated);
        }

        let mut r = Reader::new(bytes);
        let magic: [u8; 4] = r.array()?;
        if &magic != MAGIC {
            return Err(JendError::InvalidMagic);
        }

        let version = r.u16()?;
        if version != VERSION {
            return Err(JendError::UnsupportedVersion(version));
        }

        let suite = r.u16()?;
        if suite != CRYPTO_SUITE {
            return Err(JendError::UnsupportedSuite(suite));
        }

        let record_type = r.u8()?;
        if record_type != RECORD_TYPE_MESSAGE {
            return Err(JendError::UnsupportedRecordType(record_type));
        }

        let flags = r.u8()?;
        let reserved = r.u16()?;
        if flags != 0 || reserved != 0 {
            return Err(JendError::ReservedField);
        }

        let packet_id = r.array()?;
        let signer_key_id = DeviceKeyId(r.array()?);
        let nonce = r.array()?;
        let ciphertext_len = r.u32()? as usize;
        if ciphertext_len > MAX_CIPHERTEXT_LEN {
            return Err(JendError::RecordTooLarge);
        }
        if r.remaining() < ciphertext_len + TRAILER_LEN {
            return Err(JendError::Truncated);
        }

        let ciphertext = r.take(ciphertext_len)?.to_vec();
        let commitment = RecordCommitment(r.array()?);
        let signature = r.array()?;
        if !r.is_empty() {
            return Err(JendError::TrailingBytes);
        }

        let record = Self {
            packet_id,
            signer_key_id,
            nonce,
            ciphertext,
            commitment,
            signature,
        };

        let header = record.outer_header()?;
        if compute_commitment(&header, &record.ciphertext) != record.commitment {
            return Err(JendError::CommitmentMismatch);
        }

        Ok(record)
    }

    fn outer_header(&self) -> Result<Vec<u8>> {
        if self.ciphertext.len() > MAX_CIPHERTEXT_LEN || self.ciphertext.len() > u32::MAX as usize {
            return Err(JendError::RecordTooLarge);
        }
        Ok(encode_outer_header(
            self.packet_id,
            self.signer_key_id,
            self.nonce,
            self.ciphertext.len() as u32,
        ))
    }
}

fn encode_outer_header(
    packet_id: [u8; 16],
    signer_key_id: DeviceKeyId,
    nonce: [u8; 24],
    ciphertext_len: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(OUTER_HEADER_LEN);
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, VERSION);
    put_u16(&mut out, CRYPTO_SUITE);
    out.push(RECORD_TYPE_MESSAGE);
    out.push(0); // flags
    put_u16(&mut out, 0); // reserved
    out.extend_from_slice(&packet_id);
    out.extend_from_slice(&signer_key_id.0);
    out.extend_from_slice(&nonce);
    put_u32(&mut out, ciphertext_len);
    debug_assert_eq!(out.len(), OUTER_HEADER_LEN);
    out
}

fn encode_inner_padded(inner: &InnerMessage) -> Result<Vec<u8>> {
    if inner.plaintext.len() > u32::MAX as usize {
        return Err(JendError::RecordTooLarge);
    }

    let raw_len = INNER_FIXED_LEN
        .checked_add(inner.plaintext.len())
        .ok_or(JendError::RecordTooLarge)?;
    let padded_len = raw_len
        .checked_add(PADDING_GRANULARITY - 1)
        .ok_or(JendError::RecordTooLarge)?
        / PADDING_GRANULARITY
        * PADDING_GRANULARITY;

    if padded_len + AEAD_TAG_LEN > MAX_CIPHERTEXT_LEN {
        return Err(JendError::RecordTooLarge);
    }

    let mut out = Vec::with_capacity(padded_len);
    put_u16(&mut out, 1); // inner version
    out.push(inner.role as u8);
    out.push(0); // reserved
    out.extend_from_slice(&inner.conversation_id.0);
    put_u64(&mut out, inner.sequence);
    put_u32(&mut out, inner.epoch);
    put_i64(&mut out, inner.local_unix_ms);
    out.extend_from_slice(&inner.previous_commitment.0);
    put_u32(&mut out, inner.plaintext.len() as u32);
    out.extend_from_slice(inner.plaintext.as_bytes());

    let pad_len = padded_len - out.len();
    if pad_len != 0 {
        let start = out.len();
        out.resize(padded_len, 0);
        getrandom::fill(&mut out[start..])?;
    }

    Ok(out)
}

fn decode_inner(bytes: &[u8]) -> Result<InnerMessage> {
    if bytes.len() < INNER_FIXED_LEN || bytes.len() % PADDING_GRANULARITY != 0 {
        return Err(JendError::MalformedInner);
    }

    let mut r = Reader::new(bytes);
    let inner_version = r.u16()?;
    if inner_version != 1 {
        return Err(JendError::MalformedInner);
    }

    let role = match r.u8()? {
        1 => MessageRole::User,
        2 => MessageRole::Assistant,
        3 => MessageRole::System,
        other => return Err(JendError::UnsupportedRole(other)),
    };
    if r.u8()? != 0 {
        return Err(JendError::ReservedField);
    }

    let conversation_id = ConversationId(r.array()?);
    let sequence = r.u64()?;
    let epoch = r.u32()?;
    let local_unix_ms = r.i64()?;
    let previous_commitment = RecordCommitment(r.array()?);
    let plaintext_len = r.u32()? as usize;
    if plaintext_len > r.remaining() {
        return Err(JendError::MalformedInner);
    }
    let plaintext = SensitiveBytes::from_slice(r.take(plaintext_len)?);
    // Remaining bytes are authenticated random padding and intentionally ignored.

    Ok(InnerMessage {
        conversation_id,
        sequence,
        epoch,
        local_unix_ms,
        previous_commitment,
        role,
        plaintext,
    })
}

fn compute_commitment(header: &[u8], ciphertext: &[u8]) -> RecordCommitment {
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(header);
    hasher.update(ciphertext);
    RecordCommitment(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConversationSeed, RatchetState};

    #[test]
    fn round_trip_and_chain() {
        let signer = DeviceIdentity::generate().unwrap();
        let trusted = signer.public_identity();
        let conversation_id = ConversationId::generate().unwrap();
        let seed = ConversationSeed::generate().unwrap();
        let mut encrypt_ratchet = RatchetState::from_seed(&seed).unwrap();
        let mut decrypt_ratchet = RatchetState::from_seed(&seed).unwrap();

        let (seq0, key0) = encrypt_ratchet.next_key().unwrap();
        let message0 = InnerMessage {
            conversation_id,
            sequence: seq0,
            epoch: 0,
            local_unix_ms: 1_800_000_000_000,
            previous_commitment: ZERO_COMMITMENT,
            role: MessageRole::User,
            plaintext: SensitiveBytes::from_slice(b"hello local model"),
        };
        let record0 = JendRecord::seal(&message0, &key0, &signer).unwrap();
        let encoded0 = record0.encode().unwrap();
        assert!(!encoded0
            .windows(message0.plaintext.len())
            .any(|w| w == message0.plaintext.as_bytes()));

        let decoded0 = JendRecord::decode_exact(&encoded0).unwrap();
        let (dseq0, dkey0) = decrypt_ratchet.next_key().unwrap();
        let opened0 = decoded0
            .open_checked(&dkey0, &trusted, dseq0, ZERO_COMMITMENT)
            .unwrap();
        assert_eq!(opened0.sequence, message0.sequence);
        assert_eq!(opened0.plaintext, message0.plaintext);

        let (seq1, key1) = encrypt_ratchet.next_key().unwrap();
        let message1 = InnerMessage {
            conversation_id,
            sequence: seq1,
            epoch: 0,
            local_unix_ms: 1_800_000_000_500,
            previous_commitment: record0.commitment(),
            role: MessageRole::Assistant,
            plaintext: SensitiveBytes::from_slice(b"local answer"),
        };
        let record1 = JendRecord::seal(&message1, &key1, &signer).unwrap();

        let (dseq1, dkey1) = decrypt_ratchet.next_key().unwrap();
        let opened1 = record1
            .open_checked(&dkey1, &trusted, dseq1, record0.commitment())
            .unwrap();
        assert_eq!(opened1.sequence, message1.sequence);
        assert_eq!(opened1.plaintext, message1.plaintext);
    }

    #[test]
    fn ciphertext_tampering_is_detected_before_decryption() {
        let signer = DeviceIdentity::generate().unwrap();
        let conversation_id = ConversationId::generate().unwrap();
        let seed = ConversationSeed::generate().unwrap();
        let mut ratchet = RatchetState::from_seed(&seed).unwrap();
        let (seq, key) = ratchet.next_key().unwrap();

        let inner = InnerMessage {
            conversation_id,
            sequence: seq,
            epoch: 0,
            local_unix_ms: 42,
            previous_commitment: ZERO_COMMITMENT,
            role: MessageRole::User,
            plaintext: SensitiveBytes::from_slice(b"secret"),
        };

        let record = JendRecord::seal(&inner, &key, &signer).unwrap();
        let mut encoded = record.encode().unwrap();
        encoded[OUTER_HEADER_LEN + 3] ^= 0x80;

        let err = JendRecord::decode_exact(&encoded).unwrap_err();
        assert!(matches!(err, JendError::CommitmentMismatch));
    }

    #[test]
    fn wrong_device_cannot_validate_record() {
        let signer = DeviceIdentity::generate().unwrap();
        let attacker = DeviceIdentity::generate().unwrap();
        let seed = ConversationSeed::generate().unwrap();
        let mut ratchet = RatchetState::from_seed(&seed).unwrap();
        let (seq, key) = ratchet.next_key().unwrap();
        let inner = InnerMessage {
            conversation_id: ConversationId::generate().unwrap(),
            sequence: seq,
            epoch: 0,
            local_unix_ms: 0,
            previous_commitment: ZERO_COMMITMENT,
            role: MessageRole::System,
            plaintext: SensitiveBytes::from_slice(b"test"),
        };
        let record = JendRecord::seal(&inner, &key, &signer).unwrap();
        let err = record.open(&key, &attacker.public_identity()).unwrap_err();
        assert!(matches!(err, JendError::SignerMismatch));
    }
}
