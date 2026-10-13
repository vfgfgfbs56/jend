use jend_core::WrappedConversationSeed;
use crate::{
    codec::{put_u16, put_u64, Reader}, Result, SyncDeviceId, SyncDeviceIdentity,
    SyncDevicePublic, SyncError, SyncObjectId,
};

const INDEX_DOMAIN: &[u8] = b"JEND/SYNC-INDEX/V1";
const MAX_CONVERSATIONS: usize = 100_000;
const MAX_HEADS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationSyncState {
    pub conversation_id: [u8; 16],
    /// Sync epoch whose secret wraps this conversation seed.
    pub seed_epoch: u64,
    pub wrapped_seed: WrappedConversationSeed,
    pub heads: Vec<SyncObjectId>,
    pub max_lamport: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncIndex {
    pub generation: u64,
    pub device_set_epoch: u64,
    pub device_set_hash: [u8; 32],
    pub conversations: Vec<ConversationSyncState>,
    pub author: SyncDeviceId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSyncIndex {
    pub index: SyncIndex,
    pub signature: [u8; 64],
}

impl SyncIndex {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.conversations.len() > MAX_CONVERSATIONS {
            return Err(SyncError::Malformed);
        }
        let mut conversations = self.conversations.clone();
        conversations.sort_by_key(|c| c.conversation_id);
        if conversations.windows(2).any(|pair| pair[0].conversation_id == pair[1].conversation_id) {
            return Err(SyncError::Malformed);
        }
        let mut out = Vec::new();
        put_u64(&mut out, self.generation);
        put_u64(&mut out, self.device_set_epoch);
        out.extend_from_slice(&self.device_set_hash);
        out.extend_from_slice(&self.author.0);
        out.extend_from_slice(&(conversations.len() as u32).to_be_bytes());
        for conversation in conversations {
            if conversation.heads.len() > MAX_HEADS {
                return Err(SyncError::Malformed);
            }
            let mut heads = conversation.heads.clone();
            heads.sort();
            heads.dedup();
            if heads.len() != conversation.heads.len() {
                return Err(SyncError::Malformed);
            }
            if conversation.wrapped_seed.ciphertext.len() > u16::MAX as usize {
                return Err(SyncError::ObjectTooLarge);
            }
            out.extend_from_slice(&conversation.conversation_id);
            put_u64(&mut out, conversation.seed_epoch);
            out.extend_from_slice(&conversation.wrapped_seed.nonce);
            put_u16(&mut out, conversation.wrapped_seed.ciphertext.len() as u16);
            out.extend_from_slice(&conversation.wrapped_seed.ciphertext);
            put_u64(&mut out, conversation.max_lamport);
            put_u16(&mut out, heads.len() as u16);
            for head in heads {
                out.extend_from_slice(&head.0);
            }
        }
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let generation = r.u64()?;
        let device_set_epoch = r.u64()?;
        let device_set_hash = r.array()?;
        let author = SyncDeviceId(r.array()?);
        let count = r.u32()? as usize;
        if count > MAX_CONVERSATIONS {
            return Err(SyncError::Malformed);
        }
        let mut conversations = Vec::with_capacity(count);
        for _ in 0..count {
            let conversation_id = r.array()?;
            let seed_epoch = r.u64()?;
            let seed_nonce = r.array()?;
            let seed_len = r.u16()? as usize;
            if seed_len == 0 || seed_len > 1024 {
                return Err(SyncError::Malformed);
            }
            let wrapped_seed = WrappedConversationSeed {
                nonce: seed_nonce,
                ciphertext: r.take(seed_len)?.to_vec(),
            };
            let max_lamport = r.u64()?;
            let head_count = r.u16()? as usize;
            if head_count > MAX_HEADS {
                return Err(SyncError::Malformed);
            }
            let mut heads = Vec::with_capacity(head_count);
            for _ in 0..head_count {
                heads.push(SyncObjectId(r.array()?));
            }
            if !heads.windows(2).all(|pair| pair[0] < pair[1]) {
                return Err(SyncError::Malformed);
            }
            conversations.push(ConversationSyncState {
                conversation_id,
                seed_epoch,
                wrapped_seed,
                heads,
                max_lamport,
            });
        }
        r.finish()?;
        if !conversations.windows(2).all(|pair| pair[0].conversation_id < pair[1].conversation_id) {
            return Err(SyncError::Malformed);
        }
        Ok(Self {
            generation,
            device_set_epoch,
            device_set_hash,
            conversations,
            author,
        })
    }
}

impl SignedSyncIndex {
    pub fn sign(index: SyncIndex, signer: &SyncDeviceIdentity) -> Result<Self> {
        if signer.public_identity().device_id != index.author {
            return Err(SyncError::UntrustedDevice);
        }
        let signature = signer.sign(INDEX_DOMAIN, &index.canonical_bytes()?);
        Ok(Self { index, signature })
    }

    pub fn verify(&self, signer: &SyncDevicePublic) -> Result<()> {
        if signer.device_id != self.index.author {
            return Err(SyncError::UntrustedDevice);
        }
        signer.verify(INDEX_DOMAIN, &self.index.canonical_bytes()?, &self.signature)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let index = self.index.canonical_bytes()?;
        let mut out = Vec::with_capacity(4 + index.len() + 64);
        out.extend_from_slice(&(index.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let len = r.u32()? as usize;
        let index = SyncIndex::from_canonical_bytes(r.take(len)?)?;
        let signature = r.array()?;
        r.finish()?;
        Ok(Self { index, signature })
    }
}
