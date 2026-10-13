use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ConversationSeed, JendError, Result};

const INIT_INFO: &[u8] = b"JEND/RATCHET/INIT/V1";
const STEP_INFO: &[u8] = b"JEND/RATCHET/STEP/V1";
const SENDER_INIT_INFO: &[u8] = b"JEND/RATCHET/SENDER-INIT/V1";
const MAX_SENDER_CONTEXT: usize = 256;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub(crate) [u8; 32]);

pub struct PreparedRatchetStep {
    sequence: u64,
    message_key: MessageKey,
    next_chain: Zeroizing<[u8; 32]>,
}

pub struct RatchetState {
    chain_key: Zeroizing<[u8; 32]>,
    sequence: u64,
}

impl RatchetState {
    pub fn from_seed(seed: &ConversationSeed) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, &seed.0);
        let mut chain_key = [0u8; 32];
        hk.expand(INIT_INFO, &mut chain_key)
            .map_err(|_| JendError::Kdf)?;
        Ok(Self {
            chain_key: Zeroizing::new(chain_key),
            sequence: 0,
        })
    }

    /// Initializes an independent sender chain for a multi-device conversation.
    /// Different sender contexts derive unrelated initial chain keys from the
    /// same conversation seed.
    pub fn from_seed_for_sender(seed: &ConversationSeed, sender_context: &[u8]) -> Result<Self> {
        if sender_context.is_empty() || sender_context.len() > MAX_SENDER_CONTEXT {
            return Err(JendError::Kdf);
        }
        let hk = Hkdf::<Sha256>::new(Some(sender_context), &seed.0);
        let mut info = Vec::with_capacity(SENDER_INIT_INFO.len() + 2 + sender_context.len());
        info.extend_from_slice(SENDER_INIT_INFO);
        info.extend_from_slice(&(sender_context.len() as u16).to_be_bytes());
        info.extend_from_slice(sender_context);
        let mut chain_key = [0u8; 32];
        hk.expand(&info, &mut chain_key).map_err(|_| JendError::Kdf)?;
        Ok(Self {
            chain_key: Zeroizing::new(chain_key),
            sequence: 0,
        })
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Derives the next message key and next chain key without mutating the
    /// ratchet. This allows storage code to fsync a record before committing
    /// the in-memory ratchet transition.
    pub fn prepare_next(&self) -> Result<PreparedRatchetStep> {
        let seq = self.sequence;
        let (message_key, next_chain) = derive_step(&*self.chain_key, seq)?;
        Ok(PreparedRatchetStep {
            sequence: seq,
            message_key,
            next_chain: Zeroizing::new(next_chain),
        })
    }

    /// Commits a previously prepared transition after durable storage succeeds.
    pub fn commit_prepared(&mut self, step: PreparedRatchetStep) -> Result<()> {
        if step.sequence != self.sequence {
            return Err(JendError::SequenceMismatch {
                expected: self.sequence,
                got: step.sequence,
            });
        }
        self.chain_key.as_mut().zeroize();
        *self.chain_key = *step.next_chain;
        self.sequence = self.sequence.checked_add(1).ok_or(JendError::Kdf)?;
        Ok(())
    }

    /// Convenience transition for callers that do not need transactional
    /// durability. Persistent stores should prefer prepare_next/commit_prepared.
    pub fn next_key(&mut self) -> Result<(u64, MessageKey)> {
        let seq = self.sequence;
        let (message_key, next_chain) = derive_step(&*self.chain_key, seq)?;
        self.chain_key.as_mut().zeroize();
        *self.chain_key = next_chain;
        self.sequence = self.sequence.checked_add(1).ok_or(JendError::Kdf)?;
        Ok((seq, message_key))
    }
}

impl PreparedRatchetStep {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn message_key(&self) -> &MessageKey {
        &self.message_key
    }
}

fn derive_step(chain_key: &[u8; 32], seq: u64) -> Result<(MessageKey, [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(None, chain_key);
    let mut info = Vec::with_capacity(STEP_INFO.len() + 8);
    info.extend_from_slice(STEP_INFO);
    info.extend_from_slice(&seq.to_be_bytes());

    let mut output = Zeroizing::new([0u8; 64]);
    hk.expand(&info, output.as_mut())
        .map_err(|_| JendError::Kdf)?;

    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&output[..32]);
    let mut next_chain = [0u8; 32];
    next_chain.copy_from_slice(&output[32..]);
    Ok((MessageKey(message_key), next_chain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_step_does_not_advance_until_commit() {
        let seed = ConversationSeed::generate().unwrap();
        let mut ratchet = RatchetState::from_seed(&seed).unwrap();
        let step = ratchet.prepare_next().unwrap();
        assert_eq!(step.sequence(), 0);
        assert_eq!(ratchet.sequence(), 0);
        ratchet.commit_prepared(step).unwrap();
        assert_eq!(ratchet.sequence(), 1);
    }
    #[test]
    fn sender_chains_are_separated() {
        let seed = ConversationSeed::generate().unwrap();
        let mut a = RatchetState::from_seed_for_sender(&seed, b"device-a").unwrap();
        let mut b = RatchetState::from_seed_for_sender(&seed, b"device-b").unwrap();
        let (_, ka) = a.next_key().unwrap();
        let (_, kb) = b.next_key().unwrap();
        assert_ne!(ka.0, kb.0);
    }

}
