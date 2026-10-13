use std::collections::{BTreeMap, HashMap};

use jend_core::{
    ConversationId, ConversationSeed, InnerMessage, JendRecord, RatchetState, RecordCommitment,
    ZERO_COMMITMENT,
};

use crate::{
    stable_topological_order, verify_nodes_with_history, DeviceSetHistory, Result, SignedMessageNode,
    SyncDeviceId, SyncError, SyncObjectId,
};

struct SenderOpenState {
    ratchet: RatchetState,
    previous_commitment: RecordCommitment,
}

/// Decrypts a complete conversation DAG using one independent message ratchet
/// per author device.
///
/// Preconditions are intentionally strict: all graph parents must be present,
/// every sync-node signature must verify against the DeviceSet history epoch,
/// every inner `.jend` signature must match the message-signing key bound into
/// that same trusted device identity, and the per-author Jend sequence/commitment
/// chain must agree with the DAG device counter chain.
pub fn open_conversation_dag(
    conversation_id: ConversationId,
    seed: &ConversationSeed,
    nodes: &BTreeMap<SyncObjectId, SignedMessageNode>,
    history: &DeviceSetHistory,
) -> Result<Vec<(SyncObjectId, InnerMessage)>> {
    verify_nodes_with_history(nodes, history)?;
    let order = stable_topological_order(nodes)?;
    let mut senders: HashMap<SyncDeviceId, SenderOpenState> = HashMap::new();
    let mut out = Vec::with_capacity(order.len());

    for object_id in order {
        let signed = nodes.get(&object_id).ok_or(SyncError::Malformed)?;
        let node = &signed.node;
        if node.conversation_id != conversation_id.0 {
            return Err(SyncError::ConversationMismatch);
        }
        let trusted = history.trusted_device(node.trust_epoch, node.author)?;
        let message_signer = trusted.message_public_identity()?;

        let sender = match senders.entry(node.author) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(SenderOpenState {
                    ratchet: RatchetState::from_seed_for_sender(seed, &node.author.0)?,
                    previous_commitment: ZERO_COMMITMENT,
                })
            }
        };

        let (sequence, message_key) = sender.ratchet.next_key()?;
        if sequence.checked_add(1) != Some(node.device_counter) {
            return Err(SyncError::InvalidDagClock);
        }
        let record = JendRecord::decode_exact(&node.jend_record)?;
        let inner = record.open_checked(
            &message_key,
            &message_signer,
            sequence,
            sender.previous_commitment,
        )?;
        if inner.conversation_id != conversation_id {
            return Err(SyncError::ConversationMismatch);
        }
        sender.previous_commitment = record.commitment();
        out.push((object_id, inner));
    }

    Ok(out)
}
