#![forbid(unsafe_code)]

//! Jend encrypted multi-device synchronization primitives.
//!
//! The server is intentionally treated as an untrusted object relay. Chat
//! graph structure, conversation identifiers, timestamps and `.jend` records
//! are carried inside epoch-encrypted sync objects. Device authorization is
//! signed by already-trusted devices, not asserted by the server.

mod codec;
mod conversation;
mod dag;
mod device;
mod device_set;
mod envelope;
mod error;
mod ids;
mod history;
mod index;
mod join;
mod keyring;
mod local_state;
mod object;
mod recovery;
mod relay;
mod session;

pub use conversation::open_conversation_dag;
pub use dag::{stable_topological_order, verify_nodes_with_history, MessageNode, SignedMessageNode};
pub use device::{SyncDeviceIdentity, SyncDevicePublic};
pub use device_set::{DeviceSet, SignedDeviceSet};
pub use envelope::{BootstrapPayload, KeyEnvelope};
pub use error::{Result, SyncError};
pub use ids::{AccountId, SyncDeviceId, SyncObjectId};
pub use history::DeviceSetHistory;
pub use index::{ConversationSyncState, SignedSyncIndex, SyncIndex};
pub use join::{DeviceJoinRequest, PairingFingerprint};
pub use keyring::{SyncEpochSecret, SyncKeyring};
pub use local_state::LocalSyncState;
pub use object::{OpenedSyncObject, SyncObject, SyncObjectKind};
pub use recovery::{RecoveryApproval, RecoveryApprovalEnvelope, RecoveryCode, RecoveryRequest};
pub use relay::{all_devices_acked, RelayAck, RelayMailboxId, RelayUpload};
pub use session::{DeviceSessionChallenge, DeviceSessionProof};

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn encrypted_object_hides_kind_and_payload_from_wire() {
        let mut keyring = SyncKeyring::new();
        keyring.insert(1, SyncEpochSecret::generate().unwrap()).unwrap();
        let object = SyncObject::seal(&keyring, 1, SyncObjectKind::SyncIndex, b"secret-index").unwrap();
        let wire = object.encode_wire().unwrap();
        assert!(!wire.windows(b"secret-index".len()).any(|w| w == b"secret-index"));
        let decoded = SyncObject::decode_wire(object.object_id, &wire).unwrap();
        let opened = decoded.open(&keyring).unwrap();
        assert_eq!(opened.kind, SyncObjectKind::SyncIndex);
        assert_eq!(opened.payload.as_slice(), b"secret-index");
    }

    #[test]
    fn device_set_cannot_be_authorized_by_removed_device() {
        let a = SyncDeviceIdentity::generate().unwrap();
        let b = SyncDeviceIdentity::generate().unwrap();
        let account = AccountId::generate().unwrap();
        let genesis = SignedDeviceSet::sign_genesis(DeviceSet::genesis(account, a.public_identity()), &a).unwrap();
        genesis.verify_genesis().unwrap();

        let set1 = DeviceSet::transition_from(&genesis, vec![a.public_identity(), b.public_identity()]).unwrap();
        let signed1 = SignedDeviceSet::sign_transition(&genesis, set1, &a).unwrap();
        signed1.verify_transition(&genesis).unwrap();

        let set2 = DeviceSet::transition_from(&signed1, vec![a.public_identity()]).unwrap();
        let signed2 = SignedDeviceSet::sign_transition(&signed1, set2, &a).unwrap();
        signed2.verify_transition(&signed1).unwrap();

        let set3 = DeviceSet::transition_from(&signed2, vec![a.public_identity(), b.public_identity()]).unwrap();
        assert!(matches!(SignedDeviceSet::sign_transition(&signed2, set3, &b), Err(SyncError::UntrustedDevice)));
    }

    #[test]
    fn device_session_proof_is_bound_to_exact_challenge() {
        let device = SyncDeviceIdentity::generate().unwrap();
        let account = AccountId::generate().unwrap();
        let challenge = DeviceSessionChallenge::generate(account, [7u8; 16], 1_000).unwrap();
        let proof = DeviceSessionProof::sign(&challenge, &device);
        proof.verify(&challenge, &device.public_identity(), 1_001).unwrap();

        let mut altered = challenge.clone();
        altered.session_binding = [8u8; 16];
        assert!(proof.verify(&altered, &device.public_identity(), 1_001).is_err());
    }

    #[test]
    fn bootstrap_keyring_is_encrypted_to_recipient_device() {
        let sender = SyncDeviceIdentity::generate().unwrap();
        let recipient = SyncDeviceIdentity::generate().unwrap();
        let account = AccountId::generate().unwrap();
        let mut keyring = SyncKeyring::new();
        keyring.insert(4, SyncEpochSecret::generate().unwrap()).unwrap();
        let genesis = SignedDeviceSet::sign_genesis(
            DeviceSet::genesis(account, sender.public_identity()),
            &sender,
        ).unwrap();
        let history = DeviceSetHistory::from_genesis(genesis).unwrap();
        let envelope = KeyEnvelope::seal(
            account,
            4,
            &sender,
            &recipient.public_identity(),
            &keyring,
            &history,
            [9u8; 32],
            [0u8; 32],
            None,
            12,
        ).unwrap();
        let opened = envelope.open(&recipient, &sender.public_identity()).unwrap();
        assert!(opened.keyring.contains_epoch(4));
        assert_eq!(opened.index_generation, 12);
    }

    #[test]
    fn dag_order_is_causal_and_stable() {
        let device = SyncDeviceIdentity::generate().unwrap();
        let public = device.public_identity();
        let a = SyncObjectId([1u8; 32]);
        let b = SyncObjectId([2u8; 32]);
        let c = SyncObjectId([3u8; 32]);
        let n1 = SignedMessageNode::sign(MessageNode {
            conversation_id: [7u8; 16],
            parents: vec![],
            author_previous: None,
            author: public.device_id,
            trust_epoch: 0,
            device_counter: 1,
            lamport: 1,
            jend_record: vec![1],
        }, &device).unwrap();
        let n2 = SignedMessageNode::sign(MessageNode {
            conversation_id: [7u8; 16],
            parents: vec![a],
            author_previous: Some(a),
            author: public.device_id,
            trust_epoch: 0,
            device_counter: 2,
            lamport: 2,
            jend_record: vec![2],
        }, &device).unwrap();
        let device2 = SyncDeviceIdentity::generate().unwrap();
        let public2 = device2.public_identity();
        let n3 = SignedMessageNode::sign(MessageNode {
            conversation_id: [7u8; 16],
            parents: vec![a],
            author_previous: None,
            author: public2.device_id,
            trust_epoch: 0,
            device_counter: 1,
            lamport: 2,
            jend_record: vec![3],
        }, &device2).unwrap();
        let mut nodes = BTreeMap::new();
        nodes.insert(a, n1);
        nodes.insert(b, n2);
        nodes.insert(c, n3);
        let order = stable_topological_order(&nodes).unwrap();
        assert_eq!(order[0], a);
        assert_eq!(BTreeSet::from([order[1], order[2]]), BTreeSet::from([b, c]));
    }
    #[test]
    fn join_request_is_self_signed_and_pairing_fingerprint_changes_on_substitution() {
        let existing = SyncDeviceIdentity::generate().unwrap();
        let candidate = SyncDeviceIdentity::generate().unwrap();
        let attacker = SyncDeviceIdentity::generate().unwrap();
        let account = AccountId::generate().unwrap();
        let request = DeviceJoinRequest::create(account, &candidate, 1_000_000).unwrap();
        request.verify(1_000_100).unwrap();
        let fingerprint = request.pairing_fingerprint(&existing.public_identity());

        let substituted = DeviceJoinRequest::create(account, &attacker, 1_000_000).unwrap();
        let attacker_fingerprint = substituted.pairing_fingerprint(&existing.public_identity());
        assert_ne!(fingerprint, attacker_fingerprint);
    }

}
