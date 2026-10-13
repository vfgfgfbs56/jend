use std::{collections::{BTreeMap, BTreeSet, HashMap}, path::Path};

use jend_core::{
    AccountRootKey, ConversationId, ConversationSeed, DeviceIdentity, DevicePublicIdentity,
    InnerMessage, JendRecord, MessageRole, RatchetState, RecordCommitment, SensitiveBytes,
    WrappedConversationSeed, ZERO_COMMITMENT,
};
use jend_sync::{
    open_conversation_dag, AccountId, ConversationSyncState, DeviceSet, DeviceSetHistory,
    KeyEnvelope, LocalSyncState,
    RecoveryApproval, RecoveryApprovalEnvelope, RecoveryCode, RecoveryRequest, SignedDeviceSet,
    SignedMessageNode, SignedSyncIndex, SyncDeviceIdentity, SyncDevicePublic, SyncEpochSecret, SyncIndex, SyncKeyring,
    SyncObject, SyncObjectId, SyncObjectKind,
};

use crate::{Result, SecretStore, VaultError, VaultStorage};

struct ConversationRuntime {
    ratchet: RatchetState,
    previous: RecordCommitment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncStatus {
    pub account_id: AccountId,
    pub device_set_epoch: u64,
    pub device_set_hash: [u8; 32],
    pub latest_index: Option<SyncObjectId>,
    pub index_generation: u64,
}

pub struct Vault {
    account_root: AccountRootKey,
    device: DeviceIdentity,
    device_public: DevicePublicIdentity,
    sync_device: SyncDeviceIdentity,
    sync_device_public: SyncDevicePublic,
    storage: VaultStorage,
    index: HashMap<ConversationId, WrappedConversationSeed>,
    runtime: HashMap<ConversationId, ConversationRuntime>,
    sync_state: Option<LocalSyncState>,
}

impl Vault {
    pub fn open(root: impl AsRef<Path>, secret_store: &impl SecretStore) -> Result<Self> {
        let mut ark_bytes = secret_store.load_or_create_32("account-root-key")?;
        let account_root = AccountRootKey::from_secret_bytes(&mut *ark_bytes);
        let mut device_bytes = secret_store.load_or_create_32("device-signing-key")?;
        let device = DeviceIdentity::from_secret_bytes(&mut *device_bytes);
        let device_public = device.public_identity();

        let mut sync_signing = secret_store.load_or_create_32("sync-device-signing-key")?;
        let mut sync_kex = secret_store.load_or_create_32("sync-device-kex-key")?;
        let sync_device = SyncDeviceIdentity::from_secret_bytes_with_message_key(
            &mut *sync_signing,
            &mut *sync_kex,
            device_public.as_bytes(),
        );
        let sync_device_public = sync_device.public_identity();

        let storage = VaultStorage::new(root)?;
        let index = storage.load_index(&account_root)?;
        let sync_state = match storage.load_sync_state_blob()? {
            Some(blob) => Some(LocalSyncState::open_local(&account_root, &blob)?),
            None => None,
        };

        let mut vault = Self {
            account_root,
            device,
            device_public,
            sync_device,
            sync_device_public,
            storage,
            index,
            runtime: HashMap::new(),
            sync_state,
        };
        vault.rebuild_runtime()?;
        Ok(vault)
    }

    pub fn device_public_identity(&self) -> DevicePublicIdentity {
        self.device_public.clone()
    }

    pub fn sync_device_public_identity(&self) -> SyncDevicePublic {
        self.sync_device_public.clone()
    }

    /// Enables multi-device sync for an account on its first trusted device.
    /// The sync epoch secret is generated locally and stored only inside the
    /// AccountRootKey-sealed Vault state.
    pub fn enable_sync(&mut self) -> Result<SyncStatus> {
        if self.sync_state.is_none() {
            let account_id = AccountId::generate()?;
            let genesis = DeviceSet::genesis(account_id, self.sync_device_public.clone());
            let signed = SignedDeviceSet::sign_genesis(genesis, &self.sync_device)?;
            let device_history = DeviceSetHistory::from_genesis(signed.clone())?;
            let mut keyring = SyncKeyring::new();
            keyring.insert(0, SyncEpochSecret::generate()?)?;
            let state = LocalSyncState {
                account_id,
                current_device_set: signed,
                device_history,
                keyring,
                latest_index: None,
                index_generation: 0,
            };
            self.persist_sync_state(&state)?;
            self.sync_state = Some(state);
        }
        self.sync_status().ok_or(VaultError::MalformedMetadata)
    }

    pub fn sync_status(&self) -> Option<SyncStatus> {
        self.sync_state.as_ref().map(|state| SyncStatus {
            account_id: state.account_id,
            device_set_epoch: state.current_device_set.set.epoch,
            device_set_hash: state.current_device_set.hash(),
            latest_index: state.latest_index,
            index_generation: state.index_generation,
        })
    }

    /// Adds/removes trusted sync devices using a staged state transition. The
    /// new state is sealed+fsynced before the in-memory trust epoch changes.
    pub fn change_sync_devices(&mut self, devices: Vec<SyncDevicePublic>) -> Result<SyncStatus> {
        let current = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        let staged = current.stage_device_set_change(&self.sync_device, devices)?;
        self.persist_sync_state(&staged)?;
        self.sync_state = Some(staged);
        self.sync_status().ok_or(VaultError::MalformedMetadata)
    }

    pub fn sync_bootstrap_envelope(&self, recipient: &SyncDevicePublic) -> Result<KeyEnvelope> {
        let state = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        Ok(state.bootstrap_envelope(&self.sync_device, recipient)?)
    }

    /// Creates the self-signed recovery request used on a new device after the
    /// server resolves a username to its opaque account id. This does not grant
    /// chat access and does not trust the server-provided DeviceSet.
    pub fn create_recovery_request(
        &self,
        account_id: AccountId,
        now_unix_ms: i64,
    ) -> Result<RecoveryRequest> {
        Ok(RecoveryRequest::create(account_id, &self.sync_device, now_unix_ms)?)
    }

    /// Approves password recovery on an already trusted device. The returned
    /// six-digit code is displayed locally and MUST NOT be sent through the
    /// relay/API. Only the opaque envelope is network-visible.
    pub fn approve_recovery_request(
        &self,
        request: &RecoveryRequest,
        now_unix_ms: i64,
    ) -> Result<(RecoveryApprovalEnvelope, RecoveryCode)> {
        let state = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        if request.account_id != state.account_id {
            return Err(VaultError::MalformedMetadata);
        }
        Ok(RecoveryApprovalEnvelope::approve(
            request,
            &state.current_device_set,
            &self.sync_device,
            now_unix_ms,
        )?)
    }

    /// Opens a code-bound approval on the candidate/new device. Supplying the
    /// wrong code, a substituted approver key, or the wrong candidate private
    /// key fails AEAD authentication.
    pub fn open_recovery_approval(
        &self,
        request: &RecoveryRequest,
        envelope: &RecoveryApprovalEnvelope,
        approver: &SyncDevicePublic,
        code_text: &str,
        now_unix_ms: i64,
    ) -> Result<RecoveryApproval> {
        let code = RecoveryCode::parse(code_text)?;
        Ok(envelope.open(
            request,
            &self.sync_device,
            approver,
            &code,
            now_unix_ms,
        )?)
    }

    /// Builds the next encrypted sync-index object without mutating local
    /// anti-rollback state. Upload this opaque object through the Network
    /// process, then call `commit_uploaded_sync_index` with the exact object.
    pub fn prepare_sync_index(
        &self,
        cursors: &HashMap<ConversationId, (Vec<SyncObjectId>, u64)>,
    ) -> Result<SyncObject> {
        let state = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        let epoch = state.current_device_set.set.epoch;
        let generation = state
            .index_generation
            .checked_add(1)
            .ok_or(VaultError::MalformedMetadata)?;
        let mut conversations = Vec::with_capacity(self.index.len());
        for (conversation_id, local_envelope) in &self.index {
            let seed = self
                .account_root
                .unwrap_conversation_seed(&conversation_id.0, local_envelope)?;
            let wrapped_seed = state
                .keyring
                .wrap_conversation_seed(epoch, &conversation_id.0, &seed)?;
            let (heads, max_lamport) = cursors
                .get(conversation_id)
                .cloned()
                .unwrap_or_else(|| (Vec::new(), 0));
            conversations.push(ConversationSyncState {
                conversation_id: conversation_id.0,
                seed_epoch: epoch,
                wrapped_seed,
                heads,
                max_lamport,
            });
        }
        let index = SyncIndex {
            generation,
            device_set_epoch: epoch,
            device_set_hash: state.current_device_set.hash(),
            conversations,
            author: self.sync_device_public.device_id,
        };
        let signed = SignedSyncIndex::sign(index, &self.sync_device)?;
        let payload = signed.encode()?;
        Ok(SyncObject::seal(
            &state.keyring,
            epoch,
            SyncObjectKind::SyncIndex,
            &payload,
        )?)
    }

    /// Commits only an object that Vault can itself decrypt as a valid signed
    /// index. This prevents the network/UI process from forging upload state.
    pub fn commit_uploaded_sync_index(&mut self, object: &SyncObject) -> Result<SyncStatus> {
        let current = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        let opened = object.open(&current.keyring)?;
        if opened.kind != SyncObjectKind::SyncIndex {
            return Err(VaultError::MalformedMetadata);
        }
        let signed = SignedSyncIndex::decode(opened.payload.as_ref())?;
        let staged = current.stage_accept_index(object.object_id, &signed)?;
        self.persist_sync_state(&staged)?;
        self.sync_state = Some(staged);
        self.sync_status().ok_or(VaultError::MalformedMetadata)
    }

    /// Imports conversation seeds from a verified/decrypted sync index into
    /// this device's AccountRootKey-sealed local index. Existing local entries
    /// are never overwritten by remote data.
    pub fn import_sync_index_conversations(
        &mut self,
        signed: &SignedSyncIndex,
    ) -> Result<usize> {
        let state = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        let historical_set = state
            .device_history
            .get(signed.index.device_set_epoch)
            .ok_or(VaultError::MalformedMetadata)?;
        if historical_set.hash() != signed.index.device_set_hash {
            return Err(VaultError::MalformedMetadata);
        }
        let signer = historical_set
            .set
            .get(signed.index.author)
            .ok_or(VaultError::MalformedMetadata)?;
        signed.verify(signer)?;

        let mut inserted = Vec::new();
        for remote in &signed.index.conversations {
            let id = ConversationId(remote.conversation_id);
            if self.index.contains_key(&id) {
                continue;
            }
            let seed = state.keyring.unwrap_conversation_seed(
                remote.seed_epoch,
                &remote.conversation_id,
                &remote.wrapped_seed,
            )?;
            let local = self.account_root.wrap_conversation_seed(&remote.conversation_id, &seed)?;
            self.index.insert(id, local);
            inserted.push(id);
        }
        if inserted.is_empty() {
            return Ok(0);
        }
        if let Err(err) = self.storage.save_index(&self.account_root, &self.index) {
            for id in &inserted { self.index.remove(id); }
            return Err(err);
        }
        for id in &inserted {
            self.storage.ensure_log_exists(*id)?;
            let envelope = self.index.get(id).ok_or(VaultError::MalformedMetadata)?;
            let seed = self.account_root.unwrap_conversation_seed(&id.0, envelope)?;
            let ratchet = RatchetState::from_seed_for_sender(
                &seed,
                &self.sync_device_public.device_id.0,
            )?;
            self.runtime.insert(*id, ConversationRuntime {
                ratchet,
                previous: ZERO_COMMITMENT,
            });
        }
        Ok(inserted.len())
    }

    /// Validates and persists one downloaded opaque sync object. Message nodes
    /// are signature-checked against the DeviceSet epoch before being accepted.
    /// The local file stores the original encrypted JESP bytes, not plaintext.
    pub fn ingest_sync_object(&self, object: &SyncObject) -> Result<()> {
        let state = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        let opened = object.open(&state.keyring)?;
        match opened.kind {
            SyncObjectKind::MessageNode => {
                let node = SignedMessageNode::decode(opened.payload.as_ref())?;
                let signer = state
                    .device_history
                    .trusted_device(node.node.trust_epoch, node.node.author)?;
                node.verify(signer)?;
            }
            SyncObjectKind::SyncIndex => {
                let index = SignedSyncIndex::decode(opened.payload.as_ref())?;
                let historical = state
                    .device_history
                    .get(index.index.device_set_epoch)
                    .ok_or(VaultError::MalformedMetadata)?;
                if historical.hash() != index.index.device_set_hash {
                    return Err(VaultError::MalformedMetadata);
                }
                let signer = historical
                    .set
                    .get(index.index.author)
                    .ok_or(VaultError::MalformedMetadata)?;
                index.verify(signer)?;
            }
            _ => {}
        }
        self.storage.save_sync_object(object)
    }

    /// Returns only random opaque object ids that the Network process still
    /// needs to fetch. Parent ids are discovered by Vault after decrypting
    /// already-downloaded nodes, so the server never receives the plaintext DAG.
    pub fn missing_sync_objects_for_conversation(
        &self,
        signed_index: &SignedSyncIndex,
        conversation_id: ConversationId,
    ) -> Result<Vec<SyncObjectId>> {
        let state = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        let conversation = signed_index
            .index
            .conversations
            .iter()
            .find(|c| c.conversation_id == conversation_id.0)
            .ok_or(VaultError::ConversationNotFound)?;

        let mut todo: Vec<_> = conversation.heads.clone();
        let mut seen = BTreeSet::new();
        let mut missing = BTreeSet::new();
        while let Some(id) = todo.pop() {
            if !seen.insert(id) { continue; }
            let Some(object) = self.storage.load_sync_object(id)? else {
                missing.insert(id);
                continue;
            };
            let opened = object.open(&state.keyring)?;
            if opened.kind != SyncObjectKind::MessageNode {
                return Err(VaultError::MalformedMetadata);
            }
            let node = SignedMessageNode::decode(opened.payload.as_ref())?;
            if node.node.conversation_id != conversation_id.0 {
                return Err(VaultError::ConversationMismatch);
            }
            todo.extend(node.node.parents.iter().copied());
        }
        Ok(missing.into_iter().collect())
    }

    /// Reconstructs and decrypts a fully downloaded multi-device DAG. The
    /// caller must first fetch every id returned by
    /// `missing_sync_objects_for_conversation`.
    pub fn read_synced_history(
        &self,
        signed_index: &SignedSyncIndex,
        conversation_id: ConversationId,
    ) -> Result<Vec<InnerMessage>> {
        let state = self.sync_state.as_ref().ok_or(VaultError::MalformedMetadata)?;
        let conversation = signed_index
            .index
            .conversations
            .iter()
            .find(|c| c.conversation_id == conversation_id.0)
            .ok_or(VaultError::ConversationNotFound)?;

        let missing = self.missing_sync_objects_for_conversation(signed_index, conversation_id)?;
        if !missing.is_empty() {
            return Err(VaultError::SyncObjectsMissing);
        }

        let seed = state.keyring.unwrap_conversation_seed(
            conversation.seed_epoch,
            &conversation.conversation_id,
            &conversation.wrapped_seed,
        )?;
        let mut nodes = BTreeMap::new();
        let mut todo: Vec<_> = conversation.heads.clone();
        while let Some(id) = todo.pop() {
            if nodes.contains_key(&id) { continue; }
            let object = self
                .storage
                .load_sync_object(id)?
                .ok_or(VaultError::SyncObjectsMissing)?;
            let opened = object.open(&state.keyring)?;
            if opened.kind != SyncObjectKind::MessageNode {
                return Err(VaultError::MalformedMetadata);
            }
            let node = SignedMessageNode::decode(opened.payload.as_ref())?;
            todo.extend(node.node.parents.iter().copied());
            nodes.insert(id, node);
        }
        let opened = open_conversation_dag(
            conversation_id,
            &seed,
            &nodes,
            &state.device_history,
        )?;
        Ok(opened.into_iter().map(|(_, message)| message).collect())
    }

    pub fn conversation_ids(&self) -> Vec<ConversationId> {
        let mut ids: Vec<_> = self.index.keys().copied().collect();
        ids.sort_by_key(|id| id.0);
        ids
    }

    pub fn create_conversation(&mut self) -> Result<ConversationId> {
        let id = loop {
            let id = ConversationId::generate()?;
            if !self.index.contains_key(&id) {
                break id;
            }
        };
        let seed = ConversationSeed::generate()?;
        let envelope = self.account_root.wrap_conversation_seed(&id.0, &seed)?;
        let ratchet = RatchetState::from_seed_for_sender(&seed, &self.sync_device_public.device_id.0)?;

        self.index.insert(id, envelope);
        if let Err(err) = self.storage.save_index(&self.account_root, &self.index) {
            self.index.remove(&id);
            return Err(err);
        }
        if let Err(err) = self.storage.ensure_log_exists(id) {
            self.index.remove(&id);
            let _ = self.storage.save_index(&self.account_root, &self.index);
            return Err(err);
        }
        self.runtime.insert(id, ConversationRuntime { ratchet, previous: ZERO_COMMITMENT });
        Ok(id)
    }

    pub fn append_message(
        &mut self,
        id: ConversationId,
        role: MessageRole,
        local_unix_ms: i64,
        plaintext: SensitiveBytes,
    ) -> Result<RecordCommitment> {
        let runtime = self.runtime.get_mut(&id).ok_or(VaultError::ConversationNotFound)?;
        let prepared = runtime.ratchet.prepare_next()?;
        let inner = InnerMessage {
            conversation_id: id,
            sequence: prepared.sequence(),
            epoch: 0,
            local_unix_ms,
            previous_commitment: runtime.previous,
            role,
            plaintext,
        };
        let record = JendRecord::seal(&inner, prepared.message_key(), &self.device)?;
        let encoded = record.encode()?;

        // Durability boundary: only after append_record fsyncs successfully may
        // the in-memory ratchet transition be committed.
        self.storage.append_record(id, &encoded)?;
        let commitment = record.commitment();
        runtime.ratchet.commit_prepared(prepared)?;
        runtime.previous = commitment;
        Ok(commitment)
    }

    pub fn read_history(&self, id: ConversationId) -> Result<Vec<InnerMessage>> {
        let envelope = self.index.get(&id).ok_or(VaultError::ConversationNotFound)?;
        let seed = self.account_root.unwrap_conversation_seed(&id.0, envelope)?;
        let mut ratchet = RatchetState::from_seed_for_sender(&seed, &self.sync_device_public.device_id.0)?;
        let records = self.storage.read_records_recover_tail(id)?;
        let mut previous = ZERO_COMMITMENT;
        let mut out = Vec::with_capacity(records.len());

        for record in records {
            let (sequence, key) = ratchet.next_key()?;
            let inner = record.open_checked(&key, &self.device_public, sequence, previous)?;
            if inner.conversation_id != id {
                return Err(VaultError::ConversationMismatch);
            }
            previous = record.commitment();
            out.push(inner);
        }
        Ok(out)
    }

    fn persist_sync_state(&self, state: &LocalSyncState) -> Result<()> {
        let blob = state.seal_local(&self.account_root)?;
        self.storage.save_sync_state_blob(&blob)
    }

    fn rebuild_runtime(&mut self) -> Result<()> {
        for (id, envelope) in &self.index {
            let seed = self.account_root.unwrap_conversation_seed(&id.0, envelope)?;
            let mut ratchet = RatchetState::from_seed_for_sender(&seed, &self.sync_device_public.device_id.0)?;
            let records = self.storage.read_records_recover_tail(*id)?;
            let mut previous = ZERO_COMMITMENT;
            for record in records {
                let (sequence, key) = ratchet.next_key()?;
                let inner = record.open_checked(&key, &self.device_public, sequence, previous)?;
                if inner.conversation_id != *id {
                    return Err(VaultError::ConversationMismatch);
                }
                previous = record.commitment();
                // `inner` drops here and zeroizes plaintext.
            }
            self.runtime.insert(*id, ConversationRuntime { ratchet, previous });
        }
        Ok(())
    }
}
