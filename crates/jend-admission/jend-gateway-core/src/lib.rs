#![forbid(unsafe_code)]

use jend_admission::{AdmissionIssuer, AdmissionVerifier, LocalRateLimiter, RateKey, RegistrationChallenge, RiskSignals, TokenBucketConfig};
use jend_auth::{
    AuthError, AuthServer, RegistrationStart, ServerLoginFinish, Username,
};
use jend_capability::{
    CapabilityError, CapabilityIssuer, CapabilityVerifier, Permissions, SignedCapability,
};
use jend_model_store::{
    DeviceInstallation, DownloadGrant, InstallationState, ManifestId, ModelEntitlement, ModelId,
    ModelSlot, ModelStoreError, OnlineGrantSigningKey, SignedModelManifest,
};
use jend_sync::{
    AccountId, DeviceSessionChallenge, DeviceSessionProof, SignedDeviceSet, SyncDeviceId, SyncError,
};
use thiserror::Error;

const ACCOUNT_CAPABILITY_MS: i64 = 10 * 60 * 1000;
const DEVICE_CAPABILITY_MS: i64 = 15 * 60 * 1000;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("admission error: {0}")]
    Admission(#[from] jend_admission::AdmissionError),
    #[error("authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("capability error: {0}")]
    Capability(#[from] CapabilityError),
    #[error("sync/device error: {0}")]
    Sync(#[from] SyncError),
    #[error("model-store error: {0}")]
    ModelStore(#[from] ModelStoreError),
    #[error("username already exists")]
    UsernameExists,
    #[error("account not found")]
    AccountNotFound,
    #[error("device-set compare-and-swap failed")]
    DeviceSetConflict,
    #[error("model entitlement conflict")]
    ModelEntitlementConflict,
    #[error("model is not selected in the requested slot")]
    ModelNotSelected,
    #[error("model release does not match the selected model")]
    ModelManifestMismatch,
    #[error("repository failure")]
    Repository,
}

pub type Result<T> = core::result::Result<T, GatewayError>;

/// Registration admission sits in front of OPAQUE registration. It combines
/// privacy-normalized local token buckets with a short-lived, username-bound
/// adaptive proof-of-work challenge. A deployment may add Cloudflare/other
/// edge signals, but those are inputs rather than trust anchors.
pub struct RegistrationAdmission {
    issuer: AdmissionIssuer,
    limiter: LocalRateLimiter,
}

impl RegistrationAdmission {
    pub fn new(issuer: AdmissionIssuer) -> Self {
        Self {
            issuer,
            limiter: LocalRateLimiter::new(TokenBucketConfig::registration_default()),
        }
    }

    pub fn verifier(&self) -> AdmissionVerifier {
        self.issuer.verifier()
    }

    pub fn issue_challenge(
        &mut self,
        username: &Username,
        rate_keys: &[RateKey],
        risk: RiskSignals,
        now_unix_ms: i64,
    ) -> Result<RegistrationChallenge> {
        let now = u64::try_from(now_unix_ms.max(0)).map_err(|_| GatewayError::Repository)?;
        for key in rate_keys {
            self.limiter.check(*key, now)?;
        }
        self.limiter.prune(now);
        Ok(self.issuer.issue_for_username(
            username.as_str(),
            risk.proof_difficulty(),
            now_unix_ms,
            2 * 60 * 1000,
        )?)
    }

    pub fn verify_challenge(
        &self,
        challenge: &RegistrationChallenge,
        username: &Username,
        solution: u64,
        now_unix_ms: i64,
    ) -> Result<()> {
        Ok(self.verifier().verify(
            challenge,
            username.as_str(),
            solution,
            now_unix_ms,
        )?)
    }
}


#[derive(Clone)]
pub struct AccountRecord {
    pub account_id: AccountId,
    pub username: Username,
    pub opaque_password_file: Vec<u8>,
    pub auth_epoch: u64,
}

/// Persistence boundary intentionally contains no message/chat methods.
pub trait GatewayRepository {
    fn account_by_username(&self, username: &Username) -> Result<Option<AccountRecord>>;
    fn account_by_id(&self, account_id: AccountId) -> Result<Option<AccountRecord>>;
    fn create_account(
        &mut self,
        account_id: AccountId,
        username: Username,
        opaque_password_file: Vec<u8>,
    ) -> Result<AccountRecord>;

    fn device_set(&self, account_id: AccountId) -> Result<Option<SignedDeviceSet>>;

    /// Must be an atomic CAS in the concrete database implementation. `None`
    /// means genesis is allowed only when no DeviceSet exists. `Some(epoch)`
    /// requires the stored current epoch to equal `epoch`.
    fn compare_and_swap_device_set(
        &mut self,
        account_id: AccountId,
        expected_epoch: Option<u64>,
        next: SignedDeviceSet,
    ) -> Result<()>;
}

pub struct LoginStartResponse {
    pub response: Vec<u8>,
    pub ticket: Vec<u8>,
}

pub struct LoginFinishResponse {
    pub account_capability: SignedCapability,
    /// OPAQUE session key remains available to the upper transport layer for
    /// explicit channel binding if/when the HTTP protocol freezes that design.
    pub opaque: ServerLoginFinish,
}

pub struct Gateway<R: GatewayRepository> {
    auth: AuthServer,
    capabilities: CapabilityIssuer,
    repository: R,
}

impl<R: GatewayRepository> Gateway<R> {
    pub fn new(auth: AuthServer, capabilities: CapabilityIssuer, repository: R) -> Self {
        Self { auth, capabilities, repository }
    }

    pub fn capability_verifier(&self) -> CapabilityVerifier {
        self.capabilities.verifier()
    }

    pub fn repository(&self) -> &R { &self.repository }
    pub fn repository_mut(&mut self) -> &mut R { &mut self.repository }

    pub fn registration_start(
        &self,
        username: &Username,
        opaque_request: &[u8],
        now_unix_ms: i64,
    ) -> Result<RegistrationStart> {
        // Availability lookup is not a security proof; create_account below is
        // still required to enforce uniqueness atomically.
        if self.repository.account_by_username(username)?.is_some() {
            return Err(GatewayError::UsernameExists);
        }
        Ok(self.auth.registration_start(username, opaque_request, now_unix_ms)?)
    }

    pub fn registration_finish(
        &mut self,
        username: &Username,
        ticket: &[u8],
        upload: &[u8],
        now_unix_ms: i64,
    ) -> Result<AccountRecord> {
        let password_file = self.auth.registration_finish(username, ticket, upload, now_unix_ms)?;
        let account_id = AccountId::generate()?;
        self.repository
            .create_account(account_id, username.clone(), password_file)
    }

    pub fn login_start(
        &self,
        username: &Username,
        opaque_request: &[u8],
        now_unix_ms: i64,
    ) -> Result<LoginStartResponse> {
        let record = self.repository.account_by_username(username)?;
        let started = self.auth.login_start(
            username,
            record.as_ref().map(|r| r.opaque_password_file.as_slice()),
            opaque_request,
            now_unix_ms,
        )?;
        Ok(LoginStartResponse { response: started.response, ticket: started.ticket })
    }

    pub fn login_finish(
        &self,
        ticket: &[u8],
        finalization: &[u8],
        now_unix_ms: i64,
    ) -> Result<LoginFinishResponse> {
        let opaque = self.auth.login_finish(ticket, finalization, now_unix_ms)?;
        let record = self
            .repository
            .account_by_username(&opaque.username)?
            .ok_or(GatewayError::AccountNotFound)?;
        let permissions = Permissions::ACCOUNT_MANAGE
            .union(Permissions::DEVICE_ENROLL)
            .union(Permissions::MODEL_CATALOG);
        let account_capability = self.capabilities.issue(
            record.account_id,
            record.auth_epoch,
            None,
            permissions,
            now_unix_ms,
            ACCOUNT_CAPABILITY_MS,
        )?;
        Ok(LoginFinishResponse { account_capability, opaque })
    }

    pub fn begin_device_binding(
        &self,
        account_capability: &SignedCapability,
        now_unix_ms: i64,
    ) -> Result<DeviceSessionChallenge> {
        let verifier = self.capabilities.verifier();
        let record = self
            .repository
            .account_by_id(account_capability.claims.account_id)?
            .ok_or(GatewayError::AccountNotFound)?;
        verifier.verify(
            account_capability,
            now_unix_ms,
            Permissions::DEVICE_ENROLL,
            None,
            Some(record.auth_epoch),
        )?;
        Ok(DeviceSessionChallenge::generate(
            record.account_id,
            account_capability.claims.nonce,
            now_unix_ms,
        )?)
    }

    pub fn finish_device_binding(
        &self,
        account_capability: &SignedCapability,
        challenge: &DeviceSessionChallenge,
        proof: &DeviceSessionProof,
        now_unix_ms: i64,
    ) -> Result<SignedCapability> {
        let verifier = self.capabilities.verifier();
        let record = self
            .repository
            .account_by_id(account_capability.claims.account_id)?
            .ok_or(GatewayError::AccountNotFound)?;
        verifier.verify(
            account_capability,
            now_unix_ms,
            Permissions::DEVICE_ENROLL,
            None,
            Some(record.auth_epoch),
        )?;
        if challenge.account_id != record.account_id
            || challenge.session_binding != account_capability.claims.nonce
        {
            return Err(GatewayError::DeviceSetConflict);
        }
        let set = self.repository.device_set(record.account_id)?
            .ok_or(GatewayError::DeviceSetConflict)?;
        let device = set.set.get(proof.device_id).ok_or(GatewayError::DeviceSetConflict)?;
        proof.verify(challenge, device, now_unix_ms)?;

        let permissions = Permissions::SYNC_RELAY
            .union(Permissions::MODEL_CATALOG)
            .union(Permissions::MODEL_DOWNLOAD)
            .union(Permissions::ACCOUNT_MANAGE)
            .union(Permissions::DEVICE_ENROLL);
        Ok(self.capabilities.issue(
            record.account_id,
            record.auth_epoch,
            Some(proof.device_id),
            permissions,
            now_unix_ms,
            DEVICE_CAPABILITY_MS,
        )?)
    }

    /// Stores genesis or a client-authorized DeviceSet transition. The server
    /// is a persistence/CAS participant, never the source of device trust.
    pub fn submit_device_set(
        &mut self,
        account_capability: &SignedCapability,
        next: SignedDeviceSet,
        now_unix_ms: i64,
    ) -> Result<()> {
        let verifier = self.capabilities.verifier();
        let record = self
            .repository
            .account_by_id(account_capability.claims.account_id)?
            .ok_or(GatewayError::AccountNotFound)?;
        verifier.verify(
            account_capability,
            now_unix_ms,
            Permissions::DEVICE_ENROLL,
            account_capability.claims.device_id,
            Some(record.auth_epoch),
        )?;
        if next.set.account_id != record.account_id {
            return Err(GatewayError::DeviceSetConflict);
        }

        match self.repository.device_set(record.account_id)? {
            None => {
                next.verify_genesis()?;
                self.repository.compare_and_swap_device_set(record.account_id, None, next)
            }
            Some(current) => {
                next.verify_transition(&current)?;
                self.repository.compare_and_swap_device_set(
                    record.account_id,
                    Some(current.set.epoch),
                    next,
                )
            }
        }
    }
}


/// Model-store persistence boundary. It extends, rather than replaces, the
/// account/device repository. Concrete implementations should back slot CAS and
/// installation upserts with one DB transaction each.
pub trait ModelGatewayRepository: GatewayRepository {
    fn model_entitlement(
        &self,
        account_id: AccountId,
        slot: ModelSlot,
    ) -> Result<Option<ModelEntitlement>>;

    fn compare_and_swap_model_entitlement(
        &mut self,
        expected_epoch: Option<u64>,
        next: ModelEntitlement,
    ) -> Result<()>;

    fn remove_model_entitlement(
        &mut self,
        account_id: AccountId,
        slot: ModelSlot,
        expected_epoch: u64,
    ) -> Result<()>;

    fn signed_model_manifest(&self, manifest_id: ManifestId) -> Result<Option<SignedModelManifest>>;
    fn latest_model_manifest(&self, model_id: ModelId) -> Result<Option<SignedModelManifest>>;
    fn upsert_model_installation(&mut self, installation: DeviceInstallation) -> Result<()>;
}

/// Online model-access authority. This key is intentionally distinct from the
/// offline release key. Compromising it may authorize extra downloads, but it
/// cannot create a client-accepted malicious model release.
pub struct ModelAccessService {
    grants: OnlineGrantSigningKey,
}

impl ModelAccessService {
    pub fn new(grants: OnlineGrantSigningKey) -> Self {
        Self { grants }
    }

    pub fn select_model<R: ModelGatewayRepository>(
        &self,
        repository: &mut R,
        verifier: &CapabilityVerifier,
        capability: &SignedCapability,
        device_id: SyncDeviceId,
        slot: ModelSlot,
        model_id: ModelId,
        expected_epoch: Option<u64>,
        pinned_manifest: Option<ManifestId>,
        now_unix_ms: i64,
    ) -> Result<ModelEntitlement> {
        let account = repository
            .account_by_id(capability.claims.account_id)?
            .ok_or(GatewayError::AccountNotFound)?;
        require_device_capability(
            verifier,
            capability,
            device_id,
            Permissions::ACCOUNT_MANAGE,
            account.auth_epoch,
            now_unix_ms,
        )?;
        require_current_trusted_device(repository, account.account_id, device_id)?;

        if let Some(manifest_id) = pinned_manifest {
            let signed = repository
                .signed_model_manifest(manifest_id)?
                .ok_or(GatewayError::ModelManifestMismatch)?;
            if signed.manifest.model_id != model_id {
                return Err(GatewayError::ModelManifestMismatch);
            }
        }

        let next_epoch = match expected_epoch {
            Some(epoch) => epoch.checked_add(1).ok_or(GatewayError::ModelEntitlementConflict)?,
            None => 0,
        };
        let next = ModelEntitlement {
            account_id: account.account_id,
            slot,
            model_id,
            entitlement_epoch: next_epoch,
            manifest_id: pinned_manifest,
        };
        repository.compare_and_swap_model_entitlement(expected_epoch, next.clone())?;
        Ok(next)
    }

    pub fn remove_model<R: ModelGatewayRepository>(
        &self,
        repository: &mut R,
        verifier: &CapabilityVerifier,
        capability: &SignedCapability,
        device_id: SyncDeviceId,
        slot: ModelSlot,
        expected_epoch: u64,
        now_unix_ms: i64,
    ) -> Result<()> {
        let account = repository
            .account_by_id(capability.claims.account_id)?
            .ok_or(GatewayError::AccountNotFound)?;
        require_device_capability(
            verifier,
            capability,
            device_id,
            Permissions::ACCOUNT_MANAGE,
            account.auth_epoch,
            now_unix_ms,
        )?;
        require_current_trusted_device(repository, account.account_id, device_id)?;
        repository.remove_model_entitlement(account.account_id, slot, expected_epoch)
    }

    pub fn authorize_download<R: ModelGatewayRepository>(
        &self,
        repository: &mut R,
        verifier: &CapabilityVerifier,
        capability: &SignedCapability,
        device_id: SyncDeviceId,
        slot: ModelSlot,
        requested_manifest: Option<ManifestId>,
        now_unix_ms: i64,
    ) -> Result<(SignedModelManifest, DownloadGrant)> {
        let account = repository
            .account_by_id(capability.claims.account_id)?
            .ok_or(GatewayError::AccountNotFound)?;
        require_device_capability(
            verifier,
            capability,
            device_id,
            Permissions::MODEL_DOWNLOAD,
            account.auth_epoch,
            now_unix_ms,
        )?;
        require_current_trusted_device(repository, account.account_id, device_id)?;

        let entitlement = repository
            .model_entitlement(account.account_id, slot)?
            .ok_or(GatewayError::ModelNotSelected)?;

        let manifest = match requested_manifest.or(entitlement.manifest_id) {
            Some(id) => repository
                .signed_model_manifest(id)?
                .ok_or(GatewayError::ModelManifestMismatch)?,
            None => repository
                .latest_model_manifest(entitlement.model_id)?
                .ok_or(GatewayError::ModelManifestMismatch)?,
        };
        if manifest.manifest.model_id != entitlement.model_id {
            return Err(GatewayError::ModelManifestMismatch);
        }
        if let Some(pinned) = entitlement.manifest_id {
            if pinned != manifest.manifest_id {
                return Err(GatewayError::ModelManifestMismatch);
            }
        }

        let issued = u64::try_from(now_unix_ms / 1000).map_err(|_| GatewayError::Repository)?;
        let expires = issued.checked_add(10 * 60).ok_or(GatewayError::Repository)?;
        let grant = self.grants.issue(
            device_id,
            entitlement.model_id,
            manifest.manifest_id,
            slot,
            entitlement.entitlement_epoch,
            issued,
            expires,
        )?;

        repository.upsert_model_installation(DeviceInstallation {
            account_id: account.account_id,
            device_id,
            model_id: entitlement.model_id,
            manifest_id: manifest.manifest_id,
            state: InstallationState::Requested,
            installation_generation: entitlement.entitlement_epoch,
        })?;

        Ok((manifest, grant))
    }
}

fn require_current_trusted_device<R: GatewayRepository>(
    repository: &R,
    account_id: AccountId,
    device_id: SyncDeviceId,
) -> Result<()> {
    let set = repository.device_set(account_id)?.ok_or(GatewayError::DeviceSetConflict)?;
    if set.set.get(device_id).is_none() {
        return Err(GatewayError::DeviceSetConflict);
    }
    Ok(())
}

/// Utility for concrete repositories to validate device-bound requests.
pub fn require_device_capability(
    verifier: &CapabilityVerifier,
    capability: &SignedCapability,
    device_id: SyncDeviceId,
    permission: Permissions,
    current_auth_epoch: u64,
    now_unix_ms: i64,
) -> Result<AccountId> {
    verifier.verify(
        capability,
        now_unix_ms,
        permission,
        Some(device_id),
        Some(current_auth_epoch),
    )?;
    Ok(capability.claims.account_id)
}
