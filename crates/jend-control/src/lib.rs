#![forbid(unsafe_code)]

//! Server-side control-plane contracts.
//!
//! This crate intentionally contains no chat plaintext, conversation keys, or
//! model inference. It defines atomic persistence boundaries needed by auth,
//! recovery, device trust, and later model entitlements.

use jend_auth::{PasswordResetRegistrationFinish, Username};
use jend_model_store::{DeviceInstallation, ManifestId, ModelEntitlement, ModelId, ModelSlot, SignedModelManifest};
use jend_sync::{AccountId, SignedDeviceSet, SyncDeviceId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("account not found")]
    AccountNotFound,
    #[error("recovery grant was already consumed")]
    RecoveryGrantConsumed,
    #[error("recovery grant binding mismatch")]
    RecoveryGrantBindingMismatch,
    #[error("device-set rollback or conflict")]
    DeviceSetConflict,
    #[error("model entitlement conflict")]
    ModelEntitlementConflict,
    #[error("model entitlement not found")]
    ModelEntitlementNotFound,
    #[error("model release not found")]
    ModelReleaseNotFound,
    #[error("device is not currently trusted")]
    UntrustedDevice,
    #[error("persistence failure")]
    Persistence,
}

pub type Result<T> = core::result::Result<T, ControlError>;

/// Minimal account data the control plane is allowed to persist.
///
/// There is deliberately no message/history field here.
#[derive(Clone, Debug)]
pub struct AccountAuthRecord {
    pub account_id: AccountId,
    pub username: Username,
    pub opaque_password_file: Vec<u8>,
    pub auth_epoch: u64,
}

/// Persistence boundary for password reset. Implementations MUST perform the
/// grant consumption, credential replacement, and auth-epoch increment in one
/// database transaction. A duplicate `grant_nonce` must never rotate a password.
pub trait PasswordResetStore {
    fn consume_grant_and_rotate_password(
        &mut self,
        username: &Username,
        reset: PasswordResetRegistrationFinish,
    ) -> Result<u64>;
}

/// The server stores a signed DeviceSet only as control-plane authorization
/// metadata. It cannot create a valid next set because transitions require a
/// currently trusted device signature.
pub trait DeviceSetStore {
    fn current_device_set(&self, account_id: AccountId) -> Result<Option<SignedDeviceSet>>;

    fn compare_and_swap_device_set(
        &mut self,
        expected_epoch: u64,
        next: SignedDeviceSet,
    ) -> Result<()>;
}


/// Server-side persistence contract for the three account model slots.
/// Implementations MUST use optimistic compare-and-swap semantics; the DB schema
/// also constrains slots to 0..=2 so application bugs cannot create slot 4.
pub trait ModelEntitlementStore {
    fn entitlement(
        &self,
        account_id: AccountId,
        slot: ModelSlot,
    ) -> Result<Option<ModelEntitlement>>;

    fn compare_and_swap_entitlement(
        &mut self,
        expected_epoch: Option<u64>,
        next: ModelEntitlement,
    ) -> Result<()>;

    fn remove_entitlement(
        &mut self,
        account_id: AccountId,
        slot: ModelSlot,
        expected_epoch: u64,
    ) -> Result<()>;
}

/// Public catalog/release data. A release is accepted by clients only after the
/// embedded offline release signature has been verified. DB trust is insufficient.
pub trait ModelCatalogStore {
    fn signed_manifest(&self, manifest_id: ManifestId) -> Result<Option<SignedModelManifest>>;
    fn latest_manifest(&self, model_id: ModelId) -> Result<Option<SignedModelManifest>>;
}

/// Installation bookkeeping is deliberately separate from account entitlements.
/// A control-plane implementation must verify that `device_id` is present in the
/// current signed DeviceSet before recording or authorizing a download.
pub trait ModelInstallationStore {
    fn installation(
        &self,
        account_id: AccountId,
        device_id: SyncDeviceId,
        model_id: ModelId,
    ) -> Result<Option<DeviceInstallation>>;

    fn upsert_installation(&mut self, installation: DeviceInstallation) -> Result<()>;
}
