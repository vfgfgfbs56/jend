use jend_sync::{AccountId, SyncDeviceId};

use crate::{ManifestId, ModelId, ModelStoreError, Result};

/// Exactly three account-level model selections exist: slots 0, 1 and 2.
/// The DB mirrors this as a CHECK constraint, so a fourth slot cannot be
/// created even if the application server is buggy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ModelSlot(u8);

impl ModelSlot {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const TWO: Self = Self(2);

    pub fn new(value: u8) -> Result<Self> {
        if value <= 2 {
            Ok(Self(value))
        } else {
            Err(ModelStoreError::InvalidSlot)
        }
    }

    pub fn as_u8(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelEntitlement {
    pub account_id: AccountId,
    pub slot: ModelSlot,
    pub model_id: ModelId,
    /// Optimistic-concurrency counter. Every replacement increments it.
    pub entitlement_epoch: u64,
    /// Optional pinned release. `None` means latest release accepted by policy.
    pub manifest_id: Option<ManifestId>,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationState {
    Requested = 0,
    Downloading = 1,
    Installed = 2,
    Stale = 3,
    Removed = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInstallation {
    pub account_id: AccountId,
    pub device_id: SyncDeviceId,
    pub model_id: ModelId,
    pub manifest_id: ManifestId,
    pub state: InstallationState,
    pub installation_generation: u64,
}
