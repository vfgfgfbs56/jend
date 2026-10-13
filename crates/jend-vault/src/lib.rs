#![forbid(unsafe_code)]

mod error;
mod ipc;
mod runtime;
mod performance;
mod controller;
mod secrets;
mod storage;
mod vault;

pub use error::{Result, VaultError};
#[cfg(unix)]
pub use ipc::{IpcAuthToken, IpcHistoryMessage, VaultIpcClient, serve_authenticated_unix_stream, serve_one};
pub use secrets::{DevFileSecretStore, SecretStore};
pub use storage::VaultStorage;
pub use vault::{SyncStatus, Vault};

pub use runtime::{
    RuntimeLane, RuntimePressure, RuntimeQueueLimits, RuntimeQueueUpdate, RuntimeScheduler,
    RuntimeSnapshot, ScheduledTask, SubmitFailure,
};

pub use performance::{
    AdaptivePerformancePolicy, AnimationDetail, DeviceProfile, DeviceTier, PlatformClass,
    PowerMode, RuntimeSignals, ThermalPressure, classify_device,
};
pub use controller::{
    GovernorUpdate, PolicyUpdate, RuntimeController, RuntimeExecutionLimits, RuntimeGovernor,
};
