use thiserror::Error;

pub type Result<T> = core::result::Result<T, SyncError>;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),

    #[error("jend-core error: {0}")]
    Core(#[from] jend_core::JendError),

    #[error("HKDF output expansion failed")]
    Kdf,

    #[error("AEAD authentication failed")]
    Aead,

    #[error("malformed sync object")]
    Malformed,

    #[error("sync object exceeds configured size limit")]
    ObjectTooLarge,

    #[error("unsupported sync object version: {0}")]
    UnsupportedVersion(u16),

    #[error("unsupported sync object kind: {0}")]
    UnsupportedKind(u8),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("device is not trusted in the relevant DeviceSet")]
    UntrustedDevice,

    #[error("device-set transition is invalid")]
    InvalidDeviceSetTransition,

    #[error("sync epoch key is unavailable")]
    MissingEpochKey,

    #[error("sync keyring limit exceeded")]
    KeyringLimit,

    #[error("DAG contains a cycle")]
    DagCycle,

    #[error("DAG references a missing parent")]
    MissingParent,

    #[error("DAG clock/counter invariant failed")]
    InvalidDagClock,

    #[error("conversation mismatch")]
    ConversationMismatch,

    #[error("message signing key changed unexpectedly for one sender chain")]
    MessageSigningKeyChanged,

    #[error("device-set history is invalid or incomplete")]
    InvalidDeviceSetHistory,

    #[error("sync rollback detected")]
    SyncRollback,

    #[error("conflicting sync index at an already accepted generation")]
    SyncIndexFork,

    #[error("recovery request or approval expired")]
    RecoveryExpired,

    #[error("recovery request/approval binding mismatch")]
    RecoveryBindingMismatch,

    #[error("recovery comparison code or cryptographic binding is invalid")]
    RecoveryCodeMismatch,
}
