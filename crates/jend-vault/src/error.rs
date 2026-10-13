use std::io;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, VaultError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),

    #[error("jend-core error: {0}")]
    Core(#[from] jend_core::JendError),

    #[error("jend-sync error: {0}")]
    Sync(#[from] jend_sync::SyncError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("vault metadata is malformed")]
    MalformedMetadata,

    #[error("conversation does not exist")]
    ConversationNotFound,

    #[error("conversation already exists")]
    ConversationExists,

    #[error("conversation log contains a record for another conversation")]
    ConversationMismatch,

    #[error("required encrypted sync objects have not been downloaded yet")]
    SyncObjectsMissing,

    #[error("same sync object id already exists with different bytes")]
    SyncObjectConflict,

    #[error("conversation log contains an invalid frame length")]
    InvalidFrameLength,

    #[error("conversation log has an incomplete tail without a matching durability journal")]
    IncompleteTail,

    #[error("durability journal does not match the conversation log")]
    PendingMismatch,

    #[error("IPC request is malformed")]
    MalformedIpc,

    #[error("unsupported IPC request type: {0}")]
    UnsupportedIpc(u8),

    #[error("IPC request is not authorized")]
    UnauthorizedIpc,

    #[error("IPC authorization file is not a private regular file")]
    InsecureIpcAuthFile,

    #[error("IPC authorization file has an invalid size")]
    InvalidIpcAuthSize,

    #[error("secret file has an invalid size")]
    InvalidSecretSize,
}
