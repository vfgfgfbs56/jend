use thiserror::Error;

pub type Result<T> = core::result::Result<T, JendError>;

#[derive(Debug, Error)]
pub enum JendError {
    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),

    #[error("AEAD authentication failed")]
    Aead,

    #[error("invalid .jend magic")]
    InvalidMagic,

    #[error("unsupported .jend version: {0}")]
    UnsupportedVersion(u16),

    #[error("unsupported crypto suite: {0}")]
    UnsupportedSuite(u16),

    #[error("unsupported record type: {0}")]
    UnsupportedRecordType(u8),

    #[error("reserved field is non-zero")]
    ReservedField,

    #[error("record is truncated")]
    Truncated,

    #[error("record contains trailing bytes")]
    TrailingBytes,

    #[error("record exceeds configured size limit")]
    RecordTooLarge,

    #[error("inner message is malformed")]
    MalformedInner,

    #[error("unsupported message role: {0}")]
    UnsupportedRole(u8),

    #[error("record commitment mismatch")]
    CommitmentMismatch,

    #[error("record signer does not match trusted device")]
    SignerMismatch,

    #[error("invalid device signature")]
    InvalidSignature,

    #[error("history chain mismatch")]
    ChainMismatch,

    #[error("ratchet sequence mismatch (expected {expected}, got {got})")]
    SequenceMismatch { expected: u64, got: u64 },

    #[error("HKDF output expansion failed")]
    Kdf,

    #[error("conversation-seed envelope is malformed")]
    MalformedEnvelope,
}
