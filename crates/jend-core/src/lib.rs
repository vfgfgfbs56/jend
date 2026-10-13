#![forbid(unsafe_code)]

//! Jend's local cryptographic record core.
//!
//! This crate is pre-audit software and must not be treated as production-ready
//! cryptography simply because it composes established primitives.

mod codec;
mod error;
mod identity;
mod keys;
mod ratchet;
mod record;

pub use error::{JendError, Result};
pub use identity::{DeviceIdentity, DeviceKeyId, DevicePublicIdentity};
pub use keys::{AccountRootKey, ConversationSeed, SealedLocalBlob, SyncWrappingKey, WrappedConversationSeed};
pub use ratchet::{MessageKey, PreparedRatchetStep, RatchetState};
pub use record::{
    ConversationId, InnerMessage, JendRecord, MessageRole, RecordCommitment, SensitiveBytes,
    ZERO_COMMITMENT,
};
