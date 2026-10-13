use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelStoreError {
    #[error("I/O failure")]
    Io(#[from] std::io::Error),
    #[error("invalid model identifier or manifest")]
    InvalidManifest,
    #[error("model manifest is too large")]
    ManifestTooLarge,
    #[error("invalid release signature")]
    InvalidSignature,
    #[error("release key mismatch")]
    ReleaseKeyMismatch,
    #[error("invalid model slot")]
    InvalidSlot,
    #[error("chunk index is outside the manifest")]
    InvalidChunk,
    #[error("chunk length mismatch")]
    ChunkLengthMismatch,
    #[error("chunk digest mismatch")]
    ChunkDigestMismatch,
    #[error("download state belongs to another manifest")]
    DownloadStateMismatch,
    #[error("invalid model download grant")]
    InvalidGrant,
    #[error("model download grant is not valid yet")]
    GrantNotYetValid,
    #[error("model download grant expired")]
    GrantExpired,
    #[error("model download grant lifetime is invalid or too long")]
    GrantLifetimeTooLong,
    #[error("model download grant does not match requested model object")]
    GrantBindingMismatch,
    #[error("model installation is incomplete")]
    InstallationIncomplete,
    #[error("counter overflow")]
    Overflow,
    #[error("random number generator failure")]
    Random(#[from] getrandom::Error),
    #[error("model catalog entry is invalid")]
    InvalidCatalogModel,
    #[error("model source or provenance is invalid")]
    InvalidModelSource,
    #[error("model safety evaluation is incomplete")]
    IncompleteSafetyEvaluation,
    #[error("model activation/cache plan is invalid")]
    InvalidActivationPlan,
    #[error("AI executor limits are invalid")]
    InvalidAiExecutorLimits,
    #[error("AI executor job is unknown or already finished")]
    UnknownAiJob,
    #[error("independent model prototype provenance is invalid")]
    InvalidPrototypeProvenance,
    #[error("external provider/API model execution is disabled in Jend Store")]
    ExternalProviderExecutionDisabled,
    #[error("Jend-native model blueprint is invalid")]
    InvalidNativeModelBlueprint,
    #[error("weight page descriptor/source is invalid")]
    InvalidWeightPage,
    #[error("weight page length does not match its descriptor")]
    WeightPageLengthMismatch,
    #[error("weight page SHA-256 digest mismatch")]
    WeightPageDigestMismatch,
    #[error("WeightVM cache budget is invalid")]
    InvalidWeightVmBudget,
    #[error("WeightVM cache budget is smaller than the requested page")]
    WeightVmBudgetTooSmall,
    #[error("WeightVM cannot evict because all resident pages are pinned")]
    WeightVmAllPagesPinned,
    #[error("durable WeightVM page store is invalid or insecure")]
    InvalidWeightPageStore,
    #[error("could not allocate a unique WeightVM staging object")]
    WeightPageStoreCollision,
    #[error("virtual model address/expert map is invalid")]
    InvalidVirtualModelMap,
    #[error("virtual model address map is too large")]
    VirtualMapTooLarge,
    #[error("virtual model region is unknown")]
    UnknownVirtualRegion,
    #[error("virtual model expert is unknown")]
    UnknownVirtualExpert,
    #[error("source descriptor is invalid")]
    InvalidSourceDescriptor,
    #[error("source page/range binding is invalid")]
    InvalidSourceBinding,
    #[error("model source map is invalid")]
    InvalidSourceMap,
    #[error("model source map is too large")]
    SourceMapTooLarge,
    #[error("source descriptor is unknown")]
    UnknownSourceDescriptor,
    #[error("source binding is unknown")]
    UnknownSourceBinding,
    #[error("source map does not match its virtual model map/release")]
    SourceVirtualMapMismatch,
    #[error("HF/Xet adapter policy is invalid")]
    InvalidHfXetPolicy,
    #[error("HF/Xet source descriptor/request binding is invalid")]
    InvalidHfXetSource,
    #[error("HF/Xet file identity is invalid")]
    InvalidHfXetFileId,
    #[error("HF/Xet resolve response is invalid")]
    InvalidHfXetResolveResponse,
    #[error("HF/Xet resolve response did not expose X-Xet-Hash")]
    HfXetFileIdentityMissing,
    #[error("HF/Xet read grant is invalid, expired, or targets an unapproved CAS host")]
    InvalidHfXetGrant,
    #[error("HF/Xet reconstruction metadata is invalid")]
    InvalidHfXetReconstruction,
    #[error("HF/Xet reconstruction exceeds configured byte/range budgets")]
    HfXetBudgetExceeded,
    #[error("source worker response, DNS target or budget is invalid")]
    InvalidSourceWorkerResponse,
}

pub type Result<T> = core::result::Result<T, ModelStoreError>;
