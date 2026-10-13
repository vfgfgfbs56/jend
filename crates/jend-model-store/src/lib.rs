#![forbid(unsafe_code)]

//! Jend model catalog / entitlement / signed-manifest primitives.
//!
//! This crate deliberately contains no chat plaintext and no inference code.
//! Its security role is to make model installation fail closed: account slots
//! authorize at most three selected models, while every model release is
//! identified by a canonical manifest digest and a release signature.

mod capability;
mod activation;
mod ai_executor;
mod catalog;
mod download;
mod entitlement;
mod execution;
mod error;
mod ids;
mod installer;
mod manifest;
mod native;
mod release;
mod prototype;
mod source;
mod source_protocol;
mod hf_xet;
mod source_worker;
mod safety;
mod weightvm;
mod runtime_feasibility;
mod signed_gguf;
mod gguf_snapshot;
mod weight_store;
mod virtual_map;

pub use capability::{DownloadGrant, OnlineGrantPublicKey, OnlineGrantSigningKey};
pub use download::{ChunkVerifier, DownloadState, WholeModelVerifier};
pub use entitlement::{DeviceInstallation, InstallationState, ModelEntitlement, ModelSlot};
pub use error::{ModelStoreError, Result};
pub use ids::{ManifestId, ModelId, ModelObjectId, ReleaseKeyId};
pub use installer::AtomicModelInstaller;
pub use manifest::{ModelChunk, ModelManifest, SignedModelManifest};
pub use release::{ModelReleasePublicKey, ModelReleaseSigningKey};

pub use catalog::{
    approximate_quantized_weight_bytes, CatalogModel, InstallPlan, LocalPackageSpec,
    ModelDelivery, ProviderCredentialMode, ProviderRemoteSpec, VirtualPagedSpec, WeightRights,
};

pub use source::{
    LicenseEvidence, LicenseEvidenceKind, ModelProvenance, ModelSource, RedistributionDecision,
    SourceFingerprint,
};
pub use safety::{
    ArtifactFormat, BehavioralEvalReport, BehavioralVerdict, PublishGate, ScannerVerdict,
    StaticParserVerdict, StoreSafetyStatus, SupplyChainDecision, SupplyChainReport,
};

pub use activation::{
    ActivationPlan, ActivationPreferences, ExecutionReadiness, ModelCacheBudget, SelectedModel,
};

pub use ai_executor::{
    AiCancelResult, AiExecutor, AiExecutorLimits, AiExecutorSnapshot, AiJob, AiJobId,
    AiSubmitFailure,
};

pub use prototype::{
    CapabilityTarget, CleanRoomAttestation, IndependentPrototypePlan, ModelIdentityKind,
    TrainingSourceEvidence, TrainingSourceKind,
};

pub use execution::{ChatExecutionRoute, LocalExecutionKind};

pub use native::{
    JendNativeBlueprint, NativeArchitecture, NativeComponent, NativeComponentKind,
    TeacherEvidence, TeacherKind, TrainingStage, TrainingStageKind,
};

pub use weightvm::{
    WeightPageDescriptor, WeightPageId, WeightPageLease, WeightPageSource, WeightVm,
    WeightVmBudget, WeightVmBudgetUpdate, WeightVmSnapshot,
};

pub use weight_store::{DurableWeightPageStore, WeightStoreStats};

pub use virtual_map::{
    ExpertId, ExpertRole, SignedVirtualModelMap, VirtualMapId, VirtualModelMap, VirtualRegion,
    VirtualRegionKind,
};

pub use source_protocol::{
    ModelSourceMap, PageSourceBinding, SignedModelSourceMap, SourceDescriptor, SourceId,
    SourceMapId, SourceOrigin, SourceReadRequest, VerifiedSourceReadRequest,
};

pub use hf_xet::{
    HfCredentialScope, HfHttpRequestPlan, HfRedirectPolicy, HfXetAdapterPolicy,
    HfXetFileId, HfXetReadGrant, HfXetReconstructionPlan, HfXetRequestPlanner,
    XetByteRange, XetChunkRange, XetFetchMetadata, XetRangeMetadata,
    XetSignedFetchPlan, XetTermMetadata,
};

pub use source_worker::{
    BoundedSourceResponse, SourceResponseKind, SourceWorkerLimits,
    validate_resolved_addresses,
};

pub use runtime_feasibility::{
    RuntimeArtifactFormat, NativeEngine, DeviceCompute, WeightComputeTopology,
    VariantResourceEstimate, DeviceResourceEstimate, LocalFeasibility,
    estimate_local_feasibility,
};

pub use signed_gguf::{VerifiedGgufInspection, inspect_independently_signed_gguf};

pub use gguf_snapshot::{VerifiedGgufSnapshot, VerifiedGgufSnapshotStore, VerifiedGgufOpenLease};
