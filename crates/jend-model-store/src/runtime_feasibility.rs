//! Conservative **planning-only** gate for existing third-party model variants.
//!
//! This module DOES NOT grant trust, load weights, authorize a backend or
//! run inference. Inputs must eventually come from signed model metadata,
//! an independently reviewed architecture/backend allowlist and real local
//! device probing. Until a native backend implements verified sparse paging,
//! all weight bytes of a dense model count against actual available RAM.
//! Disk cache never substitutes for RAM when deciding local feasibility.

const HARD_MAX_WEIGHT_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;
const HARD_MAX_RAM: u64 = 4 * 1024 * 1024 * 1024 * 1024;
const HARD_MAX_DISK: u64 = 64 * 1024 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactFormat {
    Gguf,
    Onnx,
    Safetensors,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEngine {
    LlamaCppCpu,
    LlamaCppMetal,
    OnnxCpu,
    OnnxCoreMl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceCompute {
    CpuOnly,
    AppleSiliconUnifiedMemory,
    OtherGpu,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeightComputeTopology {
    /// Every decoded token generally touches the dense weight tensors.
    Dense,
    /// Unsupported until a real engine proves sparse compute semantics.
    SparseNotYetVerified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariantResourceEstimate {
    pub format: ArtifactFormat,
    pub engine: NativeEngine,
    pub topology: WeightComputeTopology,
    /// Physical size of verified packed tensors expected to stay resident.
    /// For dense models this MUST NOT be below the on-disk weight bytes.
    pub weight_bytes: u64,
    pub resident_weight_bytes: u64,
    pub kv_cache_bytes: u64,
    pub scratch_and_graph_bytes: u64,
    pub engine_overhead_bytes: u64,
    /// Additional disk required before local model installation.
    pub missing_artifact_disk_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceResourceEstimate {
    pub compute: DeviceCompute,
    /// Available physical unified/system memory; excludes nonexistent swap.
    pub free_physical_ram_bytes: u64,
    /// Additional OS and application headroom within the available RAM.
    pub reserved_headroom_bytes: u64,
    pub free_disk_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalFeasibility {
    /// Format/backend/OS combination is not implemented by this initial gate.
    IncompatibleBackend,
    /// Safetensors alone is a tensor container; an architecture adapter is
    /// required before any execution can be claimed.
    MissingArchitectureAdapter,
    /// Large sparse paging cannot be inferred from a tiny weight cache.
    UnsupportedSparseSemantics,
    /// Invalid, contradictory or overflowing resource estimates fail closed.
    InvalidResourceEstimate,
    MissingDisk { required: u64, available: u64 },
    InsufficientRam { required: u64, available: u64 },
    /// A *planning estimate* only, not verified trust or permission to execute.
    FitsEstimatedResources {
        required_ram: u64,
        usable_ram: u64,
    },
}

/// No native inference is performed or authorized by this function.
/// The only current positive cases are dense GGUF + CPU/Metal and dense ONNX
/// + CPU/CoreML. An actual engine must separately validate architecture,
/// GGUF/ONNX operator support, artifact signatures, runtime ABI and dimensions.
pub fn estimate_local_feasibility(
    variant: VariantResourceEstimate,
    device: DeviceResourceEstimate,
) -> LocalFeasibility {
    use ArtifactFormat::*;
    use DeviceCompute::*;
    use LocalFeasibility::*;
    use NativeEngine::*;

    if variant.format == Safetensors {
        return MissingArchitectureAdapter;
    }
    let compatible = matches!(
        (variant.format, variant.engine, device.compute),
        (Gguf, LlamaCppCpu, _) |
        (Gguf, LlamaCppMetal, AppleSiliconUnifiedMemory) |
        (Onnx, OnnxCpu, _) |
        (Onnx, OnnxCoreMl, AppleSiliconUnifiedMemory)
    );
    if !compatible {
        return IncompatibleBackend;
    }
    if variant.topology != WeightComputeTopology::Dense {
        return UnsupportedSparseSemantics;
    }

    if variant.weight_bytes == 0
        || variant.weight_bytes > HARD_MAX_WEIGHT_BYTES
        || variant.resident_weight_bytes < variant.weight_bytes
        || variant.resident_weight_bytes > HARD_MAX_RAM
        || variant.kv_cache_bytes == 0
        || variant.engine_overhead_bytes == 0
        || variant.missing_artifact_disk_bytes > HARD_MAX_DISK
        || device.free_disk_bytes > HARD_MAX_DISK
        || device.free_physical_ram_bytes > HARD_MAX_RAM
        || device.reserved_headroom_bytes >= device.free_physical_ram_bytes
    {
        return InvalidResourceEstimate;
    }

    let Some(required_ram) = variant.resident_weight_bytes
        .checked_add(variant.kv_cache_bytes)
        .and_then(|v| v.checked_add(variant.scratch_and_graph_bytes))
        .and_then(|v| v.checked_add(variant.engine_overhead_bytes))
    else {
        return InvalidResourceEstimate;
    };
    if required_ram > HARD_MAX_RAM {
        return InvalidResourceEstimate;
    }
    if device.free_disk_bytes < variant.missing_artifact_disk_bytes {
        return MissingDisk {
            required: variant.missing_artifact_disk_bytes,
            available: device.free_disk_bytes,
        };
    }
    let usable_ram = device.free_physical_ram_bytes - device.reserved_headroom_bytes;
    if required_ram > usable_ram {
        return InsufficientRam {
            required: required_ram,
            available: usable_ram,
        };
    }
    FitsEstimatedResources {
        required_ram,
        usable_ram,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;

    fn dense() -> VariantResourceEstimate {
        VariantResourceEstimate {
            format: ArtifactFormat::Gguf,
            engine: NativeEngine::LlamaCppCpu,
            topology: WeightComputeTopology::Dense,
            weight_bytes: 3 * GIB,
            resident_weight_bytes: 3 * GIB,
            kv_cache_bytes: 256 * MIB,
            scratch_and_graph_bytes: 256 * MIB,
            engine_overhead_bytes: 128 * MIB,
            missing_artifact_disk_bytes: 3 * GIB,
        }
    }
    fn weak_device() -> DeviceResourceEstimate {
        DeviceResourceEstimate {
            compute: DeviceCompute::CpuOnly,
            free_physical_ram_bytes: 2 * GIB,
            reserved_headroom_bytes: 512 * MIB,
            free_disk_bytes: 64 * GIB,
        }
    }

    #[test]
    fn abundant_disk_cannot_make_dense_model_fit_two_gib_ram() {
        assert!(matches!(
            estimate_local_feasibility(dense(), weak_device()),
            LocalFeasibility::InsufficientRam { .. }
        ));
    }

    #[test]
    fn compatible_dense_model_with_real_ram_fits_estimate() {
        let device = DeviceResourceEstimate {
            free_physical_ram_bytes: 8 * GIB,
            ..weak_device()
        };
        let result = estimate_local_feasibility(dense(), device);
        assert!(matches!(
            result, LocalFeasibility::FitsEstimatedResources {
                required_ram: 3_892_314_112,
                usable_ram: 8_053_063_680
            }
        ));
    }

    #[test]
    fn incompatible_onnx_gguf_backend_pair_rejected() {
        let variant = VariantResourceEstimate {
            format: ArtifactFormat::Onnx, ..dense()
        };
        let device = DeviceResourceEstimate {
            free_physical_ram_bytes: 8 * GIB, ..weak_device()
        };
        assert_eq!(
            estimate_local_feasibility(variant, device),
            LocalFeasibility::IncompatibleBackend
        );
    }

    #[test]
    fn safetensors_needs_architecture_specific_adapter() {
        let variant = VariantResourceEstimate {
            format: ArtifactFormat::Safetensors,
            ..dense()
        };
        assert_eq!(
            estimate_local_feasibility(variant, weak_device()),
            LocalFeasibility::MissingArchitectureAdapter
        );
    }

    #[test]
    fn metal_requires_apple_unified_memory_platform() {
        let variant = VariantResourceEstimate {
            engine: NativeEngine::LlamaCppMetal,
            ..dense()
        };
        assert_eq!(
            estimate_local_feasibility(variant, weak_device()),
            LocalFeasibility::IncompatibleBackend
        );
        let device = DeviceResourceEstimate {
            compute: DeviceCompute::AppleSiliconUnifiedMemory,
            free_physical_ram_bytes: 8 * GIB,
            ..weak_device()
        };
        assert!(matches!(
            estimate_local_feasibility(variant, device),
            LocalFeasibility::FitsEstimatedResources { .. }
        ));
    }

    #[test]
    fn sparse_model_not_magic_unverified_paging() {
        let variant = VariantResourceEstimate {
            topology: WeightComputeTopology::SparseNotYetVerified,
            resident_weight_bytes: 64 * MIB,
            ..dense()
        };
        assert_eq!(
            estimate_local_feasibility(variant, weak_device()),
            LocalFeasibility::UnsupportedSparseSemantics
        );
    }

    #[test]
    fn inconsistent_resident_claim_fails_closed() {
        let variant = VariantResourceEstimate {
            resident_weight_bytes: 64 * MIB,
            ..dense()
        };
        assert_eq!(
            estimate_local_feasibility(variant, weak_device()),
            LocalFeasibility::InvalidResourceEstimate
        );
    }

    #[test]
    fn arithmetic_overflow_and_faked_headroom_rejected() {
        let variant = VariantResourceEstimate {
            scratch_and_graph_bytes: u64::MAX,
            ..dense()
        };
        assert_eq!(
            estimate_local_feasibility(variant, weak_device()),
            LocalFeasibility::InvalidResourceEstimate
        );
        let device = DeviceResourceEstimate {
            reserved_headroom_bytes: 2 * GIB, ..weak_device()
        };
        assert_eq!(
            estimate_local_feasibility(dense(), device),
            LocalFeasibility::InvalidResourceEstimate
        );
    }

    #[test]
    fn missing_disk_blocks_new_install_but_not_preinstalled_variant() {
        let device = DeviceResourceEstimate {
            free_disk_bytes: 512 * MIB,
            free_physical_ram_bytes: 8 * GIB,
            ..weak_device()
        };
        assert_eq!(
            estimate_local_feasibility(dense(), device),
            LocalFeasibility::MissingDisk {
                required: 3 * GIB,
                available: 512 * MIB
            }
        );
        let variant = VariantResourceEstimate {
            missing_artifact_disk_bytes: 0,
            ..dense()
        };
        assert!(matches!(
            estimate_local_feasibility(variant, device),
            LocalFeasibility::FitsEstimatedResources { .. }
        ));
    }
}
