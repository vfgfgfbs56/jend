#![forbid(unsafe_code)]

// Offline policy smoke only. No GGUF/ONNX inference or loading is claimed.
use jend_model_store::{
    ArtifactFormat, DeviceCompute, DeviceResourceEstimate, LocalFeasibility,
    NativeEngine, VariantResourceEstimate, WeightComputeTopology,
    estimate_local_feasibility,
};

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gguf = VariantResourceEstimate {
        format: ArtifactFormat::Gguf,
        engine: NativeEngine::LlamaCppCpu,
        topology: WeightComputeTopology::Dense,
        weight_bytes: 3 * GIB,
        resident_weight_bytes: 3 * GIB,
        kv_cache_bytes: 256 * MIB,
        scratch_and_graph_bytes: 256 * MIB,
        engine_overhead_bytes: 128 * MIB,
        missing_artifact_disk_bytes: 3 * GIB,
    };
    let weak = DeviceResourceEstimate {
        compute: DeviceCompute::CpuOnly,
        free_physical_ram_bytes: 2 * GIB,
        reserved_headroom_bytes: 512 * MIB,
        free_disk_bytes: 64 * GIB,
    };
    if !matches!(
        estimate_local_feasibility(gguf, weak),
        LocalFeasibility::InsufficientRam { .. }
    ) {
        return Err("dense GGUF was incorrectly allowed to run from disk cache".into());
    }
    println!("Jend weak-device dense RAM versus disk gate: PASS");

    let good = DeviceResourceEstimate {
        free_physical_ram_bytes: 8 * GIB, ..weak
    };
    if !matches!(
        estimate_local_feasibility(gguf, good),
        LocalFeasibility::FitsEstimatedResources { .. }
    ) {
        return Err("compatible GGUF planning path incorrectly rejected".into());
    }
    println!("Jend compatible GGUF CPU resource estimate: PASS");

    let unknown = VariantResourceEstimate {
        format: ArtifactFormat::Safetensors, ..gguf
    };
    if estimate_local_feasibility(unknown, good)
        != LocalFeasibility::MissingArchitectureAdapter
    {
        return Err("unmapped safetensors format admitted as an executable graph".into());
    }
    println!("Jend standalone safetensors inference refused: PASS");

    let mismatch = VariantResourceEstimate {
        format: ArtifactFormat::Onnx, ..gguf
    };
    if estimate_local_feasibility(mismatch, good)
        != LocalFeasibility::IncompatibleBackend
    {
        return Err("ONNX file permitted to use incompatible GGUF engine".into());
    }
    println!("Jend mismatched model backend rejected: PASS");

    let sparse = VariantResourceEstimate {
        topology: WeightComputeTopology::SparseNotYetVerified,
        resident_weight_bytes: 64 * MIB,
        ..gguf
    };
    if estimate_local_feasibility(sparse, good)
        != LocalFeasibility::UnsupportedSparseSemantics
    {
        return Err("unproven sparse residency accepted".into());
    }
    println!("Jend unverified sparse paging claim rejected: PASS");

    println!("Jend resource feasibility remains planning-only, no inference: PASS");
    Ok(())
}
