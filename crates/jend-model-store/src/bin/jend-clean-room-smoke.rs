#![forbid(unsafe_code)]

use jend_model_store::{
    CapabilityTarget, CleanRoomAttestation, IndependentPrototypePlan, ModelId, ModelIdentityKind,
    TrainingSourceEvidence, TrainingSourceKind,
};

fn approved(kind: TrainingSourceKind, name: &str) -> TrainingSourceEvidence {
    TrainingSourceEvidence { kind, name: name.into(), rights_approved: true }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plan = IndependentPrototypePlan {
        attestation: CleanRoomAttestation {
            model_id: ModelId([13u8; 16]),
            display_name: "Jend Reasoner Proto".into(),
            identity: ModelIdentityKind::JendIndependent,
            sources: vec![
                approved(TrainingSourceKind::OpenLicensedDataset, "licensed-corpus"),
                approved(TrainingSourceKind::PublicBenchmark, "public-eval-suite"),
                approved(TrainingSourceKind::JendOwnedSynthetic, "jend-synthetic"),
            ],
            no_restricted_provider_distillation: true,
            no_unlicensed_weights: true,
            no_provider_impersonation: true,
        },
        targets: vec![
            CapabilityTarget::GeneralReasoning,
            CapabilityTarget::Coding,
            CapabilityTarget::ToolUse,
        ],
    };
    plan.validate()?;

    let mut forbidden = plan.attestation.clone();
    forbidden.sources.push(approved(
        TrainingSourceKind::RestrictedProviderOutput,
        "restricted-provider-output",
    ));
    if forbidden.validate().is_ok() {
        return Err("restricted provider output escaped clean-room provenance gate".into());
    }

    let mut leaked = plan.attestation.clone();
    leaked.sources.push(approved(
        TrainingSourceKind::UnknownOrLeakedMaterial,
        "unknown-checkpoint",
    ));
    if leaked.validate().is_ok() {
        return Err("unknown/leaked checkpoint escaped provenance gate".into());
    }

    println!("Jend clean-room independent-model provenance: PASS");
    println!("Jend provider/prototype identity separation: PASS");
    Ok(())
}
