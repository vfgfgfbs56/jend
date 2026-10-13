#![forbid(unsafe_code)]

use jend_model_store::{
    CapabilityTarget, CleanRoomAttestation, JendNativeBlueprint, ModelId, ModelIdentityKind,
    NativeArchitecture, NativeComponent, NativeComponentKind, TeacherEvidence, TeacherKind,
    TrainingSourceEvidence, TrainingSourceKind, TrainingStage, TrainingStageKind,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let model_id = ModelId([45u8; 16]);
    let provenance = CleanRoomAttestation {
        model_id,
        display_name: "Jend Native Reasoner".into(),
        identity: ModelIdentityKind::JendIndependent,
        sources: vec![
            TrainingSourceEvidence {
                kind: TrainingSourceKind::OpenLicensedWeights,
                name: "open-licensed-base".into(),
                rights_approved: true,
            },
            TrainingSourceEvidence {
                kind: TrainingSourceKind::JendOwnedSynthetic,
                name: "jend-owned-curriculum".into(),
                rights_approved: true,
            },
        ],
        no_restricted_provider_distillation: true,
        no_unlicensed_weights: true,
        no_provider_impersonation: true,
    };

    let blueprint = JendNativeBlueprint {
        model_id,
        architecture: NativeArchitecture::SparseMoe,
        provenance,
        components: vec![
            NativeComponent {
                kind: NativeComponentKind::SharedBackbone,
                name: "shared-backbone".into(),
                parameters: 4_000_000_000,
                pageable: false,
            },
            NativeComponent {
                kind: NativeComponentKind::Router,
                name: "router".into(),
                parameters: 100_000_000,
                pageable: false,
            },
            NativeComponent {
                kind: NativeComponentKind::ExpertGroup,
                name: "experts".into(),
                parameters: 96_000_000_000,
                pageable: true,
            },
        ],
        stages: vec![
            TrainingStage {
                kind: TrainingStageKind::ContinuedPretraining,
                source_name: "licensed-corpus".into(),
                rights_approved: true,
            },
            TrainingStage {
                kind: TrainingStageKind::ReasoningCurriculum,
                source_name: "jend-reasoning".into(),
                rights_approved: true,
            },
        ],
        teachers: vec![TeacherEvidence {
            kind: TeacherKind::JendOwned,
            name: "jend-teacher-v1".into(),
            training_rights_approved: true,
        }],
        capability_targets: vec![
            CapabilityTarget::GeneralReasoning,
            CapabilityTarget::Coding,
            CapabilityTarget::ToolUse,
        ],
    };

    blueprint.validate()?;
    if blueprint.pageable_parameters()? != 96_000_000_000 {
        return Err("native sparse expert paging math changed unexpectedly".into());
    }

    let mut forbidden = blueprint.clone();
    forbidden.teachers.push(TeacherEvidence {
        kind: TeacherKind::RestrictedProvider,
        name: "closed-frontier-service".into(),
        training_rights_approved: false,
    });
    if forbidden.validate().is_ok() {
        return Err("restricted closed provider escaped native teacher gate".into());
    }

    println!("Jend native sparse-model blueprint: PASS");
    println!("Jend restricted-provider teacher rejection: PASS");
    Ok(())
}
