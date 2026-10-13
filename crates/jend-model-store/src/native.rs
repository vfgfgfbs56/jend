//! Jend-native model blueprint.
//!
//! This describes how Jend may build its own models with capabilities similar
//! in class to frontier assistants without copying a restricted closed model.
//! The blueprint is provenance-first: base weights, datasets and teachers must
//! carry explicit training rights.

use crate::{
    CapabilityTarget, CleanRoomAttestation, ModelId, ModelIdentityKind, ModelStoreError, Result,
};

const MAX_COMPONENT_NAME: usize = 96;
const MAX_COMPONENTS: usize = 256;
const MAX_STAGES: usize = 64;
const MAX_TARGETS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeArchitecture {
    DenseTransformer,
    SparseMoe,
    HybridSparse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeComponentKind {
    SharedBackbone,
    Router,
    ExpertGroup,
    Adapter,
    LongContextModule,
    ToolUseModule,
    MultimodalEncoder,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeComponent {
    pub kind: NativeComponentKind,
    pub name: String,
    /// Logical parameter count owned/controlled by this component.
    pub parameters: u64,
    /// Whether this component may be independently paged by future WeightVM.
    pub pageable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrainingStageKind {
    ContinuedPretraining,
    SupervisedFineTuning,
    PreferenceOptimization,
    ReasoningCurriculum,
    ToolUseCurriculum,
    LongContextTraining,
    ExpertSpecialization,
    QuantizationAwareTuning,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrainingStage {
    pub kind: TrainingStageKind,
    pub source_name: String,
    pub rights_approved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TeacherKind {
    /// A Jend-owned model/checkpoint.
    JendOwned,
    /// A model whose license/contract explicitly grants training/distillation
    /// rights for this use.
    ExplicitlyLicensed,
    /// A closed/restricted provider service without explicit training rights.
    RestrictedProvider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeacherEvidence {
    pub kind: TeacherKind,
    pub name: String,
    pub training_rights_approved: bool,
}

impl TeacherEvidence {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        match self.kind {
            TeacherKind::JendOwned => {
                if !self.training_rights_approved {
                    return Err(ModelStoreError::InvalidNativeModelBlueprint);
                }
            }
            TeacherKind::ExplicitlyLicensed => {
                if !self.training_rights_approved {
                    return Err(ModelStoreError::InvalidNativeModelBlueprint);
                }
            }
            TeacherKind::RestrictedProvider => {
                return Err(ModelStoreError::InvalidNativeModelBlueprint);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JendNativeBlueprint {
    pub model_id: ModelId,
    pub architecture: NativeArchitecture,
    pub provenance: CleanRoomAttestation,
    pub components: Vec<NativeComponent>,
    pub stages: Vec<TrainingStage>,
    pub teachers: Vec<TeacherEvidence>,
    pub capability_targets: Vec<CapabilityTarget>,
}

impl JendNativeBlueprint {
    pub fn validate(&self) -> Result<()> {
        self.provenance.validate()?;
        if self.provenance.model_id != self.model_id
            || self.provenance.identity != ModelIdentityKind::JendIndependent
            || self.components.is_empty()
            || self.components.len() > MAX_COMPONENTS
            || self.stages.is_empty()
            || self.stages.len() > MAX_STAGES
            || self.capability_targets.is_empty()
            || self.capability_targets.len() > MAX_TARGETS
        {
            return Err(ModelStoreError::InvalidNativeModelBlueprint);
        }

        let mut total_parameters = 0u64;
        for component in &self.components {
            validate_name(&component.name)?;
            if component.parameters == 0 {
                return Err(ModelStoreError::InvalidNativeModelBlueprint);
            }
            total_parameters = total_parameters
                .checked_add(component.parameters)
                .ok_or(ModelStoreError::Overflow)?;
        }
        if total_parameters == 0 {
            return Err(ModelStoreError::InvalidNativeModelBlueprint);
        }

        for stage in &self.stages {
            validate_name(&stage.source_name)?;
            if !stage.rights_approved {
                return Err(ModelStoreError::InvalidNativeModelBlueprint);
            }
        }

        for teacher in &self.teachers {
            teacher.validate()?;
        }

        if matches!(
            self.architecture,
            NativeArchitecture::SparseMoe | NativeArchitecture::HybridSparse
        ) {
            let has_router = self
                .components
                .iter()
                .any(|c| c.kind == NativeComponentKind::Router);
            let has_experts = self
                .components
                .iter()
                .any(|c| c.kind == NativeComponentKind::ExpertGroup);
            if !has_router || !has_experts {
                return Err(ModelStoreError::InvalidNativeModelBlueprint);
            }
        }

        Ok(())
    }

    pub fn logical_parameters(&self) -> Result<u64> {
        self.validate()?;
        self.components.iter().try_fold(0u64, |acc, component| {
            acc.checked_add(component.parameters)
                .ok_or(ModelStoreError::Overflow)
        })
    }

    pub fn pageable_parameters(&self) -> Result<u64> {
        self.validate()?;
        self.components
            .iter()
            .filter(|component| component.pageable)
            .try_fold(0u64, |acc, component| {
                acc.checked_add(component.parameters)
                    .ok_or(ModelStoreError::Overflow)
            })
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_COMPONENT_NAME
        || name.contains('\n')
        || name.contains('\r')
    {
        return Err(ModelStoreError::InvalidNativeModelBlueprint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrainingSourceEvidence, TrainingSourceKind};

    fn provenance(model_id: ModelId) -> CleanRoomAttestation {
        CleanRoomAttestation {
            model_id,
            display_name: "Jend Native Proto".into(),
            identity: ModelIdentityKind::JendIndependent,
            sources: vec![
                TrainingSourceEvidence {
                    kind: TrainingSourceKind::OpenLicensedWeights,
                    name: "open-base".into(),
                    rights_approved: true,
                },
                TrainingSourceEvidence {
                    kind: TrainingSourceKind::JendOwnedSynthetic,
                    name: "jend-synthetic".into(),
                    rights_approved: true,
                },
            ],
            no_restricted_provider_distillation: true,
            no_unlicensed_weights: true,
            no_provider_impersonation: true,
        }
    }

    fn sparse_blueprint() -> JendNativeBlueprint {
        let model_id = ModelId([41u8; 16]);
        JendNativeBlueprint {
            model_id,
            architecture: NativeArchitecture::SparseMoe,
            provenance: provenance(model_id),
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
                    source_name: "jend-reasoning-curriculum".into(),
                    rights_approved: true,
                },
            ],
            teachers: vec![
                TeacherEvidence {
                    kind: TeacherKind::JendOwned,
                    name: "jend-teacher-v1".into(),
                    training_rights_approved: true,
                },
            ],
            capability_targets: vec![
                CapabilityTarget::GeneralReasoning,
                CapabilityTarget::Coding,
                CapabilityTarget::ToolUse,
            ],
        }
    }

    #[test]
    fn sparse_jend_native_blueprint_is_valid_and_pageable() {
        let blueprint = sparse_blueprint();
        assert!(blueprint.validate().is_ok());
        assert_eq!(blueprint.logical_parameters().unwrap(), 100_100_000_000);
        assert_eq!(blueprint.pageable_parameters().unwrap(), 96_000_000_000);
    }

    #[test]
    fn restricted_closed_provider_cannot_be_teacher() {
        let mut blueprint = sparse_blueprint();
        blueprint.teachers.push(TeacherEvidence {
            kind: TeacherKind::RestrictedProvider,
            name: "closed-frontier-service".into(),
            training_rights_approved: false,
        });
        assert!(blueprint.validate().is_err());
    }

    #[test]
    fn licensed_teacher_must_have_explicit_training_rights() {
        let mut blueprint = sparse_blueprint();
        blueprint.teachers.push(TeacherEvidence {
            kind: TeacherKind::ExplicitlyLicensed,
            name: "licensed-teacher".into(),
            training_rights_approved: false,
        });
        assert!(blueprint.validate().is_err());
    }

    #[test]
    fn sparse_architecture_requires_router_and_experts() {
        let mut blueprint = sparse_blueprint();
        blueprint
            .components
            .retain(|component| component.kind != NativeComponentKind::Router);
        assert!(blueprint.validate().is_err());
    }
}
