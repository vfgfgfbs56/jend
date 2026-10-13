//! Clean-room provenance for Jend-owned model prototypes.

use crate::{ModelId, ModelStoreError, Result};

const MAX_NAME: usize = 80;
const MAX_SOURCE_NAME: usize = 160;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelIdentityKind {
    ProviderBacked,
    JendIndependent,
    OpenLicensed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrainingSourceKind {
    OpenLicensedWeights,
    OpenLicensedDataset,
    HumanAuthored,
    JendOwnedSynthetic,
    PublicBenchmark,
    PublicSpecification,
    RestrictedProviderOutput,
    UnknownOrLeakedMaterial,
}

impl TrainingSourceKind {
    pub const fn allowed_for_jend_independent(self) -> bool {
        matches!(
            self,
            Self::OpenLicensedWeights
                | Self::OpenLicensedDataset
                | Self::HumanAuthored
                | Self::JendOwnedSynthetic
                | Self::PublicBenchmark
                | Self::PublicSpecification
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrainingSourceEvidence {
    pub kind: TrainingSourceKind,
    pub name: String,
    pub rights_approved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanRoomAttestation {
    pub model_id: ModelId,
    pub display_name: String,
    pub identity: ModelIdentityKind,
    pub sources: Vec<TrainingSourceEvidence>,
    pub no_restricted_provider_distillation: bool,
    pub no_unlicensed_weights: bool,
    pub no_provider_impersonation: bool,
}

impl CleanRoomAttestation {
    pub fn validate(&self) -> Result<()> {
        validate_name(&self.display_name)?;
        if self.sources.is_empty()
            || !self.no_restricted_provider_distillation
            || !self.no_unlicensed_weights
            || !self.no_provider_impersonation
        {
            return Err(ModelStoreError::InvalidPrototypeProvenance);
        }

        for source in &self.sources {
            validate_source_name(&source.name)?;
            if !source.rights_approved {
                return Err(ModelStoreError::InvalidPrototypeProvenance);
            }
            if self.identity == ModelIdentityKind::JendIndependent
                && !source.kind.allowed_for_jend_independent()
            {
                return Err(ModelStoreError::InvalidPrototypeProvenance);
            }
        }
        Ok(())
    }

    pub fn is_clean_room_jend_model(&self) -> bool {
        self.identity == ModelIdentityKind::JendIndependent && self.validate().is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityTarget {
    GeneralReasoning,
    Coding,
    LongContext,
    ToolUse,
    Multimodal,
    Writing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependentPrototypePlan {
    pub attestation: CleanRoomAttestation,
    pub targets: Vec<CapabilityTarget>,
}

impl IndependentPrototypePlan {
    pub fn validate(&self) -> Result<()> {
        self.attestation.validate()?;
        if self.attestation.identity != ModelIdentityKind::JendIndependent
            || self.targets.is_empty()
        {
            return Err(ModelStoreError::InvalidPrototypeProvenance);
        }
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NAME
        || !name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_' | b'.' | b'+')
        })
    {
        return Err(ModelStoreError::InvalidPrototypeProvenance);
    }
    Ok(())
}

fn validate_source_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_SOURCE_NAME
        || name.contains('\n')
        || name.contains('\r')
    {
        return Err(ModelStoreError::InvalidPrototypeProvenance);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved(kind: TrainingSourceKind, name: &str) -> TrainingSourceEvidence {
        TrainingSourceEvidence { kind, name: name.into(), rights_approved: true }
    }

    fn base() -> CleanRoomAttestation {
        CleanRoomAttestation {
            model_id: ModelId([11u8; 16]),
            display_name: "Jend Reasoner Proto".into(),
            identity: ModelIdentityKind::JendIndependent,
            sources: vec![
                approved(TrainingSourceKind::OpenLicensedDataset, "licensed-corpus"),
                approved(TrainingSourceKind::PublicBenchmark, "public-reasoning-benchmark"),
                approved(TrainingSourceKind::HumanAuthored, "jend-human-evals"),
            ],
            no_restricted_provider_distillation: true,
            no_unlicensed_weights: true,
            no_provider_impersonation: true,
        }
    }

    #[test]
    fn independent_clean_room_plan_is_allowed() {
        let plan = IndependentPrototypePlan {
            attestation: base(),
            targets: vec![CapabilityTarget::GeneralReasoning, CapabilityTarget::Coding],
        };
        assert!(plan.validate().is_ok());
        assert!(plan.attestation.is_clean_room_jend_model());
    }

    #[test]
    fn restricted_provider_outputs_fail_closed() {
        let mut attestation = base();
        attestation.sources.push(approved(
            TrainingSourceKind::RestrictedProviderOutput,
            "third-party-chat-output",
        ));
        assert!(attestation.validate().is_err());
    }

    #[test]
    fn unknown_or_leaked_weights_fail_closed() {
        let mut attestation = base();
        attestation.sources.push(approved(
            TrainingSourceKind::UnknownOrLeakedMaterial,
            "unknown-checkpoint",
        ));
        assert!(attestation.validate().is_err());
    }

    #[test]
    fn provider_impersonation_is_not_valid_clean_room() {
        let mut attestation = base();
        attestation.no_provider_impersonation = false;
        assert!(attestation.validate().is_err());
    }
}
