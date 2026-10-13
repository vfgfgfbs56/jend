//! Model ingestion security and behavioral-evaluation gates.
//!
//! "Model safety" has two distinct meanings here:
//! 1) supply-chain safety of files/code/format before import;
//! 2) behavioral risk of the model after safe offline loading.
//!
//! A public Store release needs both gates. A malware scan alone can never
//! certify model behavior, and a good behavior eval can never make a malicious
//! pickle/custom-code package safe to load.

use crate::{ModelStoreError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactFormat {
    Safetensors,
    Gguf,
    Onnx,
    CoreMl,
    /// Python pickle / legacy PyTorch `.bin` / `.pt` style artifact.
    Pickle,
    /// Package explicitly containing executable/custom model code.
    ExecutableCustomCode,
    OtherData,
}

impl ArtifactFormat {
    pub const fn is_data_only_preferred(self) -> bool {
        matches!(
            self,
            Self::Safetensors | Self::Gguf | Self::Onnx | Self::CoreMl
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerVerdict {
    NotRun,
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticParserVerdict {
    NotRun,
    ParsedSafely,
    Malformed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupplyChainDecision {
    Quarantine,
    Reject,
    ClearedForBehaviorEval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupplyChainReport {
    pub immutable_source: bool,
    pub digest_verified: bool,
    pub license_approved: bool,
    pub format: ArtifactFormat,
    pub malware_scan: ScannerVerdict,
    pub parser_scan: StaticParserVerdict,
    /// True if repository/package asks the runtime to import or execute
    /// publisher-controlled code (e.g. trust_remote_code-style behavior).
    pub requires_custom_code: bool,
}

impl SupplyChainReport {
    pub fn decision(self) -> SupplyChainDecision {
        if self.malware_scan == ScannerVerdict::Malicious
            || self.format == ArtifactFormat::ExecutableCustomCode
            || self.requires_custom_code
        {
            return SupplyChainDecision::Reject;
        }

        // Jend Store does not directly load pickle-based model packages.
        // A future offline conversion service may ingest them only inside a
        // disposable sandbox and emit a separate safe data-only release.
        if self.format == ArtifactFormat::Pickle {
            return SupplyChainDecision::Reject;
        }

        if !self.immutable_source
            || !self.digest_verified
            || !self.license_approved
            || self.malware_scan != ScannerVerdict::Clean
            || self.parser_scan != StaticParserVerdict::ParsedSafely
            || !self.format.is_data_only_preferred()
        {
            return SupplyChainDecision::Quarantine;
        }

        SupplyChainDecision::ClearedForBehaviorEval
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BehavioralVerdict {
    NotRun,
    Pass,
    Restricted,
    Fail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BehavioralEvalReport {
    pub backdoor_suite: BehavioralVerdict,
    pub prompt_injection_suite: BehavioralVerdict,
    pub tool_abuse_suite: BehavioralVerdict,
    pub data_exfiltration_suite: BehavioralVerdict,
    pub malformed_output_suite: BehavioralVerdict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreSafetyStatus {
    Quarantined,
    Rejected,
    Restricted,
    Approved,
}

impl BehavioralEvalReport {
    pub fn final_status(self, supply_chain: SupplyChainDecision) -> StoreSafetyStatus {
        match supply_chain {
            SupplyChainDecision::Reject => return StoreSafetyStatus::Rejected,
            SupplyChainDecision::Quarantine => return StoreSafetyStatus::Quarantined,
            SupplyChainDecision::ClearedForBehaviorEval => {}
        }

        let checks = [
            self.backdoor_suite,
            self.prompt_injection_suite,
            self.tool_abuse_suite,
            self.data_exfiltration_suite,
            self.malformed_output_suite,
        ];

        if checks.contains(&BehavioralVerdict::Fail) {
            return StoreSafetyStatus::Rejected;
        }
        if checks.contains(&BehavioralVerdict::NotRun) {
            return StoreSafetyStatus::Quarantined;
        }
        if checks.contains(&BehavioralVerdict::Restricted) {
            return StoreSafetyStatus::Restricted;
        }
        StoreSafetyStatus::Approved
    }

    pub fn validate_complete(self) -> Result<()> {
        if [
            self.backdoor_suite,
            self.prompt_injection_suite,
            self.tool_abuse_suite,
            self.data_exfiltration_suite,
            self.malformed_output_suite,
        ]
        .contains(&BehavioralVerdict::NotRun)
        {
            return Err(ModelStoreError::IncompleteSafetyEvaluation);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishGate {
    pub supply_chain: SupplyChainDecision,
    pub behavioral: BehavioralEvalReport,
}

impl PublishGate {
    pub fn public_store_status(self) -> StoreSafetyStatus {
        self.behavioral.final_status(self.supply_chain)
    }

    pub fn may_publish_publicly(self) -> bool {
        matches!(
            self.public_store_status(),
            StoreSafetyStatus::Approved | StoreSafetyStatus::Restricted
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleared() -> SupplyChainReport {
        SupplyChainReport {
            immutable_source: true,
            digest_verified: true,
            license_approved: true,
            format: ArtifactFormat::Safetensors,
            malware_scan: ScannerVerdict::Clean,
            parser_scan: StaticParserVerdict::ParsedSafely,
            requires_custom_code: false,
        }
    }

    fn passing_behavior() -> BehavioralEvalReport {
        BehavioralEvalReport {
            backdoor_suite: BehavioralVerdict::Pass,
            prompt_injection_suite: BehavioralVerdict::Pass,
            tool_abuse_suite: BehavioralVerdict::Pass,
            data_exfiltration_suite: BehavioralVerdict::Pass,
            malformed_output_suite: BehavioralVerdict::Pass,
        }
    }

    #[test]
    fn clean_data_only_artifact_advances_to_behavior_eval() {
        assert_eq!(
            cleared().decision(),
            SupplyChainDecision::ClearedForBehaviorEval
        );
    }

    #[test]
    fn pickle_is_rejected_even_when_antivirus_is_clean() {
        let mut report = cleared();
        report.format = ArtifactFormat::Pickle;
        assert_eq!(report.decision(), SupplyChainDecision::Reject);
    }

    #[test]
    fn custom_remote_code_is_rejected() {
        let mut report = cleared();
        report.requires_custom_code = true;
        assert_eq!(report.decision(), SupplyChainDecision::Reject);
    }

    #[test]
    fn mutable_or_unverified_source_stays_quarantined() {
        let mut report = cleared();
        report.immutable_source = false;
        assert_eq!(report.decision(), SupplyChainDecision::Quarantine);

        report.immutable_source = true;
        report.digest_verified = false;
        assert_eq!(report.decision(), SupplyChainDecision::Quarantine);
    }

    #[test]
    fn public_listing_requires_behavioral_suite() {
        let behavior = BehavioralEvalReport {
            backdoor_suite: BehavioralVerdict::Pass,
            prompt_injection_suite: BehavioralVerdict::NotRun,
            ..passing_behavior()
        };
        let gate = PublishGate {
            supply_chain: cleared().decision(),
            behavioral: behavior,
        };
        assert_eq!(gate.public_store_status(), StoreSafetyStatus::Quarantined);
        assert!(!gate.may_publish_publicly());
    }

    #[test]
    fn restricted_model_can_be_listed_with_restrictions() {
        let mut behavior = passing_behavior();
        behavior.tool_abuse_suite = BehavioralVerdict::Restricted;
        let gate = PublishGate {
            supply_chain: cleared().decision(),
            behavioral: behavior,
        };
        assert_eq!(gate.public_store_status(), StoreSafetyStatus::Restricted);
        assert!(gate.may_publish_publicly());
    }

    #[test]
    fn failed_backdoor_eval_rejects_release() {
        let mut behavior = passing_behavior();
        behavior.backdoor_suite = BehavioralVerdict::Fail;
        assert_eq!(
            behavior.final_status(cleared().decision()),
            StoreSafetyStatus::Rejected
        );
    }
}
