#![forbid(unsafe_code)]

use jend_model_store::{
    ArtifactFormat, BehavioralEvalReport, BehavioralVerdict, LicenseEvidence,
    LicenseEvidenceKind, ModelProvenance, ModelSource, PublishGate, RedistributionDecision,
    ScannerVerdict, StaticParserVerdict, StoreSafetyStatus, SupplyChainDecision,
    SupplyChainReport,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = ModelSource::HuggingFaceSnapshot {
        repo_id: "example-org/example-model".into(),
        commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
    };
    let provenance = ModelProvenance {
        publisher: "Example Org".into(),
        source,
        license: LicenseEvidence {
            license_id: "apache-2.0".into(),
            evidence_kind: LicenseEvidenceKind::HubMetadata,
            redistribution: RedistributionDecision::Approved,
        },
    };
    if !provenance.permits_weight_publication()? {
        return Err("approved immutable provenance failed publication gate".into());
    }

    let supply = SupplyChainReport {
        immutable_source: true,
        digest_verified: true,
        license_approved: true,
        format: ArtifactFormat::Safetensors,
        malware_scan: ScannerVerdict::Clean,
        parser_scan: StaticParserVerdict::ParsedSafely,
        requires_custom_code: false,
    };
    if supply.decision() != SupplyChainDecision::ClearedForBehaviorEval {
        return Err("safe data-only package did not reach behavioral quarantine".into());
    }

    let behavior = BehavioralEvalReport {
        backdoor_suite: BehavioralVerdict::Pass,
        prompt_injection_suite: BehavioralVerdict::Pass,
        tool_abuse_suite: BehavioralVerdict::Restricted,
        data_exfiltration_suite: BehavioralVerdict::Pass,
        malformed_output_suite: BehavioralVerdict::Pass,
    };
    let gate = PublishGate {
        supply_chain: supply.decision(),
        behavioral: behavior,
    };
    if gate.public_store_status() != StoreSafetyStatus::Restricted
        || !gate.may_publish_publicly()
    {
        return Err("restricted behavioral result did not retain explicit restriction status".into());
    }

    let pickle = SupplyChainReport {
        format: ArtifactFormat::Pickle,
        ..supply
    };
    if pickle.decision() != SupplyChainDecision::Reject {
        return Err("pickle package escaped the Store rejection gate".into());
    }

    println!("Jend immutable-source/license/quarantine contract: PASS");
    println!("Jend model supply-chain/behavior safety contract: PASS");
    Ok(())
}
