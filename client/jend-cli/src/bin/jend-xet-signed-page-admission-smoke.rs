#![forbid(unsafe_code)]

// Offline end-to-end proof: two independent signed Xet single-range grants
// -> bounded Xorb v0 decode -> independent Jend release-signed SHA-256 page
// -> durable store -> WeightVM. All keypairs/bytes here are TEST FIXTURES.
// This is NOT a claim of a real GPT2/HF model publisher signature.
#[allow(dead_code)]
#[path = "../source_worker_transport.rs"]
mod source_worker_transport;
#[allow(dead_code)]
#[path = "../xet_metadata.rs"]
mod xet_metadata;
#[allow(dead_code)]
#[path = "../xet_fetch_schedule.rs"]
mod xet_fetch_schedule;
#[allow(dead_code)]
#[path = "../xet_multipart.rs"]
mod xet_multipart;
#[allow(dead_code)]
#[path = "../xet_multi_fetch_transport.rs"]
mod xet_multi_fetch_transport;
#[allow(dead_code)]
#[path = "../xet_signed_fetch_executor.rs"]
mod xet_signed_fetch_executor;
#[allow(dead_code)]
#[path = "../xorb_decode.rs"]
mod xorb_decode;
#[allow(dead_code)]
#[path = "../xet_multi_decode.rs"]
mod xet_multi_decode;
#[allow(dead_code)]
#[path = "../verified_xet_page_bridge.rs"]
mod verified_xet_page_bridge;

use jend_model_store::{
    DurableWeightPageStore, ModelId, ModelReleaseSigningKey, ModelSourceMap,
    ModelStoreError, PageSourceBinding, SourceDescriptor, SourceOrigin, VirtualModelMap,
    VirtualRegion, VirtualRegionKind, WeightPageDescriptor, WeightPageId, WeightVm, WeightVmBudget,
};
use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use verified_xet_page_bridge::{
    reconstruct_and_publish_signed_xet_page, ExpectedImmutableHfSource, PageAdmissionError,
};
use xet_fetch_schedule::{build_fetch_schedule, FetchScheduleLimits};
use xet_metadata::parse_v2_reconstruction;
use xet_signed_fetch_executor::{validate_signed_single_range_body, validate_schedule, SequentialFetchLimits};

const HF_REPO: &str = "openai-community/gpt2";
const HF_COMMIT: &str = "607a30d783dfa663caf39e06633721c8d4cfcd7e";
const HF_FILE: &str = "model.safetensors";
const OFFSET: u64 = 4096;

fn record(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut v = vec![0, n as u8, 0, 0, 0, n as u8, 0, 0];
    v.extend_from_slice(data);
    v
}

fn root() -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
        .expect("UNIX clock").as_nanos();
    std::env::temp_dir().join(format!("jend-m8513-page-{}-{}", std::process::id(), nanos))
}

fn origin(source_offset: u64) -> ExpectedImmutableHfSource<'static> {
    ExpectedImmutableHfSource {
        repo_id: HF_REPO,
        commit_sha: HF_COMMIT,
        file_path: HF_FILE,
        source_offset,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"abcdef";
    let hash = "a".repeat(64);
    let reconstruction_fixture = format!(
        r#"{{"offset_into_first_range":0,
          "terms":[
            {{"hash":"{hash}","unpacked_length":3,"range":{{"start":0,"end":1}}}},
            {{"hash":"{hash}","unpacked_length":3,"range":{{"start":1,"end":2}}}}
          ],
          "xorbs":{{"{hash}":[
            {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p&Signature=s&Key-Pair-Id=k",
              "ranges":[{{"chunks":{{"start":0,"end":1}},"bytes":{{"start":0,"end":10}}}}]}},
            {{"url":"https://us.aws.cdn.hf.co/xorbs/default/{hash}?Expires=9999999999&Policy=p2&Signature=s2&Key-Pair-Id=k",
              "ranges":[{{"chunks":{{"start":1,"end":2}},"bytes":{{"start":20,"end":30}}}}]}}
          ]}}}}"#
    );
    let reconstruction = parse_v2_reconstruction(reconstruction_fixture.as_bytes(), 6)?;
    let schedule = build_fetch_schedule(&reconstruction, FetchScheduleLimits {
        max_total_payload_bytes: 22,
        max_request_payload_bytes: 11,
        max_jobs: 2,
        max_ranges: 2,
        max_concurrency: 1,
    })?;
    validate_schedule(&schedule, SequentialFetchLimits {
        max_total_physical_bytes: 22,
        max_jobs: 2,
        max_framing_per_job: 512,
        connect_timeout_ms: 1000,
        request_timeout_ms: 2000,
    })?;
    let mut ranges = Vec::new();
    for (job, (raw, content_range)) in schedule.jobs.iter().zip([
        (record(b"abc"), "bytes 0-10/100"),
        (record(b"def"), "bytes 20-30/100"),
    ]) {
        ranges.push(validate_signed_single_range_body(
            &job.request, reqwest::StatusCode::PARTIAL_CONTENT,
            content_range, raw, 22
        )?);
    }

    let expected_page = WeightPageDescriptor {
        page_id: WeightPageId::for_bytes(data),
        plaintext_len: u64::try_from(data.len())?,
    };
    let model_id = ModelId([0x51; 16]);
    let release_sequence = 8513u64;
    let virtual_map = VirtualModelMap {
        model_id,
        release_sequence,
        minimum_runtime: 1,
        logical_weight_bytes: expected_page.plaintext_len,
        regions: vec![VirtualRegion {
            region_id: 0,
            kind: VirtualRegionKind::SharedBackbone,
            expert_id: None,
            expert_role: None,
            logical_offset: 0,
            logical_len: expected_page.plaintext_len,
            pages: vec![expected_page],
            prefetch_regions: vec![],
        }],
    };
    let source = SourceDescriptor {
        origin: SourceOrigin::HuggingFaceXet {
            repo_id: HF_REPO.into(),
            commit_sha: HF_COMMIT.into(),
            file_path: HF_FILE.into(),
        },
        object_len: 8192,
        whole_object_sha256: None,
    };
    let source_id = source.source_id()?;
    let source_map = ModelSourceMap {
        model_id,
        release_sequence,
        sources: vec![source],
        bindings: vec![PageSourceBinding {
            page: expected_page,
            source_id,
            source_offset: OFFSET,
        }],
    };

    // Test-only ephemeral signing key. Production callers need independently
    // trusted public key / signed maps obtained from release distribution.
    let signing = ModelReleaseSigningKey::generate()?;
    let trusted = signing.public_key();
    let signed_virtual = signing.sign_virtual_map(virtual_map)?;
    let signed_source = signing.sign_source_map(source_map)?;

    let temp = root();
    let store = DurableWeightPageStore::new(&temp)?;
    let invoke = |ranges, source, signed_source: &jend_model_store::SignedModelSourceMap,
                  signed_virtual: &jend_model_store::SignedVirtualModelMap,
                  trusted: &jend_model_store::ModelReleasePublicKey| {
        reconstruct_and_publish_signed_xet_page(
            &store, trusted, signed_source, signed_virtual,
            expected_page.page_id, source_id, source,
            &reconstruction, ranges, 22, 6,
        )
    };

    // First prove no untrusted transport bytes or modified release maps can
    // write a staging file or a durable content-addressed object.
    let mut flipped = ranges.clone();
    flipped[1].bytes[10] ^= 1;
    if !matches!(
        invoke(flipped, origin(OFFSET), &signed_source, &signed_virtual, &trusted),
        Err(PageAdmissionError::VerifiedStore(ModelStoreError::WeightPageDigestMismatch))
    ) { return Err("a one-byte source corruption bypassed signed WeightPage SHA-256".into()); }

    let mut truncated = ranges.clone();
    truncated[1].bytes.pop();
    if !matches!(
        invoke(truncated, origin(OFFSET), &signed_source, &signed_virtual, &trusted),
        Err(PageAdmissionError::PhysicalDecode(_))
    ) { return Err("a truncated signed Xet physical range bypassed bounds".into()); }

    let mut altered_source = signed_source.clone();
    altered_source.map.bindings[0].source_offset += 1;
    if !matches!(
        invoke(ranges.clone(), origin(OFFSET), &altered_source, &signed_virtual, &trusted),
        Err(PageAdmissionError::SignedMap(_))
    ) { return Err("a mutated release-signed SourceMap was accepted".into()); }

    let mut altered_virtual = signed_virtual.clone();
    altered_virtual.map.release_sequence += 1;
    if !matches!(
        invoke(ranges.clone(), origin(OFFSET), &signed_source, &altered_virtual, &trusted),
        Err(PageAdmissionError::SignedMap(_))
    ) { return Err("a mutated release-signed VirtualMap was accepted".into()); }

    if !matches!(
        invoke(ranges.clone(), origin(OFFSET + 1), &signed_source, &signed_virtual, &trusted),
        Err(PageAdmissionError::UntrustedSourceOffset)
    ) { return Err("source offset outside signed binding was accepted".into()); }

    let wrong_origin = ExpectedImmutableHfSource {
        repo_id: "other-owner/other-model",
        ..origin(OFFSET)
    };
    if !matches!(
        invoke(ranges.clone(), wrong_origin, &signed_source, &signed_virtual, &trusted),
        Err(PageAdmissionError::UntrustedOrigin)
    ) { return Err("wrong immutable HF source identity was accepted".into()); }

    let attacker_key = ModelReleaseSigningKey::generate()?.public_key();
    if !matches!(
        invoke(ranges.clone(), origin(OFFSET), &signed_source, &signed_virtual, &attacker_key),
        Err(PageAdmissionError::SignedMap(_))
    ) { return Err("untrusted release key was accepted as signer".into()); }

    if store.stats()?.object_count != 0 || fs::read_dir(temp.join("staging"))?.count() != 0 {
        return Err("a rejected page reached durable staging/object namespace".into());
    }

    let page = invoke(ranges, origin(OFFSET), &signed_source, &signed_virtual, &trusted)?;
    if page != expected_page || !store.contains_verified(page)? {
        return Err("signed WeightPage was not published under independent digest".into());
    }
    let vm = WeightVm::new(store.clone(), WeightVmBudget { resident_bytes: 6 })?;
    let lease = vm.pin_page(page)?;
    if lease.bytes() != data || vm.snapshot().resident_pages != 1 {
        return Err("WeightVM did not admit exactly the release-signed local page".into());
    }
    drop(lease);

    println!("Jend Xet release-signed source+virtual map admission: PASS");
    println!("Jend Xet immutable HF source and offset binding: PASS");
    println!("Jend Xet modified digest/length rejected before staging: PASS");
    println!("Jend Xet untrusted signing key and maps rejected: PASS");
    println!("Jend Xet durable signed WeightPage and WeightVM lease: PASS");
    println!("Jend Xet page admission uses synthetic offline fixture only: PASS");

    fs::remove_dir_all(temp)?;
    Ok(())
}
