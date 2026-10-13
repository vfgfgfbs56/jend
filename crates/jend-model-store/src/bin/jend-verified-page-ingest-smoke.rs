#![forbid(unsafe_code)]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use jend_model_store::{
    DurableWeightPageStore, ModelId, ModelReleaseSigningKey, ModelSourceMap,
    ModelStoreError, PageSourceBinding, SourceDescriptor, SourceOrigin, VirtualModelMap,
    VirtualRegion, VirtualRegionKind, WeightPageDescriptor, WeightPageId, WeightVm,
    WeightVmBudget,
};

fn temp_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "jend-verified-page-ingest-smoke-{}-{}",
        std::process::id(),
        nanos
    ))
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let payload: Vec<u8> = (0..64 * 1024).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
    let expected = WeightPageDescriptor {
        page_id: WeightPageId::for_bytes(&payload),
        plaintext_len: payload.len() as u64,
    };
    let model_id = ModelId([0x56; 16]);
    let release_sequence = 856;

    let virtual_map = VirtualModelMap {
        model_id,
        release_sequence,
        minimum_runtime: 1,
        logical_weight_bytes: expected.plaintext_len,
        regions: vec![VirtualRegion {
            region_id: 0,
            kind: VirtualRegionKind::SharedBackbone,
            expert_id: None,
            expert_role: None,
            logical_offset: 0,
            logical_len: expected.plaintext_len,
            pages: vec![expected],
            prefetch_regions: vec![],
        }],
    };

    let source = SourceDescriptor {
        origin: SourceOrigin::HuggingFaceXet {
            repo_id: "openai-community/gpt2".into(),
            commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
            file_path: "model.safetensors".into(),
        },
        object_len: expected.plaintext_len + 4096,
        whole_object_sha256: None,
    };
    let source_id = source.source_id()?;
    let source_map = ModelSourceMap {
        model_id,
        release_sequence,
        sources: vec![source],
        bindings: vec![PageSourceBinding {
            page: expected,
            source_id,
            source_offset: 4096,
        }],
    };

    let signing = ModelReleaseSigningKey::generate()?;
    let public = signing.public_key();
    let signed_virtual = signing.sign_virtual_map(virtual_map)?;
    let signed_source = signing.sign_source_map(source_map)?;
    let verified = public.verify_source_read_request(
        &signed_source,
        &signed_virtual,
        expected.page_id,
        source_id,
    )?;
    if verified.expected_page() != expected
        || verified.request().source_offset != 4096
        || verified.release_key_id() != public.key_id()
    {
        return Err("verified request lost signed page/range identity".into());
    }

    let root = temp_root();
    let store = DurableWeightPageStore::new(&root)?;

    let mut wrong_digest = payload.clone();
    wrong_digest[0] ^= 0x80;
    if !matches!(
        store.put_verified_source_page(verified, &wrong_digest),
        Err(ModelStoreError::WeightPageDigestMismatch)
    ) {
        return Err("digest-mismatched reconstructed page was not rejected".into());
    }
    if store.stats()?.object_count != 0 {
        return Err("digest-mismatched bytes reached the durable object namespace".into());
    }

    if !matches!(
        store.put_verified_source_page(verified, &payload[..payload.len() - 1]),
        Err(ModelStoreError::WeightPageLengthMismatch)
    ) {
        return Err("length-mismatched reconstructed page was not rejected".into());
    }
    let staging_entries = fs::read_dir(root.join("staging"))?.count();
    if staging_entries != 0 || store.stats()?.object_count != 0 {
        return Err("rejected bytes created a staging/final durable object".into());
    }

    let stored = store.put_verified_source_page(verified, &payload)?;
    if stored != expected || !store.contains_verified(expected)? {
        return Err("verified page did not publish under its signed content identity".into());
    }

    let vm = WeightVm::new(
        store.clone(),
        WeightVmBudget {
            resident_bytes: expected.plaintext_len,
        },
    )?;
    let lease = vm.pin_page(expected)?;
    if lease.bytes() != payload.as_slice() {
        return Err("WeightVM did not receive exactly the verified durable page".into());
    }
    drop(lease);

    let mut tampered_source = signed_source.clone();
    tampered_source.map.bindings[0].source_offset += 1;
    if public
        .verify_source_read_request(
            &tampered_source,
            &signed_virtual,
            expected.page_id,
            source_id,
        )
        .is_ok()
    {
        return Err("tampered source map minted a verified read request".into());
    }

    let stats = store.stats()?;
    println!("Jend signed source+virtual map request gate: PASS");
    println!("Jend reconstructed page exact length/SHA-256 gate: PASS");
    println!("Jend rejected page never reaches staging/object namespace: PASS");
    println!("Jend durable verified WeightPage publication: PASS");
    println!("Jend WeightVM verified-store admission: PASS");
    println!(
        "Jend verified page: bytes={}, objects={}, source_offset={}, release_sequence={}",
        expected.plaintext_len,
        stats.object_count,
        verified.request().source_offset,
        release_sequence,
    );

    fs::remove_dir_all(root)?;
    Ok(())
}
