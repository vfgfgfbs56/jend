#![forbid(unsafe_code)]

use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use jend_model_store::{
    DurableWeightPageStore, ExpertId, ExpertRole, ModelId, ModelReleaseSigningKey,
    VirtualModelMap, VirtualRegion, VirtualRegionKind, WeightVm, WeightVmBudget,
};

fn temp_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("jend-virtual-map-smoke-{}-{}", std::process::id(), nanos))
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = temp_root();
    let store = DurableWeightPageStore::new(&root)?;

    let payloads: Vec<Vec<u8>> = (1u8..=6)
        .map(|seed| vec![seed; 1024 * 1024])
        .collect();
    let pages = payloads
        .iter()
        .map(|payload| store.put_page(payload))
        .collect::<jend_model_store::Result<Vec<_>>>()?;

    let map = VirtualModelMap {
        model_id: ModelId([81u8; 16]),
        release_sequence: 1,
        minimum_runtime: 1,
        logical_weight_bytes: 6 * 1024 * 1024,
        regions: vec![
            VirtualRegion {
                region_id: 0,
                kind: VirtualRegionKind::SharedBackbone,
                expert_id: None,
                expert_role: None,
                logical_offset: 0,
                logical_len: 1024 * 1024,
                pages: vec![pages[0]],
                prefetch_regions: vec![],
            },
            VirtualRegion {
                region_id: 1,
                kind: VirtualRegionKind::Router,
                expert_id: None,
                expert_role: None,
                logical_offset: 1024 * 1024,
                logical_len: 1024 * 1024,
                pages: vec![pages[1]],
                prefetch_regions: vec![0],
            },
            VirtualRegion {
                region_id: 2,
                kind: VirtualRegionKind::Expert,
                expert_id: Some(ExpertId(17)),
                expert_role: Some(ExpertRole::Coding),
                logical_offset: 2 * 1024 * 1024,
                logical_len: 2 * 1024 * 1024,
                pages: vec![pages[2], pages[3]],
                prefetch_regions: vec![0, 1],
            },
            VirtualRegion {
                region_id: 3,
                kind: VirtualRegionKind::Expert,
                expert_id: Some(ExpertId(42)),
                expert_role: Some(ExpertRole::Reasoning),
                logical_offset: 4 * 1024 * 1024,
                logical_len: 2 * 1024 * 1024,
                pages: vec![pages[4], pages[5]],
                prefetch_regions: vec![0, 1],
            },
        ],
    };
    map.validate()?;

    let signing = ModelReleaseSigningKey::generate()?;
    let public = signing.public_key();
    let signed = signing.sign_virtual_map(map)?;
    public.verify_virtual_map(&signed)?;

    let wire = signed.encode_wire()?;
    let decoded = jend_model_store::SignedVirtualModelMap::decode_wire(&wire)?;
    public.verify_virtual_map(&decoded)?;

    if decoded.map.experts_for_role(ExpertRole::Coding) != vec![ExpertId(17)] {
        return Err("coding role did not resolve to expert 17".into());
    }
    let warm = decoded.map.prefetch_pages_for_expert(ExpertId(17))?;
    if warm.len() != 4 {
        return Err("coding expert warm-up plan did not include backbone/router dependencies".into());
    }

    let reopened = DurableWeightPageStore::new(&root)?;
    let vm = WeightVm::new(
        reopened,
        WeightVmBudget { resident_bytes: 4 * 1024 * 1024 },
    )?;
    for page in warm {
        vm.prefetch_page(page)?;
    }
    let snapshot = vm.snapshot();
    if snapshot.resident_pages != 4 || snapshot.resident_bytes != 4 * 1024 * 1024 {
        return Err("expert map did not materialize the expected bounded working set".into());
    }

    let mut tampered = decoded.clone();
    tampered.map.regions[2].expert_id = Some(ExpertId(99));
    if public.verify_virtual_map(&tampered).is_ok() {
        return Err("signed expert-map tampering was not detected".into());
    }

    println!(
        "Jend virtual map: regions={}, coding_expert={}, warm_pages={}, resident_mib={}",
        decoded.map.regions.len(),
        17,
        4,
        snapshot.resident_bytes / (1024 * 1024),
    );
    println!("Jend signed virtual-model/expert address map: PASS");
    println!("Jend expert-to-WeightVM page resolution: PASS");

    fs::remove_dir_all(root)?;
    Ok(())
}
