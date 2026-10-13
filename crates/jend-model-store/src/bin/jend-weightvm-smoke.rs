#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::Arc,
};

use jend_model_store::{
    ModelStoreError, VirtualPagedSpec, WeightPageDescriptor, WeightPageId, WeightPageSource,
    WeightVm, WeightVmBudget,
};

#[derive(Clone)]
struct MemoryObjectStore {
    pages: Arc<HashMap<WeightPageId, Vec<u8>>>,
}

impl WeightPageSource for MemoryObjectStore {
    fn read_page(&self, page_id: WeightPageId) -> jend_model_store::Result<Vec<u8>> {
        self.pages
            .get(&page_id)
            .cloned()
            .ok_or(ModelStoreError::InvalidWeightPage)
    }
}

fn fixture(seed: u8, bytes: usize) -> (WeightPageDescriptor, Vec<u8>) {
    let payload = vec![seed; bytes];
    (
        WeightPageDescriptor {
            page_id: WeightPageId::for_bytes(&payload),
            plaintext_len: bytes as u64,
        },
        payload,
    )
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Logical model size is deliberately huge. M8.0 does not claim this whole
    // model is runnable from 4 MiB; this smoke proves residency virtualization.
    let logical_model = VirtualPagedSpec {
        logical_weight_bytes: 500_000_000_000,
        active_weight_bytes: 16_000_000_000,
        minimum_cache_bytes: 4 * 1024 * 1024,
        page_bytes: 1024 * 1024,
        expert_paging: true,
    };

    let fixtures: Vec<_> = (1u8..=6)
        .map(|seed| fixture(seed, 1024 * 1024))
        .collect();

    let store = MemoryObjectStore {
        pages: Arc::new(
            fixtures
                .iter()
                .map(|(descriptor, bytes)| (descriptor.page_id, bytes.clone()))
                .collect(),
        ),
    };

    let vm = WeightVm::new(
        store,
        WeightVmBudget {
            resident_bytes: 4 * 1024 * 1024,
        },
    )?;

    // Keep the first page pinned while causing faults/evictions around it.
    let pinned = vm.pin_page(fixtures[0].0)?;
    for (descriptor, _) in fixtures.iter().skip(1) {
        vm.prefetch_page(*descriptor)?;
    }

    let snapshot = vm.snapshot();
    if snapshot.resident_bytes > 4 * 1024 * 1024 {
        return Err("WeightVM exceeded its physical residency budget".into());
    }
    if snapshot.evictions < 2 {
        return Err("WeightVM did not evict cold pages under pressure".into());
    }
    if snapshot.pinned_pages != 1 || pinned.len() != 1024 * 1024 {
        return Err("WeightVM failed to preserve an active pinned page".into());
    }
    if logical_model.logical_weight_bytes <= snapshot.resident_bytes {
        return Err("smoke no longer demonstrates logical > physical residency".into());
    }

    // Content addressing must deduplicate the same immutable page.
    let before = vm.snapshot();
    let duplicate = vm.pin_page(fixtures[0].0)?;
    let after = vm.snapshot();
    if after.resident_pages != before.resident_pages || after.hits <= before.hits {
        return Err("content-addressed resident-page reuse failed".into());
    }
    drop(duplicate);
    drop(pinned);

    println!(
        "Jend WeightVM: logical_gb={}, physical_cache_mib={}, resident_mib={}, evictions={}",
        logical_model.logical_weight_bytes / 1_000_000_000,
        4,
        vm.snapshot().resident_bytes / (1024 * 1024),
        vm.snapshot().evictions,
    );
    println!("Jend WeightVM bounded residency/page-fault smoke: PASS");
    println!("Jend WeightVM content-addressed dedup/pinning: PASS");
    Ok(())
}
