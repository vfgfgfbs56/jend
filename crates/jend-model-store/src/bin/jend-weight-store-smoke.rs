#![forbid(unsafe_code)]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use jend_model_store::{
    DurableWeightPageStore, WeightPageSource, WeightVm, WeightVmBudget,
};

fn temp_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "jend-weight-store-smoke-{}-{}",
        std::process::id(),
        nanos
    ))
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = temp_root();
    let page_a = vec![0xA1u8; 1024 * 1024];
    let page_b = vec![0xB2u8; 1024 * 1024];

    let (a, b) = {
        let store = DurableWeightPageStore::new(&root)?;
        let a = store.put_page(&page_a)?;
        let a_again = store.put_page(&page_a)?;
        let b = store.put_page(&page_b)?;
        if a != a_again {
            return Err("content-addressed duplicate produced a second identity".into());
        }
        let stats = store.stats()?;
        if stats.object_count != 2 || stats.stored_bytes != 2 * 1024 * 1024 {
            return Err("durable page-store dedup/statistics contract failed".into());
        }

        // Simulate a crash leaving a partial file. It must never become an
        // object and must be removed on reopen.
        let staging = root.join("staging").join("simulated-crash.part");
        fs::write(&staging, b"incomplete")?;
        (a, b)
    };

    let reopened = DurableWeightPageStore::new(&root)?;
    if root.join("staging").join("simulated-crash.part").exists() {
        return Err("stale crash staging file survived recovery".into());
    }
    if !reopened.contains_verified(a)? || !reopened.contains_verified(b)? {
        return Err("verified pages did not survive store restart".into());
    }

    // Prove the reopened SSD/object store is a direct WeightVM page source.
    let vm = WeightVm::new(
        reopened.clone(),
        WeightVmBudget {
            resident_bytes: 1024 * 1024,
        },
    )?;
    let lease_a = vm.pin_page(a)?;
    if lease_a.bytes() != page_a.as_slice() {
        return Err("WeightVM read wrong bytes from durable store".into());
    }
    drop(lease_a);
    let lease_b = vm.pin_page(b)?;
    if lease_b.bytes() != page_b.as_slice() {
        return Err("WeightVM second durable page mismatch".into());
    }
    drop(lease_b);

    let snapshot = vm.snapshot();
    if snapshot.resident_bytes != 1024 * 1024 || snapshot.evictions < 1 {
        return Err("WeightVM did not evict while backed by durable page store".into());
    }

    // Re-read through the source API to prove digest verification remains
    // active outside RAM residency.
    if reopened.read_page(a.page_id)? != page_a {
        return Err("durable object verification/readback failed".into());
    }

    let stats = reopened.stats()?;
    println!(
        "Jend durable WeightVM store: objects={}, stored_mib={}, resident_mib={}, evictions={}",
        stats.object_count,
        stats.stored_bytes / (1024 * 1024),
        snapshot.resident_bytes / (1024 * 1024),
        snapshot.evictions,
    );
    println!("Jend WeightVM durable restart/recovery: PASS");
    println!("Jend WeightVM disk content-addressed dedup: PASS");

    fs::remove_dir_all(root)?;
    Ok(())
}
