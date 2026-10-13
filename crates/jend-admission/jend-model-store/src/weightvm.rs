//! WeightVM v1: bounded content-addressed weight-page residency.
//!
//! WeightVM does not contain a network client. A page source is expected to be
//! a local verified object store / cache populated by a separate authorized
//! ingestion or sync path. Every page is verified again by length and SHA-256
//! before it can become resident.
//!
//! Cache identity is the content digest, not `(model, offset)`, so identical
//! pages can be shared across model releases. Resident pages are LRU-evicted,
//! but a page with an active lease is pinned and cannot be evicted.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{ModelStoreError, Result};

const MAX_PAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024; // 4 TiB

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct WeightPageId(pub [u8; 32]);

impl WeightPageId {
    pub fn for_bytes(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self(h.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightPageDescriptor {
    pub page_id: WeightPageId,
    pub plaintext_len: u64,
}

impl WeightPageDescriptor {
    pub fn validate(self) -> Result<Self> {
        if self.plaintext_len == 0
            || self.plaintext_len > MAX_PAGE_BYTES
            || self.page_id.0.iter().all(|byte| *byte == 0)
        {
            return Err(ModelStoreError::InvalidWeightPage);
        }
        Ok(self)
    }
}

/// The v1 source boundary is deliberately byte-oriented and network-agnostic.
/// `jend-model-store` has no HTTP dependency; future network fetches must land
/// in a verified local object cache before WeightVM consumes them.
pub trait WeightPageSource: Send + Sync + 'static {
    fn read_page(&self, page_id: WeightPageId) -> Result<Vec<u8>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightVmBudget {
    pub resident_bytes: u64,
}

impl WeightVmBudget {
    pub fn validate(self) -> Result<Self> {
        if self.resident_bytes > MAX_CACHE_BYTES {
            return Err(ModelStoreError::InvalidWeightVmBudget);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightVmSnapshot {
    pub budget_bytes: u64,
    pub resident_bytes: u64,
    pub resident_pages: usize,
    pub pinned_pages: usize,
    pub hits: u64,
    pub faults: u64,
    pub evictions: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightVmBudgetUpdate {
    pub previous: WeightVmBudget,
    pub current: WeightVmBudget,
    pub resident_bytes: u64,
    pub over_budget_due_to_pins: bool,
}

struct ResidentPage {
    bytes: Arc<[u8]>,
    pins: usize,
}

struct WeightVmState {
    budget: WeightVmBudget,
    pages: HashMap<WeightPageId, ResidentPage>,
    lru: VecDeque<WeightPageId>,
    resident_bytes: u64,
    hits: u64,
    faults: u64,
    evictions: u64,
}

struct WeightVmInner<S: WeightPageSource> {
    source: S,
    state: Mutex<WeightVmState>,
}

pub struct WeightVm<S: WeightPageSource> {
    inner: Arc<WeightVmInner<S>>,
}

impl<S: WeightPageSource> Clone for WeightVm<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

pub struct WeightPageLease<S: WeightPageSource> {
    page_id: WeightPageId,
    bytes: Arc<[u8]>,
    inner: Arc<WeightVmInner<S>>,
}

impl<S: WeightPageSource> WeightPageLease<S> {
    pub fn page_id(&self) -> WeightPageId {
        self.page_id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<S: WeightPageSource> Drop for WeightPageLease<S> {
    fn drop(&mut self) {
        let mut state = lock_state(&self.inner.state);
        if let Some(page) = state.pages.get_mut(&self.page_id) {
            page.pins = page.pins.saturating_sub(1);
        }
    }
}

impl<S: WeightPageSource> WeightVm<S> {
    pub fn new(source: S, budget: WeightVmBudget) -> Result<Self> {
        let budget = budget.validate()?;
        Ok(Self {
            inner: Arc::new(WeightVmInner {
                source,
                state: Mutex::new(WeightVmState {
                    budget,
                    pages: HashMap::new(),
                    lru: VecDeque::new(),
                    resident_bytes: 0,
                    hits: 0,
                    faults: 0,
                    evictions: 0,
                }),
            }),
        })
    }

    /// Resolve a page fault (if needed), verify the page, make it resident, and
    /// pin it for the lifetime of the returned lease.
    pub fn pin_page(
        &self,
        descriptor: WeightPageDescriptor,
    ) -> Result<WeightPageLease<S>> {
        let descriptor = descriptor.validate()?;

        if let Some(lease) = self.try_pin_resident(descriptor.page_id) {
            return Ok(lease);
        }

        {
            let mut state = lock_state(&self.inner.state);
            state.faults = state
                .faults
                .checked_add(1)
                .ok_or(ModelStoreError::Overflow)?;
        }

        // Never perform potentially slow page-source I/O while holding the
        // residency mutex. A racing fault may fetch the same immutable page
        // twice; the second insertion reuses the first resident copy.
        let bytes = self.inner.source.read_page(descriptor.page_id)?;
        verify_page(descriptor, &bytes)?;
        let bytes: Arc<[u8]> = Arc::from(bytes);

        let mut state = lock_state(&self.inner.state);

        // Another thread may have inserted this immutable page while we read.
        if state.pages.contains_key(&descriptor.page_id) {
            let resident = {
                let page = state
                    .pages
                    .get_mut(&descriptor.page_id)
                    .expect("resident page existence was checked");
                page.pins = page
                    .pins
                    .checked_add(1)
                    .ok_or(ModelStoreError::Overflow)?;
                Arc::clone(&page.bytes)
            };
            touch_lru(&mut state, descriptor.page_id);
            return Ok(WeightPageLease {
                page_id: descriptor.page_id,
                bytes: resident,
                inner: Arc::clone(&self.inner),
            });
        }

        if descriptor.plaintext_len > state.budget.resident_bytes {
            return Err(ModelStoreError::WeightVmBudgetTooSmall);
        }

        while state
            .resident_bytes
            .checked_add(descriptor.plaintext_len)
            .ok_or(ModelStoreError::Overflow)?
            > state.budget.resident_bytes
        {
            if !evict_one_unpinned(&mut state)? {
                return Err(ModelStoreError::WeightVmAllPagesPinned);
            }
        }

        state.resident_bytes = state
            .resident_bytes
            .checked_add(descriptor.plaintext_len)
            .ok_or(ModelStoreError::Overflow)?;
        state.pages.insert(
            descriptor.page_id,
            ResidentPage {
                bytes: Arc::clone(&bytes),
                pins: 1,
            },
        );
        touch_lru(&mut state, descriptor.page_id);

        Ok(WeightPageLease {
            page_id: descriptor.page_id,
            bytes,
            inner: Arc::clone(&self.inner),
        })
    }

    /// Populate/refresh a verified page without keeping it pinned.
    pub fn prefetch_page(&self, descriptor: WeightPageDescriptor) -> Result<()> {
        let lease = self.pin_page(descriptor)?;
        drop(lease);
        Ok(())
    }

    /// Change the live residency budget. Tightening never invalidates active
    /// leases. If pinned pages alone exceed the new budget, WeightVM reports
    /// that state and drains below budget as those leases are released and
    /// later insertions trigger eviction.
    pub fn update_budget(&self, budget: WeightVmBudget) -> Result<WeightVmBudgetUpdate> {
        let budget = budget.validate()?;
        let mut state = lock_state(&self.inner.state);
        let previous = state.budget;
        state.budget = budget;

        while state.resident_bytes > state.budget.resident_bytes {
            if !evict_one_unpinned(&mut state)? {
                break;
            }
        }

        Ok(WeightVmBudgetUpdate {
            previous,
            current: budget,
            resident_bytes: state.resident_bytes,
            over_budget_due_to_pins: state.resident_bytes > budget.resident_bytes,
        })
    }

    pub fn snapshot(&self) -> WeightVmSnapshot {
        let state = lock_state(&self.inner.state);
        WeightVmSnapshot {
            budget_bytes: state.budget.resident_bytes,
            resident_bytes: state.resident_bytes,
            resident_pages: state.pages.len(),
            pinned_pages: state.pages.values().filter(|page| page.pins > 0).count(),
            hits: state.hits,
            faults: state.faults,
            evictions: state.evictions,
        }
    }

    fn try_pin_resident(&self, page_id: WeightPageId) -> Option<WeightPageLease<S>> {
        let mut state = lock_state(&self.inner.state);
        let bytes = {
            let page = state.pages.get_mut(&page_id)?;
            page.pins = page.pins.checked_add(1)?;
            Arc::clone(&page.bytes)
        };
        state.hits = state.hits.saturating_add(1);
        touch_lru(&mut state, page_id);
        Some(WeightPageLease {
            page_id,
            bytes,
            inner: Arc::clone(&self.inner),
        })
    }
}

fn verify_page(descriptor: WeightPageDescriptor, bytes: &[u8]) -> Result<()> {
    let actual_len = u64::try_from(bytes.len()).map_err(|_| ModelStoreError::Overflow)?;
    if actual_len != descriptor.plaintext_len {
        return Err(ModelStoreError::WeightPageLengthMismatch);
    }
    let actual = WeightPageId::for_bytes(bytes);
    if actual.0.ct_eq(&descriptor.page_id.0).unwrap_u8() != 1 {
        return Err(ModelStoreError::WeightPageDigestMismatch);
    }
    Ok(())
}

fn touch_lru(state: &mut WeightVmState, page_id: WeightPageId) {
    if let Some(position) = state.lru.iter().position(|candidate| *candidate == page_id) {
        state.lru.remove(position);
    }
    state.lru.push_back(page_id);
}

fn evict_one_unpinned(state: &mut WeightVmState) -> Result<bool> {
    let candidates = state.lru.len();
    for _ in 0..candidates {
        let Some(page_id) = state.lru.pop_front() else {
            return Ok(false);
        };

        let pinned = state
            .pages
            .get(&page_id)
            .is_some_and(|page| page.pins > 0);

        if pinned {
            state.lru.push_back(page_id);
            continue;
        }

        if let Some(page) = state.pages.remove(&page_id) {
            let len = u64::try_from(page.bytes.len()).map_err(|_| ModelStoreError::Overflow)?;
            state.resident_bytes = state
                .resident_bytes
                .checked_sub(len)
                .ok_or(ModelStoreError::Overflow)?;
            state.evictions = state
                .evictions
                .checked_add(1)
                .ok_or(ModelStoreError::Overflow)?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn lock_state<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MemorySource {
        pages: Arc<HashMap<WeightPageId, Vec<u8>>>,
    }

    impl WeightPageSource for MemorySource {
        fn read_page(&self, page_id: WeightPageId) -> Result<Vec<u8>> {
            self.pages
                .get(&page_id)
                .cloned()
                .ok_or(ModelStoreError::InvalidWeightPage)
        }
    }

    fn page(seed: u8, len: usize) -> (WeightPageDescriptor, Vec<u8>) {
        let bytes = vec![seed; len];
        let descriptor = WeightPageDescriptor {
            page_id: WeightPageId::for_bytes(&bytes),
            plaintext_len: len as u64,
        };
        (descriptor, bytes)
    }

    fn vm(
        budget: u64,
        fixtures: &[(WeightPageDescriptor, Vec<u8>)],
    ) -> WeightVm<MemorySource> {
        let pages = fixtures
            .iter()
            .map(|(descriptor, bytes)| (descriptor.page_id, bytes.clone()))
            .collect();
        WeightVm::new(
            MemorySource {
                pages: Arc::new(pages),
            },
            WeightVmBudget {
                resident_bytes: budget,
            },
        )
        .unwrap()
    }

    #[test]
    fn page_fault_verifies_and_hit_reuses_resident_copy() {
        let fixture = page(7, 1024);
        let vm = vm(4096, &[fixture.clone()]);
        let first = vm.pin_page(fixture.0).unwrap();
        assert_eq!(first.bytes(), fixture.1.as_slice());
        drop(first);

        let second = vm.pin_page(fixture.0).unwrap();
        assert_eq!(second.bytes(), fixture.1.as_slice());

        let snapshot = vm.snapshot();
        assert_eq!(snapshot.faults, 1);
        assert_eq!(snapshot.hits, 1);
        assert_eq!(snapshot.resident_pages, 1);
    }

    #[test]
    fn bad_source_bytes_fail_digest_verification() {
        #[derive(Clone)]
        struct BadSource;
        impl WeightPageSource for BadSource {
            fn read_page(&self, _page_id: WeightPageId) -> Result<Vec<u8>> {
                Ok(vec![9u8; 1024])
            }
        }

        let expected = vec![8u8; 1024];
        let descriptor = WeightPageDescriptor {
            page_id: WeightPageId::for_bytes(&expected),
            plaintext_len: expected.len() as u64,
        };
        let vm = WeightVm::new(
            BadSource,
            WeightVmBudget {
                resident_bytes: 4096,
            },
        )
        .unwrap();

        assert!(matches!(
            vm.pin_page(descriptor),
            Err(ModelStoreError::WeightPageDigestMismatch)
        ));
    }

    #[test]
    fn lru_evicts_cold_pages_under_budget() {
        let a = page(1, 1024);
        let b = page(2, 1024);
        let c = page(3, 1024);
        let vm = vm(2048, &[a.clone(), b.clone(), c.clone()]);

        vm.prefetch_page(a.0).unwrap();
        vm.prefetch_page(b.0).unwrap();
        vm.prefetch_page(c.0).unwrap();

        let snapshot = vm.snapshot();
        assert_eq!(snapshot.resident_bytes, 2048);
        assert_eq!(snapshot.resident_pages, 2);
        assert_eq!(snapshot.evictions, 1);
    }

    #[test]
    fn active_lease_pins_page_against_eviction() {
        let a = page(1, 1024);
        let b = page(2, 1024);
        let c = page(3, 1024);
        let vm = vm(2048, &[a.clone(), b.clone(), c.clone()]);

        let pinned = vm.pin_page(a.0).unwrap();
        vm.prefetch_page(b.0).unwrap();
        vm.prefetch_page(c.0).unwrap();

        assert_eq!(pinned.bytes(), a.1.as_slice());
        let snapshot = vm.snapshot();
        assert_eq!(snapshot.resident_bytes, 2048);
        assert_eq!(snapshot.pinned_pages, 1);
        assert!(snapshot.evictions >= 1);
    }

    #[test]
    fn tightening_budget_never_invalidates_active_lease() {
        let a = page(4, 1024);
        let b = page(5, 1024);
        let vm = vm(2048, &[a.clone(), b.clone()]);

        let pinned_a = vm.pin_page(a.0).unwrap();
        let pinned_b = vm.pin_page(b.0).unwrap();

        let update = vm
            .update_budget(WeightVmBudget {
                resident_bytes: 1024,
            })
            .unwrap();

        assert!(update.over_budget_due_to_pins);
        assert_eq!(pinned_a.bytes(), a.1.as_slice());
        assert_eq!(pinned_b.bytes(), b.1.as_slice());

        drop(pinned_b);
        vm.update_budget(WeightVmBudget {
            resident_bytes: 1024,
        })
        .unwrap();

        let snapshot = vm.snapshot();
        assert_eq!(snapshot.resident_bytes, 1024);
        assert_eq!(snapshot.pinned_pages, 1);
    }

    #[test]
    fn same_digest_is_shared_as_one_resident_page() {
        let shared = page(8, 1024);
        let vm = vm(4096, &[shared.clone()]);

        let a = vm.pin_page(shared.0).unwrap();
        let b = vm.pin_page(shared.0).unwrap();

        assert_eq!(a.page_id(), b.page_id());
        let snapshot = vm.snapshot();
        assert_eq!(snapshot.resident_pages, 1);
        assert_eq!(snapshot.faults, 1);
        assert_eq!(snapshot.hits, 1);
    }
}
