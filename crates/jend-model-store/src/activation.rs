//! Zero-install model selection and bounded local cache planning.
//!
//! Selecting a Store model is not the same operation as downloading all of its
//! weights. A selection can become chat-visible immediately while Jend keeps a
//! small bootstrap/cache footprint and resolves execution on demand.

use crate::{
    CatalogModel, ModelDelivery, ModelId, ModelSlot, ModelStoreError, Result,
};

const MAX_BOOTSTRAP_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB
const MAX_CACHE_BUDGET_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024; // 4 TiB

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelCacheBudget {
    /// Persistent weight-page cache. Zero is valid for provider-backed models.
    pub disk_bytes: u64,
    /// Runtime RAM cache hint. The runtime may use less under pressure.
    pub memory_bytes: u64,
}

impl ModelCacheBudget {
    pub fn validate(self) -> Result<Self> {
        if self.disk_bytes > MAX_CACHE_BUDGET_BYTES
            || self.memory_bytes > MAX_CACHE_BUDGET_BYTES
        {
            return Err(ModelStoreError::InvalidActivationPlan);
        }
        Ok(self)
    }

    pub const fn tiny() -> Self {
        Self {
            disk_bytes: 64 * 1024 * 1024,
            memory_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationPreferences {
    pub cache: ModelCacheBudget,
    /// Whether this device may fetch signed model pages after selection.
    pub allow_network_page_faults: bool,
    /// If true, Jend may evict cold pages from models that are no longer in a
    /// selected slot.
    pub evict_unselected_cache: bool,
}

impl ActivationPreferences {
    pub fn validate(self) -> Result<Self> {
        self.cache.validate()?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionReadiness {
    /// No weight pages are required locally.
    ProviderReady,
    /// Enough cache exists for the model's declared active working set.
    LocalWorkingSetPossible,
    /// Selection is valid, but page misses require network access and may be
    /// slower than a resident working set.
    StreamedOnDemand,
    /// The selected model cannot execute with current offline/cache conditions.
    NeedsMoreLocalData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationPlan {
    /// Closed/provider model: tiny local adapter state, no model weights.
    ProviderAdapter {
        model_id: ModelId,
    },

    /// Traditional local package. This remains supported, but is not the
    /// default UX for very large models.
    FullLocalPackage {
        model_id: ModelId,
        download_bytes: u64,
    },

    /// Virtual model: selection installs only bootstrap metadata. Signed weight
    /// pages are fetched lazily into a bounded cache.
    VirtualOnDemand {
        model_id: ModelId,
        bootstrap_bytes: u64,
        logical_weight_bytes: u64,
        active_weight_bytes: u64,
        page_bytes: u32,
        disk_cache_budget_bytes: u64,
        memory_cache_budget_bytes: u64,
        readiness: ExecutionReadiness,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedModel {
    pub slot: ModelSlot,
    pub model_id: ModelId,
    pub selection_epoch: u64,
}

impl SelectedModel {
    pub fn replace(
        self,
        model_id: ModelId,
    ) -> Result<Self> {
        let selection_epoch = self
            .selection_epoch
            .checked_add(1)
            .ok_or(ModelStoreError::Overflow)?;
        Ok(Self {
            slot: self.slot,
            model_id,
            selection_epoch,
        })
    }
}

impl CatalogModel {
    /// Build a device activation plan without conflating Store selection with a
    /// full model download.
    pub fn activation_plan(
        &self,
        preferences: ActivationPreferences,
    ) -> Result<ActivationPlan> {
        self.validate()?;
        let preferences = preferences.validate()?;

        Ok(match &self.delivery {
            ModelDelivery::ProviderRemote(_) => {
                return Err(ModelStoreError::ExternalProviderExecutionDisabled);
            }

            ModelDelivery::LocalPackage(spec) => ActivationPlan::FullLocalPackage {
                model_id: self.model_id,
                download_bytes: spec.approximate_download_bytes,
            },

            ModelDelivery::VirtualPaged(spec) => {
                let bootstrap_bytes = virtual_bootstrap_bytes(spec.page_bytes);
                let cache_for_working_set = preferences
                    .cache
                    .disk_bytes
                    .max(preferences.cache.memory_bytes);

                let readiness = if cache_for_working_set >= spec.active_weight_bytes {
                    ExecutionReadiness::LocalWorkingSetPossible
                } else if preferences.allow_network_page_faults {
                    ExecutionReadiness::StreamedOnDemand
                } else {
                    ExecutionReadiness::NeedsMoreLocalData
                };

                ActivationPlan::VirtualOnDemand {
                    model_id: self.model_id,
                    bootstrap_bytes,
                    logical_weight_bytes: spec.logical_weight_bytes,
                    active_weight_bytes: spec.active_weight_bytes,
                    page_bytes: spec.page_bytes,
                    disk_cache_budget_bytes: preferences.cache.disk_bytes,
                    memory_cache_budget_bytes: preferences.cache.memory_bytes,
                    readiness,
                }
            }
        })
    }
}

/// Bootstrap is intentionally small: signed index/router/tokenizer metadata plus
/// a few page-sized buffers. This is an installation-footprint target, not a
/// claim that the model's inference working set is equally small.
fn virtual_bootstrap_bytes(page_bytes: u32) -> u64 {
    let pages = u64::from(page_bytes).saturating_mul(2);
    pages.min(MAX_BOOTSTRAP_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProviderCredentialMode, ProviderRemoteSpec, VirtualPagedSpec, WeightRights,
    };

    fn virtual_model() -> CatalogModel {
        CatalogModel {
            model_id: ModelId([4u8; 16]),
            display_name: "Virtual Model".into(),
            weight_rights: WeightRights::Downloadable,
            delivery: ModelDelivery::VirtualPaged(VirtualPagedSpec {
                logical_weight_bytes: 500_000_000_000,
                active_weight_bytes: 16_000_000_000,
                minimum_cache_bytes: 64 * 1024 * 1024,
                page_bytes: 16 * 1024 * 1024,
                expert_paging: true,
            }),
        }
    }

    #[test]
    fn selecting_virtual_model_can_have_megabyte_scale_bootstrap() {
        let plan = virtual_model()
            .activation_plan(ActivationPreferences {
                cache: ModelCacheBudget::tiny(),
                allow_network_page_faults: true,
                evict_unselected_cache: true,
            })
            .unwrap();

        match plan {
            ActivationPlan::VirtualOnDemand {
                bootstrap_bytes,
                disk_cache_budget_bytes,
                readiness,
                ..
            } => {
                assert_eq!(bootstrap_bytes, 32 * 1024 * 1024);
                assert_eq!(disk_cache_budget_bytes, 64 * 1024 * 1024);
                assert_eq!(readiness, ExecutionReadiness::StreamedOnDemand);
            }
            _ => panic!("expected virtual activation"),
        }
    }

    #[test]
    fn tiny_cache_is_not_misrepresented_as_resident_16gb_working_set() {
        let plan = virtual_model()
            .activation_plan(ActivationPreferences {
                cache: ModelCacheBudget::tiny(),
                allow_network_page_faults: false,
                evict_unselected_cache: true,
            })
            .unwrap();

        assert!(matches!(
            plan,
            ActivationPlan::VirtualOnDemand {
                readiness: ExecutionReadiness::NeedsMoreLocalData,
                ..
            }
        ));
    }

    #[test]
    fn enough_cache_can_hold_declared_active_working_set() {
        let plan = virtual_model()
            .activation_plan(ActivationPreferences {
                cache: ModelCacheBudget {
                    disk_bytes: 16_000_000_000,
                    memory_bytes: 2 * 1024 * 1024 * 1024,
                },
                allow_network_page_faults: false,
                evict_unselected_cache: true,
            })
            .unwrap();

        assert!(matches!(
            plan,
            ActivationPlan::VirtualOnDemand {
                readiness: ExecutionReadiness::LocalWorkingSetPossible,
                ..
            }
        ));
    }

    #[test]
    fn provider_selection_is_disabled_for_public_store() {
        let model = CatalogModel {
            model_id: ModelId([5u8; 16]),
            display_name: "Provider Reference".into(),
            weight_rights: WeightRights::Unavailable,
            delivery: ModelDelivery::ProviderRemote(ProviderRemoteSpec {
                provider: "provider".into(),
                remote_model: "model".into(),
                credential_mode: ProviderCredentialMode::ProviderAccount,
            }),
        };
        let result = model.activation_plan(ActivationPreferences {
            cache: ModelCacheBudget {
                disk_bytes: 0,
                memory_bytes: 0,
            },
            allow_network_page_faults: true,
            evict_unselected_cache: true,
        });
        assert!(matches!(
            result,
            Err(ModelStoreError::ExternalProviderExecutionDisabled)
        ));
    }

    #[test]
    fn replacing_a_slot_changes_selection_without_installing_weights() {
        let selection = SelectedModel {
            slot: ModelSlot::ONE,
            model_id: ModelId([1u8; 16]),
            selection_epoch: 7,
        };
        let replaced = selection.replace(ModelId([2u8; 16])).unwrap();
        assert_eq!(replaced.slot, ModelSlot::ONE);
        assert_eq!(replaced.model_id, ModelId([2u8; 16]));
        assert_eq!(replaced.selection_epoch, 8);
    }
}
