//! Model Store delivery/access contracts.
//!
//! A Store listing describes *how* a model can be used, not merely a file to
//! download. This lets Jend present one catalog while preserving three very
//! different execution realities:
//!
//! 1. LocalPackage: downloadable/licensed weights installed on the device.
//! 2. ProviderRemote: no local weights; Jend installs a provider adapter.
//! 3. VirtualPaged: very large downloadable/licensed weights addressed through
//!    a signed chunk/page index and a bounded local working set.
//!
//! Provider credentials are intentionally not stored in these public catalog
//! structures.

use crate::{ModelId, ModelStoreError, Result};

const MAX_LABEL: usize = 96;
const MIN_PAGE_BYTES: u32 = 64 * 1024;
const MAX_PAGE_BYTES: u32 = 512 * 1024 * 1024;
const MAX_LOGICAL_WEIGHT_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024; // 64 TiB

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeightRights {
    /// Publisher permits weight download under the attached release/license.
    Downloadable,
    /// Jend has a license permitting local distribution to entitled devices.
    LicensedToJend,
    /// No local weight distribution right exists; provider execution only.
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCredentialMode {
    /// User supplies a provider API credential directly to the local secure
    /// credential boundary; it is not embedded in Store metadata.
    UserManagedKey,
    /// Provider account/OAuth style authorization.
    ProviderAccount,
    /// Jend may meter/pass through usage only under an explicit commercial
    /// agreement. This mode does not imply Jend owns or hosts model weights.
    CommercialPassThrough,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPackageSpec {
    pub format: String,
    pub approximate_download_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRemoteSpec {
    pub provider: String,
    pub remote_model: String,
    pub credential_mode: ProviderCredentialMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualPagedSpec {
    /// Total logical weight bytes represented by the signed virtual model.
    pub logical_weight_bytes: u64,
    /// Approximate weight bytes touched for one token/step on the intended
    /// sparse execution path. For dense models this may equal logical bytes.
    pub active_weight_bytes: u64,
    /// Smallest local cache the publisher/runtime considers useful.
    pub minimum_cache_bytes: u64,
    /// Signed page/chunk granularity. Pages are independently addressable.
    pub page_bytes: u32,
    /// True when the architecture exposes independently pageable experts.
    pub expert_paging: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelDelivery {
    LocalPackage(LocalPackageSpec),
    ProviderRemote(ProviderRemoteSpec),
    VirtualPaged(VirtualPagedSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogModel {
    pub model_id: ModelId,
    pub display_name: String,
    pub weight_rights: WeightRights,
    pub delivery: ModelDelivery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallPlan {
    DownloadLocalPackage {
        approximate_download_bytes: u64,
    },
    ConnectProvider {
        provider: String,
        remote_model: String,
        credential_mode: ProviderCredentialMode,
    },
    InstallVirtualIndex {
        logical_weight_bytes: u64,
        minimum_cache_bytes: u64,
        page_bytes: u32,
        expert_paging: bool,
    },
}

impl CatalogModel {
    pub fn validate(&self) -> Result<()> {
        validate_label(&self.display_name)?;

        match &self.delivery {
            ModelDelivery::LocalPackage(spec) => {
                validate_label(&spec.format)?;
                if self.weight_rights == WeightRights::Unavailable
                    || spec.approximate_download_bytes == 0
                    || spec.approximate_download_bytes > MAX_LOGICAL_WEIGHT_BYTES
                {
                    return Err(ModelStoreError::InvalidCatalogModel);
                }
            }
            ModelDelivery::ProviderRemote(spec) => {
                validate_label(&spec.provider)?;
                validate_label(&spec.remote_model)?;
                // Provider-backed listings may represent either closed models
                // or an open model intentionally consumed through a provider.
                // No local weight file is implied by this delivery kind.
            }
            ModelDelivery::VirtualPaged(spec) => {
                if self.weight_rights == WeightRights::Unavailable
                    || spec.logical_weight_bytes == 0
                    || spec.logical_weight_bytes > MAX_LOGICAL_WEIGHT_BYTES
                    || spec.active_weight_bytes == 0
                    || spec.active_weight_bytes > spec.logical_weight_bytes
                    || spec.minimum_cache_bytes == 0
                    || spec.minimum_cache_bytes > spec.logical_weight_bytes
                    || spec.page_bytes < MIN_PAGE_BYTES
                    || spec.page_bytes > MAX_PAGE_BYTES
                    || !spec.page_bytes.is_power_of_two()
                {
                    return Err(ModelStoreError::InvalidCatalogModel);
                }
            }
        }
        Ok(())
    }

    pub fn install_plan(&self) -> Result<InstallPlan> {
        self.validate()?;
        Ok(match &self.delivery {
            ModelDelivery::LocalPackage(spec) => InstallPlan::DownloadLocalPackage {
                approximate_download_bytes: spec.approximate_download_bytes,
            },
            ModelDelivery::ProviderRemote(spec) => InstallPlan::ConnectProvider {
                provider: spec.provider.clone(),
                remote_model: spec.remote_model.clone(),
                credential_mode: spec.credential_mode,
            },
            ModelDelivery::VirtualPaged(spec) => InstallPlan::InstallVirtualIndex {
                logical_weight_bytes: spec.logical_weight_bytes,
                minimum_cache_bytes: spec.minimum_cache_bytes,
                page_bytes: spec.page_bytes,
                expert_paging: spec.expert_paging,
            },
        })
    }

    pub fn requires_local_weights(&self) -> bool {
        matches!(
            self.delivery,
            ModelDelivery::LocalPackage(_) | ModelDelivery::VirtualPaged(_)
        )
    }
}

/// Approximate raw bit-packed weight bytes. This helper is deliberately honest:
/// quantization can reduce bytes/weight, but it cannot make an arbitrary dense
/// trillion-parameter model "free". Distillation/pruning would create a changed
/// model and are separate transformations.
pub fn approximate_quantized_weight_bytes(
    parameters: u64,
    bits_per_weight: u8,
) -> Result<u64> {
    if parameters == 0 || !(1..=16).contains(&bits_per_weight) {
        return Err(ModelStoreError::InvalidCatalogModel);
    }
    let bits = parameters
        .checked_mul(bits_per_weight as u64)
        .ok_or(ModelStoreError::Overflow)?;
    bits.checked_add(7)
        .ok_or(ModelStoreError::Overflow)
        .map(|value| value / 8)
}

fn validate_label(text: &str) -> Result<()> {
    if text.is_empty()
        || text.len() > MAX_LABEL
        || !text.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b' ' | b'_' | b'-' | b'.' | b'/' | b'+' | b':')
        })
    {
        return Err(ModelStoreError::InvalidCatalogModel);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> ModelId {
        ModelId([7u8; 16])
    }

    #[test]
    fn closed_provider_model_installs_adapter_not_weights() {
        let model = CatalogModel {
            model_id: id(),
            display_name: "Closed Provider Model".into(),
            weight_rights: WeightRights::Unavailable,
            delivery: ModelDelivery::ProviderRemote(ProviderRemoteSpec {
                provider: "provider".into(),
                remote_model: "frontier-model".into(),
                credential_mode: ProviderCredentialMode::ProviderAccount,
            }),
        };

        assert!(!model.requires_local_weights());
        assert!(matches!(
            model.install_plan().unwrap(),
            InstallPlan::ConnectProvider { .. }
        ));
    }

    #[test]
    fn unavailable_weights_cannot_be_packaged_locally() {
        let model = CatalogModel {
            model_id: id(),
            display_name: "No Weights".into(),
            weight_rights: WeightRights::Unavailable,
            delivery: ModelDelivery::LocalPackage(LocalPackageSpec {
                format: "gguf".into(),
                approximate_download_bytes: 1024,
            }),
        };
        assert!(model.validate().is_err());
    }

    #[test]
    fn trillion_parameter_sparse_model_can_be_virtual_paged() {
        let logical = approximate_quantized_weight_bytes(1_000_000_000_000, 4).unwrap();
        let active = approximate_quantized_weight_bytes(32_000_000_000, 4).unwrap();
        let model = CatalogModel {
            model_id: id(),
            display_name: "1T MoE Example".into(),
            weight_rights: WeightRights::Downloadable,
            delivery: ModelDelivery::VirtualPaged(VirtualPagedSpec {
                logical_weight_bytes: logical,
                active_weight_bytes: active,
                minimum_cache_bytes: 8 * 1024 * 1024 * 1024,
                page_bytes: 16 * 1024 * 1024,
                expert_paging: true,
            }),
        };
        assert!(model.validate().is_ok());
        assert!(model.requires_local_weights());
        assert!(active < logical);
    }

    #[test]
    fn four_bit_trillion_parameter_math_is_still_hundreds_of_gb() {
        let bytes = approximate_quantized_weight_bytes(1_000_000_000_000, 4).unwrap();
        assert_eq!(bytes, 500_000_000_000);
    }

    #[test]
    fn virtual_page_size_must_be_bounded_power_of_two() {
        let model = CatalogModel {
            model_id: id(),
            display_name: "Bad Virtual".into(),
            weight_rights: WeightRights::Downloadable,
            delivery: ModelDelivery::VirtualPaged(VirtualPagedSpec {
                logical_weight_bytes: 1_000_000,
                active_weight_bytes: 500_000,
                minimum_cache_bytes: 100_000,
                page_bytes: 100_000,
                expert_paging: true,
            }),
        };
        assert!(model.validate().is_err());
    }
}
