//! Public Jend Store chat execution routing.
//!
//! Product invariant: end users select models from Jend Store, and selected
//! models execute through Jend's local/virtual model path. Provider/API-backed
//! inference is not an end-user execution mode.

use crate::{CatalogModel, ModelDelivery, ModelId, ModelStoreError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalExecutionKind {
    ResidentPackage,
    VirtualPaged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatExecutionRoute {
    pub model_id: ModelId,
    pub kind: LocalExecutionKind,
}

impl ChatExecutionRoute {
    pub const fn uses_local_ai_executor(&self) -> bool {
        true
    }
}

impl CatalogModel {
    /// Resolve the public Store execution route.
    ///
    /// ProviderRemote remains representable only for administrative/history
    /// compatibility. It cannot be activated for end-user chat.
    pub fn chat_execution_route(&self) -> Result<ChatExecutionRoute> {
        self.validate()?;

        match &self.delivery {
            ModelDelivery::LocalPackage(_) => Ok(ChatExecutionRoute {
                model_id: self.model_id,
                kind: LocalExecutionKind::ResidentPackage,
            }),
            ModelDelivery::VirtualPaged(_) => Ok(ChatExecutionRoute {
                model_id: self.model_id,
                kind: LocalExecutionKind::VirtualPaged,
            }),
            ModelDelivery::ProviderRemote(_) => {
                Err(ModelStoreError::ExternalProviderExecutionDisabled)
            }
        }
    }

    pub fn is_public_store_executable(&self) -> bool {
        self.chat_execution_route().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LocalPackageSpec, ProviderCredentialMode, ProviderRemoteSpec, VirtualPagedSpec,
        WeightRights,
    };

    #[test]
    fn provider_model_fails_closed_for_public_store_chat() {
        let model = CatalogModel {
            model_id: ModelId([21u8; 16]),
            display_name: "Provider Reference".into(),
            weight_rights: WeightRights::Unavailable,
            delivery: ModelDelivery::ProviderRemote(ProviderRemoteSpec {
                provider: "provider-a".into(),
                remote_model: "frontier-chat".into(),
                credential_mode: ProviderCredentialMode::ProviderAccount,
            }),
        };

        assert!(matches!(
            model.chat_execution_route(),
            Err(ModelStoreError::ExternalProviderExecutionDisabled)
        ));
        assert!(!model.is_public_store_executable());
    }

    #[test]
    fn local_package_routes_to_isolated_ai_executor() {
        let model = CatalogModel {
            model_id: ModelId([22u8; 16]),
            display_name: "Local Model".into(),
            weight_rights: WeightRights::Downloadable,
            delivery: ModelDelivery::LocalPackage(LocalPackageSpec {
                format: "gguf".into(),
                approximate_download_bytes: 1024,
            }),
        };
        let route = model.chat_execution_route().unwrap();
        assert_eq!(route.kind, LocalExecutionKind::ResidentPackage);
        assert!(route.uses_local_ai_executor());
    }

    #[test]
    fn virtual_model_routes_to_weightvm_ai_boundary() {
        let model = CatalogModel {
            model_id: ModelId([23u8; 16]),
            display_name: "Virtual Model".into(),
            weight_rights: WeightRights::Downloadable,
            delivery: ModelDelivery::VirtualPaged(VirtualPagedSpec {
                logical_weight_bytes: 1_000_000,
                active_weight_bytes: 500_000,
                minimum_cache_bytes: 128 * 1024,
                page_bytes: 64 * 1024,
                expert_paging: true,
            }),
        };
        let route = model.chat_execution_route().unwrap();
        assert_eq!(route.kind, LocalExecutionKind::VirtualPaged);
    }
}
