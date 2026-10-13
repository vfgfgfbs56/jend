#![forbid(unsafe_code)]

use jend_model_store::{
    CatalogModel, LocalExecutionKind, LocalPackageSpec, ModelDelivery, ModelId, ModelStoreError,
    ProviderCredentialMode, ProviderRemoteSpec, VirtualPagedSpec, WeightRights,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = CatalogModel {
        model_id: ModelId([31u8; 16]),
        display_name: "Provider Reference".into(),
        weight_rights: WeightRights::Unavailable,
        delivery: ModelDelivery::ProviderRemote(ProviderRemoteSpec {
            provider: "provider-a".into(),
            remote_model: "frontier-chat".into(),
            credential_mode: ProviderCredentialMode::ProviderAccount,
        }),
    };

    if !matches!(
        provider.chat_execution_route(),
        Err(ModelStoreError::ExternalProviderExecutionDisabled)
    ) {
        return Err("external provider model remained executable in public Store".into());
    }

    let local = CatalogModel {
        model_id: ModelId([32u8; 16]),
        display_name: "Local Chat".into(),
        weight_rights: WeightRights::Downloadable,
        delivery: ModelDelivery::LocalPackage(LocalPackageSpec {
            format: "gguf".into(),
            approximate_download_bytes: 4096,
        }),
    };
    if local.chat_execution_route()?.kind != LocalExecutionKind::ResidentPackage {
        return Err("local Store model did not route to resident local executor".into());
    }

    let virtual_model = CatalogModel {
        model_id: ModelId([33u8; 16]),
        display_name: "Virtual Chat".into(),
        weight_rights: WeightRights::Downloadable,
        delivery: ModelDelivery::VirtualPaged(VirtualPagedSpec {
            logical_weight_bytes: 1_000_000_000,
            active_weight_bytes: 100_000_000,
            minimum_cache_bytes: 64 * 1024 * 1024,
            page_bytes: 16 * 1024 * 1024,
            expert_paging: true,
        }),
    };
    if virtual_model.chat_execution_route()?.kind != LocalExecutionKind::VirtualPaged {
        return Err("virtual Store model did not route to local WeightVM boundary".into());
    }

    println!("Jend Store-only local/virtual execution policy: PASS");
    println!("Jend external provider execution disabled: PASS");
    Ok(())
}
