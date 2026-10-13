#![forbid(unsafe_code)]

use jend_model_store::{
    approximate_quantized_weight_bytes, CatalogModel, InstallPlan, ModelDelivery, ModelId,
    ProviderCredentialMode, ProviderRemoteSpec, VirtualPagedSpec, WeightRights,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = CatalogModel {
        model_id: ModelId([1u8; 16]),
        display_name: "Provider model".into(),
        weight_rights: WeightRights::Unavailable,
        delivery: ModelDelivery::ProviderRemote(ProviderRemoteSpec {
            provider: "example-provider".into(),
            remote_model: "frontier-model".into(),
            credential_mode: ProviderCredentialMode::ProviderAccount,
        }),
    };
    match provider.install_plan()? {
        InstallPlan::ConnectProvider { .. } => {}
        _ => return Err("closed/provider model incorrectly required local weights".into()),
    }

    let logical = approximate_quantized_weight_bytes(1_000_000_000_000, 4)?;
    let active = approximate_quantized_weight_bytes(32_000_000_000, 4)?;
    if logical != 500_000_000_000 || active >= logical {
        return Err("trillion-parameter storage math regression".into());
    }

    let virtual_model = CatalogModel {
        model_id: ModelId([2u8; 16]),
        display_name: "Virtual 1T MoE".into(),
        weight_rights: WeightRights::Downloadable,
        delivery: ModelDelivery::VirtualPaged(VirtualPagedSpec {
            logical_weight_bytes: logical,
            active_weight_bytes: active,
            minimum_cache_bytes: 8 * 1024 * 1024 * 1024,
            page_bytes: 16 * 1024 * 1024,
            expert_paging: true,
        }),
    };
    match virtual_model.install_plan()? {
        InstallPlan::InstallVirtualIndex {
            logical_weight_bytes,
            expert_paging: true,
            ..
        } if logical_weight_bytes == logical => {}
        _ => return Err("virtual model did not produce a virtual-index install plan".into()),
    }

    println!("Jend model access/provider/virtual-paging contract: PASS");
    Ok(())
}
