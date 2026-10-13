#![forbid(unsafe_code)]

use jend_model_store::{
    ActivationPlan, ActivationPreferences, CatalogModel, ExecutionReadiness, ModelCacheBudget,
    ModelDelivery, ModelId, ModelSlot, SelectedModel, VirtualPagedSpec, WeightRights,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let model = CatalogModel {
        model_id: ModelId([9u8; 16]),
        display_name: "Virtual 1T".into(),
        weight_rights: WeightRights::Downloadable,
        delivery: ModelDelivery::VirtualPaged(VirtualPagedSpec {
            logical_weight_bytes: 500_000_000_000,
            active_weight_bytes: 16_000_000_000,
            minimum_cache_bytes: 64 * 1024 * 1024,
            page_bytes: 16 * 1024 * 1024,
            expert_paging: true,
        }),
    };

    let plan = model.activation_plan(ActivationPreferences {
        cache: ModelCacheBudget::tiny(),
        allow_network_page_faults: true,
        evict_unselected_cache: true,
    })?;

    match plan {
        ActivationPlan::VirtualOnDemand {
            bootstrap_bytes,
            disk_cache_budget_bytes,
            active_weight_bytes,
            readiness,
            ..
        } => {
            if bootstrap_bytes != 32 * 1024 * 1024 {
                return Err("virtual model bootstrap is not megabyte-scale".into());
            }
            if disk_cache_budget_bytes != 64 * 1024 * 1024 {
                return Err("tiny cache budget changed unexpectedly".into());
            }
            if active_weight_bytes <= disk_cache_budget_bytes {
                return Err("smoke no longer proves cache/working-set distinction".into());
            }
            if readiness != ExecutionReadiness::StreamedOnDemand {
                return Err("tiny online cache did not select on-demand paging".into());
            }
        }
        _ => return Err("virtual model unexpectedly required eager installation".into()),
    }

    let selected = SelectedModel {
        slot: ModelSlot::ZERO,
        model_id: ModelId([1u8; 16]),
        selection_epoch: 1,
    };
    let changed = selected.replace(ModelId([2u8; 16]))?;
    if changed.selection_epoch != 2 || changed.model_id != ModelId([2u8; 16]) {
        return Err("model slot replacement contract failed".into());
    }

    println!("Jend zero-install model selection/cache contract: PASS");
    Ok(())
}
