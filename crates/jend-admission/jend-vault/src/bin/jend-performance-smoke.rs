#![forbid(unsafe_code)]

use jend_vault::{
    AdaptivePerformancePolicy, DeviceProfile, DeviceTier, PlatformClass, PowerMode,
    RuntimeController, RuntimePressure, ThermalPressure,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = DeviceProfile::detect();

    if profile.logical_parallelism == 0 {
        return Err("device profiler returned zero logical parallelism".into());
    }

    let normal =
        AdaptivePerformancePolicy::for_profile(profile, RuntimePressure::Normal);
    let saturated =
        AdaptivePerformancePolicy::for_profile(profile, RuntimePressure::Saturated);

    if saturated.ai_workers > normal.ai_workers {
        return Err("saturated policy increased AI concurrency".into());
    }
    if saturated.background_workers > normal.background_workers {
        return Err("saturated policy increased background concurrency".into());
    }
    if saturated.ai_queue_limit > normal.ai_queue_limit {
        return Err("saturated policy increased AI queue capacity".into());
    }

    // Validate mobile policy deterministically even when this smoke runs on macOS.
    let simulated_mobile = DeviceProfile {
        logical_parallelism: 8,
        memory_bytes: Some(12 * 1024 * 1024 * 1024),
        tier: DeviceTier::High,
        platform: PlatformClass::Mobile,
    };
    let mut mobile_controller = RuntimeController::new(simulated_mobile);
    let mobile_normal = mobile_controller.policy();
    if mobile_normal.target_ui_hz > 60
        || mobile_normal.ai_workers > 2
        || mobile_normal.background_workers > 1
        || mobile_normal.allow_background_prefetch
    {
        return Err("mobile baseline exceeded conservative sustained-performance limits".into());
    }

    let low_power = mobile_controller.update_power_mode(PowerMode::LowPower).current;
    if low_power.ai_workers != 1
        || low_power.background_workers != 0
        || low_power.ai_queue_limit != 1
    {
        return Err("mobile low-power policy failed to reduce compute load".into());
    }

    let thermal = mobile_controller
        .update_thermal_pressure(ThermalPressure::Critical)
        .current;
    if thermal.ai_compute_share_percent > 15 || thermal.background_workers != 0 {
        return Err("mobile critical-thermal policy failed to protect the device".into());
    }

    println!(
        "Jend device profile: platform={:?}, tier={:?}, logical_parallelism={}, memory_gib={}",
        profile.platform,
        profile.tier,
        profile.logical_parallelism,
        profile
            .memory_gib_floor()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
    );
    println!(
        "Jend normal policy: ui_hz={}, ai_workers={}, bg_workers={}, ai_queue={}",
        normal.target_ui_hz,
        normal.ai_workers,
        normal.background_workers,
        normal.ai_queue_limit,
    );
    println!("Jend mobile adaptive policy: PASS");
    println!("Jend adaptive performance smoke: PASS");
    Ok(())
}
