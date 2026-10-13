#![forbid(unsafe_code)]

use jend_vault::{
    DeviceProfile, DeviceTier, PlatformClass, PowerMode, RuntimeGovernor, RuntimeLane,
    RuntimeQueueLimits, SubmitFailure,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mobile = DeviceProfile {
        logical_parallelism: 8,
        memory_bytes: Some(12 * 1024 * 1024 * 1024),
        tier: DeviceTier::High,
        platform: PlatformClass::Mobile,
    };
    let base = RuntimeQueueLimits::default();
    let mut governor = RuntimeGovernor::<&'static str>::new(mobile, base);

    governor
        .scheduler()
        .try_submit(RuntimeLane::AiForeground, "accepted-before-low-power")
        .map_err(|_| "failed to queue initial AI task")?;

    let update = governor.update_power_mode(PowerMode::LowPower);
    if update.execution.ai_workers != 1
        || update.execution.background_workers != 0
        || update.queues.current.ai_foreground != 1
        || update.queues.current.background != 0
    {
        return Err("low-power policy was not applied to the live runtime".into());
    }
    if update.queues.current.ui_interactive != base.ui_interactive
        || update.queues.current.vault_critical != base.vault_critical
        || update.queues.current.sync_interactive != base.sync_interactive
    {
        return Err("adaptive policy reduced an interactive queue".into());
    }

    match governor
        .scheduler()
        .try_submit(RuntimeLane::AiForeground, "new-ai")
    {
        Err(SubmitFailure::QueueFull { .. }) => {}
        _ => return Err("live AI queue did not apply low-power backpressure".into()),
    }

    match governor
        .scheduler()
        .try_submit(RuntimeLane::Background, "background")
    {
        Err(SubmitFailure::QueueFull { .. }) => {}
        _ => return Err("live background queue remained enabled in low-power mode".into()),
    }

    let accepted = governor
        .scheduler()
        .try_next()
        .ok_or("accepted pre-policy task was dropped")?;
    if accepted.task != "accepted-before-low-power" {
        return Err("runtime reordered or lost accepted work".into());
    }

    println!("Jend dynamic runtime policy application: PASS");
    Ok(())
}
