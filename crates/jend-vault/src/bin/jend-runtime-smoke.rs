#![forbid(unsafe_code)]

use jend_vault::{
    RuntimeLane, RuntimeQueueLimits, RuntimeScheduler, SubmitFailure,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scheduler = RuntimeScheduler::new(RuntimeQueueLimits {
        ui_interactive: 4,
        vault_critical: 4,
        sync_interactive: 4,
        ai_foreground: 2,
        background: 2,
    });

    // Simulate a model already having queued work.
    scheduler
        .try_submit(RuntimeLane::AiForeground, "ai-1")
        .map_err(|_| "unable to queue AI smoke task")?;
    scheduler
        .try_submit(RuntimeLane::AiForeground, "ai-2")
        .map_err(|_| "unable to queue AI smoke task")?;

    // AI queue is bounded: a third task must be rejected immediately.
    match scheduler.try_submit(RuntimeLane::AiForeground, "ai-overflow") {
        Err(SubmitFailure::QueueFull { lane, task }) => {
            if lane != RuntimeLane::AiForeground || task != "ai-overflow" {
                return Err("runtime returned incorrect AI backpressure metadata".into());
            }
        }
        _ => return Err("runtime failed to bound the AI queue".into()),
    }

    scheduler
        .try_submit(RuntimeLane::VaultCritical, "vault")
        .map_err(|_| "unable to queue Vault smoke task")?;
    scheduler
        .try_submit(RuntimeLane::UiInteractive, "ui")
        .map_err(|_| "unable to queue UI smoke task")?;

    let first = scheduler.try_next().ok_or("runtime produced no UI task")?;
    let second = scheduler.try_next().ok_or("runtime produced no Vault task")?;

    if first.lane != RuntimeLane::UiInteractive || first.task != "ui" {
        return Err("AI backlog overtook UI work".into());
    }
    if second.lane != RuntimeLane::VaultCritical || second.task != "vault" {
        return Err("AI backlog overtook Vault work".into());
    }

    println!("Jend runtime priority/backpressure smoke: PASS");
    Ok(())
}
