//! Live adaptive runtime controller and policy governor.
//!
//! Platform UI bridges may feed thermal and low-power state changes here.
//! The controller performs no network access and no expensive probing on
//! update. `RuntimeGovernor` additionally applies queue admission limits to a
//! live scheduler.

use crate::{
    AdaptivePerformancePolicy, DeviceProfile, PowerMode, RuntimePressure, RuntimeQueueLimits,
    RuntimeQueueUpdate, RuntimeScheduler, RuntimeSignals, ThermalPressure,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyUpdate {
    pub previous: AdaptivePerformancePolicy,
    pub current: AdaptivePerformancePolicy,
    pub changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeExecutionLimits {
    pub ai_workers: usize,
    pub background_workers: usize,
    pub ai_compute_share_percent: u8,
    pub target_ui_hz: u16,
}

impl From<AdaptivePerformancePolicy> for RuntimeExecutionLimits {
    fn from(policy: AdaptivePerformancePolicy) -> Self {
        Self {
            ai_workers: policy.ai_workers,
            background_workers: policy.background_workers,
            ai_compute_share_percent: policy.ai_compute_share_percent,
            target_ui_hz: policy.target_ui_hz,
        }
    }
}

pub struct RuntimeController {
    profile: DeviceProfile,
    signals: RuntimeSignals,
    policy: AdaptivePerformancePolicy,
}

impl RuntimeController {
    pub fn detect() -> Self {
        Self::new(DeviceProfile::detect())
    }

    pub fn new(profile: DeviceProfile) -> Self {
        let signals = RuntimeSignals::normal(RuntimePressure::Idle);
        let policy = AdaptivePerformancePolicy::for_signals(profile, signals);
        Self {
            profile,
            signals,
            policy,
        }
    }

    pub fn profile(&self) -> DeviceProfile {
        self.profile
    }

    pub fn signals(&self) -> RuntimeSignals {
        self.signals
    }

    pub fn policy(&self) -> AdaptivePerformancePolicy {
        self.policy
    }

    pub fn execution_limits(&self) -> RuntimeExecutionLimits {
        self.policy.into()
    }

    /// Preserve UI/Vault/Sync admission capacity while adapting expensive
    /// AI/background lanes to the current policy.
    pub fn queue_limits(&self, base: RuntimeQueueLimits) -> RuntimeQueueLimits {
        RuntimeQueueLimits {
            ui_interactive: base.ui_interactive,
            vault_critical: base.vault_critical,
            sync_interactive: base.sync_interactive,
            ai_foreground: self.policy.ai_queue_limit,
            background: if self.policy.background_workers == 0 {
                0
            } else {
                base.background
                    .min(self.policy.background_workers.saturating_mul(4).max(1))
            },
        }
    }

    pub fn update_runtime_pressure(&mut self, pressure: RuntimePressure) -> PolicyUpdate {
        let mut next = self.signals;
        next.pressure = pressure;
        self.update_signals(next)
    }

    pub fn update_thermal_pressure(&mut self, thermal: ThermalPressure) -> PolicyUpdate {
        let mut next = self.signals;
        next.thermal = thermal;
        self.update_signals(next)
    }

    pub fn update_power_mode(&mut self, power_mode: PowerMode) -> PolicyUpdate {
        let mut next = self.signals;
        next.power_mode = power_mode;
        self.update_signals(next)
    }

    pub fn update_signals(&mut self, signals: RuntimeSignals) -> PolicyUpdate {
        let previous = self.policy;
        self.signals = signals;
        self.policy = AdaptivePerformancePolicy::for_signals(self.profile, self.signals);
        PolicyUpdate {
            previous,
            current: self.policy,
            changed: previous != self.policy,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GovernorUpdate {
    pub policy: PolicyUpdate,
    pub queues: RuntimeQueueUpdate,
    pub execution: RuntimeExecutionLimits,
}

/// Binds device/runtime policy to a live scheduler.
///
/// Queue limits are applied immediately. Execution limits are exposed for the
/// future AI/background worker executors; until those executors exist, Jend
/// does not pretend that changing `ai_workers` can interrupt an already running
/// model kernel.
pub struct RuntimeGovernor<T> {
    controller: RuntimeController,
    scheduler: RuntimeScheduler<T>,
    base_limits: RuntimeQueueLimits,
}

impl<T> RuntimeGovernor<T> {
    pub fn new(profile: DeviceProfile, base_limits: RuntimeQueueLimits) -> Self {
        let controller = RuntimeController::new(profile);
        let scheduler = RuntimeScheduler::new(controller.queue_limits(base_limits));
        Self {
            controller,
            scheduler,
            base_limits,
        }
    }

    pub fn detect(base_limits: RuntimeQueueLimits) -> Self {
        Self::new(DeviceProfile::detect(), base_limits)
    }

    pub fn controller(&self) -> &RuntimeController {
        &self.controller
    }

    pub fn scheduler(&self) -> &RuntimeScheduler<T> {
        &self.scheduler
    }

    pub fn execution_limits(&self) -> RuntimeExecutionLimits {
        self.controller.execution_limits()
    }

    pub fn update_runtime_pressure(&mut self, pressure: RuntimePressure) -> GovernorUpdate {
        let policy = self.controller.update_runtime_pressure(pressure);
        self.apply(policy)
    }

    pub fn update_thermal_pressure(&mut self, thermal: ThermalPressure) -> GovernorUpdate {
        let policy = self.controller.update_thermal_pressure(thermal);
        self.apply(policy)
    }

    pub fn update_power_mode(&mut self, power_mode: PowerMode) -> GovernorUpdate {
        let policy = self.controller.update_power_mode(power_mode);
        self.apply(policy)
    }

    pub fn update_signals(&mut self, signals: RuntimeSignals) -> GovernorUpdate {
        let policy = self.controller.update_signals(signals);
        self.apply(policy)
    }

    fn apply(&self, policy: PolicyUpdate) -> GovernorUpdate {
        let queues = self
            .scheduler
            .update_limits(self.controller.queue_limits(self.base_limits));
        GovernorUpdate {
            policy,
            queues,
            execution: self.controller.execution_limits(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnimationDetail, DeviceTier, PlatformClass, RuntimeLane, SubmitFailure,
    };

    fn mobile_profile() -> DeviceProfile {
        DeviceProfile {
            logical_parallelism: 8,
            memory_bytes: Some(12 * 1024 * 1024 * 1024),
            tier: DeviceTier::High,
            platform: PlatformClass::Mobile,
        }
    }

    #[test]
    fn controller_reacts_to_runtime_pressure() {
        let mut controller = RuntimeController::new(mobile_profile());
        let normal = controller.policy();
        let update = controller.update_runtime_pressure(RuntimePressure::Saturated);

        assert!(update.changed);
        assert!(update.current.ai_workers <= normal.ai_workers);
        assert_eq!(update.current.background_workers, 0);
        assert_eq!(update.current.animation_detail, AnimationDetail::Minimal);
    }

    #[test]
    fn controller_reacts_to_low_power_mode() {
        let mut controller = RuntimeController::new(mobile_profile());
        let update = controller.update_power_mode(PowerMode::LowPower);

        assert!(update.changed);
        assert_eq!(update.current.ai_workers, 1);
        assert_eq!(update.current.background_workers, 0);
        assert_eq!(update.current.ai_queue_limit, 1);
    }

    #[test]
    fn controller_reacts_to_critical_thermal_state() {
        let mut controller = RuntimeController::new(mobile_profile());
        let update = controller.update_thermal_pressure(ThermalPressure::Critical);

        assert!(update.changed);
        assert_eq!(update.current.ai_compute_share_percent, 15);
        assert_eq!(update.current.background_workers, 0);
    }

    #[test]
    fn repeating_same_signal_is_stable() {
        let mut controller = RuntimeController::new(mobile_profile());
        let first = controller.update_power_mode(PowerMode::LowPower);
        let second = controller.update_power_mode(PowerMode::LowPower);

        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(second.previous, second.current);
    }

    #[test]
    fn governor_applies_mobile_low_power_to_live_queues() {
        let base = RuntimeQueueLimits::default();
        let mut governor = RuntimeGovernor::<u8>::new(mobile_profile(), base);

        assert!(governor
            .scheduler()
            .try_submit(RuntimeLane::AiForeground, 1)
            .is_ok());

        let update = governor.update_power_mode(PowerMode::LowPower);
        assert_eq!(update.execution.ai_workers, 1);
        assert_eq!(update.execution.background_workers, 0);
        assert_eq!(update.queues.current.ai_foreground, 1);
        assert_eq!(update.queues.current.background, 0);
        assert_eq!(update.queues.current.ui_interactive, base.ui_interactive);
        assert_eq!(update.queues.current.vault_critical, base.vault_critical);

        assert!(matches!(
            governor
                .scheduler()
                .try_submit(RuntimeLane::AiForeground, 2),
            Err(SubmitFailure::QueueFull {
                lane: RuntimeLane::AiForeground,
                task: 2
            })
        ));
        assert!(matches!(
            governor.scheduler().try_submit(RuntimeLane::Background, 3),
            Err(SubmitFailure::QueueFull {
                lane: RuntimeLane::Background,
                task: 3
            })
        ));
    }

    #[test]
    fn governor_does_not_drop_already_accepted_ai_work() {
        let base = RuntimeQueueLimits {
            ui_interactive: 8,
            vault_critical: 8,
            sync_interactive: 8,
            ai_foreground: 8,
            background: 8,
        };
        let mut governor = RuntimeGovernor::<u8>::new(mobile_profile(), base);

        // Mobile normal policy starts with an AI queue limit of 4.
        for value in 0..4u8 {
            assert!(governor
                .scheduler()
                .try_submit(RuntimeLane::AiForeground, value)
                .is_ok());
        }

        governor.update_runtime_pressure(RuntimePressure::Saturated);

        // The queue now admits only 1, but the existing 4 tasks remain.
        assert_eq!(governor.scheduler().limits().ai_foreground, 1);
        assert_eq!(
            governor.scheduler().snapshot().depths[3],
            4
        );

        for expected in 0..4u8 {
            let next = governor.scheduler().try_next().expect("accepted work must drain");
            assert_eq!(next.task, expected);
        }
    }
}
