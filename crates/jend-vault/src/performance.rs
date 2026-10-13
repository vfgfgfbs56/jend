//! Local-only device profiling and adaptive performance policy.
//!
//! No profile data leaves the process. The profiler intentionally uses only
//! coarse CPU-parallelism, memory capacity and platform class. It does not use
//! CPU model strings as identifiers and never requires network access.

use std::thread;

use crate::RuntimePressure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformClass {
    Desktop,
    Mobile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum DeviceTier {
    Low,
    Balanced,
    High,
    Ultra,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceProfile {
    pub logical_parallelism: usize,
    pub memory_bytes: Option<u64>,
    pub tier: DeviceTier,
    pub platform: PlatformClass,
}

impl DeviceProfile {
    pub fn detect() -> Self {
        let logical_parallelism = thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1);
        let memory_bytes = detect_memory_bytes();
        let tier = classify_device(logical_parallelism, memory_bytes);
        Self {
            logical_parallelism,
            memory_bytes,
            tier,
            platform: detect_platform_class(),
        }
    }

    pub fn memory_gib_floor(self) -> Option<u64> {
        self.memory_bytes.map(|bytes| bytes / (1024 * 1024 * 1024))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnimationDetail {
    Minimal,
    Balanced,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThermalPressure {
    Nominal,
    Elevated,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerMode {
    Normal,
    LowPower,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSignals {
    pub pressure: RuntimePressure,
    pub thermal: ThermalPressure,
    pub power_mode: PowerMode,
}

impl RuntimeSignals {
    pub const fn normal(pressure: RuntimePressure) -> Self {
        Self {
            pressure,
            thermal: ThermalPressure::Nominal,
            power_mode: PowerMode::Normal,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptivePerformancePolicy {
    pub target_ui_hz: u16,
    pub ai_workers: usize,
    pub background_workers: usize,
    pub ai_queue_limit: usize,
    pub ai_compute_share_percent: u8,
    pub animation_detail: AnimationDetail,
    pub allow_background_prefetch: bool,
}

impl AdaptivePerformancePolicy {
    /// Compatibility helper for callers that do not yet provide power/thermal
    /// signals. Mobile constraints are still applied through `profile`.
    pub fn for_profile(profile: DeviceProfile, pressure: RuntimePressure) -> Self {
        Self::for_signals(profile, RuntimeSignals::normal(pressure))
    }

    pub fn for_signals(profile: DeviceProfile, signals: RuntimeSignals) -> Self {
        let mut policy = match profile.tier {
            DeviceTier::Low => Self {
                target_ui_hz: 60,
                ai_workers: 1,
                background_workers: 1,
                ai_queue_limit: 2,
                ai_compute_share_percent: 35,
                animation_detail: AnimationDetail::Minimal,
                allow_background_prefetch: false,
            },
            DeviceTier::Balanced => Self {
                target_ui_hz: 60,
                ai_workers: 2,
                background_workers: 1,
                ai_queue_limit: 4,
                ai_compute_share_percent: 50,
                animation_detail: AnimationDetail::Balanced,
                allow_background_prefetch: true,
            },
            DeviceTier::High => Self {
                target_ui_hz: 120,
                ai_workers: 4,
                background_workers: 2,
                ai_queue_limit: 8,
                ai_compute_share_percent: 65,
                animation_detail: AnimationDetail::Full,
                allow_background_prefetch: true,
            },
            DeviceTier::Ultra => Self {
                target_ui_hz: 120,
                ai_workers: 6,
                background_workers: 2,
                ai_queue_limit: 8,
                ai_compute_share_percent: 75,
                animation_detail: AnimationDetail::Full,
                allow_background_prefetch: true,
            },
        };

        // Mobile devices must reserve more thermal/battery headroom even when
        // raw core/RAM counts look desktop-class. Until the platform UI layer
        // explicitly reports a high-refresh display, Jend caps its target at
        // 60 Hz and favors sustained responsiveness over burst throughput.
        if profile.platform == PlatformClass::Mobile {
            policy.target_ui_hz = policy.target_ui_hz.min(60);
            policy.ai_workers = policy.ai_workers.min(2);
            policy.background_workers = policy.background_workers.min(1);
            policy.ai_queue_limit = policy.ai_queue_limit.min(4);
            policy.ai_compute_share_percent = policy.ai_compute_share_percent.min(50);
            policy.allow_background_prefetch = false;
            if policy.animation_detail == AnimationDetail::Full {
                policy.animation_detail = AnimationDetail::Balanced;
            }
        }

        match signals.pressure {
            RuntimePressure::Idle | RuntimePressure::Normal => {}
            RuntimePressure::Elevated => {
                policy.ai_workers = policy.ai_workers.saturating_sub(1).max(1);
                policy.background_workers = policy.background_workers.min(1);
                policy.ai_queue_limit = policy.ai_queue_limit.min(4);
                policy.ai_compute_share_percent = policy
                    .ai_compute_share_percent
                    .saturating_sub(15)
                    .max(25);
                policy.allow_background_prefetch = false;
                policy.animation_detail = reduce_animation(policy.animation_detail);
            }
            RuntimePressure::Saturated => {
                protect_interactivity(&mut policy, 25);
            }
        }

        match signals.power_mode {
            PowerMode::Normal => {}
            PowerMode::LowPower => {
                policy.target_ui_hz = policy.target_ui_hz.min(60);
                policy.ai_workers = 1;
                policy.background_workers = 0;
                policy.ai_queue_limit = policy.ai_queue_limit.min(1);
                policy.ai_compute_share_percent = policy.ai_compute_share_percent.min(30);
                policy.animation_detail = AnimationDetail::Minimal;
                policy.allow_background_prefetch = false;
            }
        }

        match signals.thermal {
            ThermalPressure::Nominal => {}
            ThermalPressure::Elevated => {
                policy.target_ui_hz = policy.target_ui_hz.min(60);
                policy.ai_workers = policy.ai_workers.min(1);
                policy.background_workers = 0;
                policy.ai_queue_limit = policy.ai_queue_limit.min(2);
                policy.ai_compute_share_percent = policy.ai_compute_share_percent.min(25);
                policy.animation_detail = reduce_animation(policy.animation_detail);
                policy.allow_background_prefetch = false;
            }
            ThermalPressure::Critical => {
                protect_interactivity(&mut policy, 15);
            }
        }

        // Never recommend more foreground AI workers than the device exposes
        // logical execution slots. Keep at least one slot logically reserved
        // for UI/Vault/runtime whenever possible.
        let max_ai_workers = if profile.logical_parallelism > 1 {
            profile.logical_parallelism - 1
        } else {
            1
        };
        policy.ai_workers = policy.ai_workers.min(max_ai_workers).max(1);

        policy
    }
}

fn reduce_animation(detail: AnimationDetail) -> AnimationDetail {
    match detail {
        AnimationDetail::Full => AnimationDetail::Balanced,
        AnimationDetail::Balanced => AnimationDetail::Minimal,
        AnimationDetail::Minimal => AnimationDetail::Minimal,
    }
}

fn protect_interactivity(policy: &mut AdaptivePerformancePolicy, ai_share: u8) {
    policy.target_ui_hz = policy.target_ui_hz.min(60);
    policy.ai_workers = 1;
    policy.background_workers = 0;
    policy.ai_queue_limit = 1;
    policy.ai_compute_share_percent = ai_share;
    policy.animation_detail = AnimationDetail::Minimal;
    policy.allow_background_prefetch = false;
}

/// Conservative tiering. If memory cannot be read, the device is never
/// classified above Balanced: fail toward responsiveness, not throughput.
pub fn classify_device(
    logical_parallelism: usize,
    memory_bytes: Option<u64>,
) -> DeviceTier {
    let logical = logical_parallelism.max(1);
    let gib = memory_bytes.map(|bytes| bytes / (1024 * 1024 * 1024));

    match gib {
        Some(memory_gib) if logical <= 4 || memory_gib <= 4 => DeviceTier::Low,
        Some(memory_gib) if logical <= 6 || memory_gib <= 8 => DeviceTier::Balanced,
        Some(memory_gib) if logical <= 10 || memory_gib <= 16 => DeviceTier::High,
        Some(_) => DeviceTier::Ultra,
        None if logical <= 4 => DeviceTier::Low,
        None => DeviceTier::Balanced,
    }
}

fn detect_platform_class() -> PlatformClass {
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        return PlatformClass::Mobile;
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        PlatformClass::Desktop
    }
}

#[cfg(target_os = "macos")]
fn detect_memory_bytes() -> Option<u64> {
    use std::process::Command;

    // One local startup probe; never called on the render path.
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = std::str::from_utf8(&output.stdout).ok()?.trim();
    text.parse::<u64>().ok()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn detect_memory_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_proc_meminfo_bytes(&text)
}

// iOS intentionally takes the conservative fallback here. The production
// platform bridge will provide RAM/thermal/low-power signals without shelling
// out or weakening `#![forbid(unsafe_code)]`.
#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
)))]
fn detect_memory_bytes() -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_proc_meminfo_bytes(text: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
    let mut parts = line.split_whitespace();
    let _label = parts.next()?;
    let value_kib = parts.next()?.parse::<u64>().ok()?;
    let unit = parts.next()?;
    if unit != "kB" {
        return None;
    }
    value_kib.checked_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gib(value: u64) -> Option<u64> {
        Some(value * 1024 * 1024 * 1024)
    }

    fn desktop(tier: DeviceTier, logical_parallelism: usize, memory_gib: u64) -> DeviceProfile {
        DeviceProfile {
            logical_parallelism,
            memory_bytes: gib(memory_gib),
            tier,
            platform: PlatformClass::Desktop,
        }
    }

    fn mobile(tier: DeviceTier, logical_parallelism: usize, memory_gib: u64) -> DeviceProfile {
        DeviceProfile {
            logical_parallelism,
            memory_bytes: gib(memory_gib),
            tier,
            platform: PlatformClass::Mobile,
        }
    }

    #[test]
    fn old_small_device_is_low_tier() {
        assert_eq!(classify_device(4, gib(4)), DeviceTier::Low);
        assert_eq!(classify_device(8, gib(4)), DeviceTier::Low);
    }

    #[test]
    fn unknown_memory_never_assumes_high_end_hardware() {
        assert_eq!(classify_device(2, None), DeviceTier::Low);
        assert_eq!(classify_device(32, None), DeviceTier::Balanced);
    }

    #[test]
    fn large_devices_scale_conservatively() {
        assert_eq!(classify_device(8, gib(16)), DeviceTier::High);
        assert_eq!(classify_device(12, gib(32)), DeviceTier::Ultra);
    }

    #[test]
    fn saturated_runtime_protects_interactivity() {
        let profile = desktop(DeviceTier::Ultra, 16, 32);
        let policy =
            AdaptivePerformancePolicy::for_profile(profile, RuntimePressure::Saturated);

        assert_eq!(policy.target_ui_hz, 60);
        assert_eq!(policy.ai_workers, 1);
        assert_eq!(policy.background_workers, 0);
        assert_eq!(policy.ai_queue_limit, 1);
        assert_eq!(policy.animation_detail, AnimationDetail::Minimal);
        assert!(!policy.allow_background_prefetch);
    }

    #[test]
    fn desktop_high_profile_keeps_existing_m74_policy() {
        let profile = desktop(DeviceTier::High, 10, 16);
        let policy =
            AdaptivePerformancePolicy::for_profile(profile, RuntimePressure::Normal);
        assert_eq!(policy.target_ui_hz, 120);
        assert_eq!(policy.ai_workers, 4);
        assert_eq!(policy.background_workers, 2);
        assert_eq!(policy.ai_queue_limit, 8);
    }

    #[test]
    fn mobile_caps_desktop_class_hardware() {
        let profile = mobile(DeviceTier::Ultra, 12, 24);
        let policy =
            AdaptivePerformancePolicy::for_profile(profile, RuntimePressure::Normal);

        assert_eq!(policy.target_ui_hz, 60);
        assert_eq!(policy.ai_workers, 2);
        assert_eq!(policy.background_workers, 1);
        assert_eq!(policy.ai_queue_limit, 4);
        assert!(policy.ai_compute_share_percent <= 50);
        assert!(!policy.allow_background_prefetch);
    }

    #[test]
    fn mobile_low_power_prioritizes_battery_and_ui() {
        let profile = mobile(DeviceTier::High, 8, 12);
        let policy = AdaptivePerformancePolicy::for_signals(
            profile,
            RuntimeSignals {
                pressure: RuntimePressure::Normal,
                thermal: ThermalPressure::Nominal,
                power_mode: PowerMode::LowPower,
            },
        );

        assert_eq!(policy.ai_workers, 1);
        assert_eq!(policy.background_workers, 0);
        assert_eq!(policy.ai_queue_limit, 1);
        assert_eq!(policy.animation_detail, AnimationDetail::Minimal);
        assert!(!policy.allow_background_prefetch);
    }

    #[test]
    fn critical_thermal_state_minimizes_compute_on_mobile() {
        let profile = mobile(DeviceTier::Ultra, 12, 24);
        let policy = AdaptivePerformancePolicy::for_signals(
            profile,
            RuntimeSignals {
                pressure: RuntimePressure::Normal,
                thermal: ThermalPressure::Critical,
                power_mode: PowerMode::Normal,
            },
        );

        assert_eq!(policy.ai_workers, 1);
        assert_eq!(policy.background_workers, 0);
        assert_eq!(policy.ai_queue_limit, 1);
        assert_eq!(policy.ai_compute_share_percent, 15);
        assert_eq!(policy.animation_detail, AnimationDetail::Minimal);
    }

    #[test]
    fn ai_workers_leave_capacity_for_interactive_work() {
        let profile = desktop(DeviceTier::High, 2, 16);
        let policy =
            AdaptivePerformancePolicy::for_profile(profile, RuntimePressure::Normal);
        assert_eq!(policy.ai_workers, 1);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn parses_proc_meminfo() {
        let input = "MemTotal:       16384000 kB\nMemFree:         1000 kB\n";
        assert_eq!(
            parse_proc_meminfo_bytes(input),
            Some(16_384_000 * 1024)
        );
    }
}
