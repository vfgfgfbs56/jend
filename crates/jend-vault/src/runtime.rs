//! Local client runtime scheduling primitives.
//!
//! This module intentionally uses only `std` so M7.3 does not change the
//! workspace dependency graph or `Cargo.lock`.  It is the first foundation for
//! Jend's "instant UI even while local AI is busy" requirement.
//!
//! The scheduler does not execute work on the render thread. Producers submit
//! with `try_submit`, which never waits for queue capacity. Consumers may use
//! `try_next` or `wait_next` from dedicated worker threads.

use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};

/// Work lanes are ordered by user-visible urgency, not by computational cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLane {
    /// Input, optimistic message insertion, animation state transitions.
    UiInteractive,
    /// Encrypt/decrypt, durable message commit, key operations.
    VaultCritical,
    /// Foreground device/message synchronization.
    SyncInteractive,
    /// Local model generation that is visible to the user.
    AiForeground,
    /// Indexing, cleanup, prefetch, maintenance.
    Background,
}

impl RuntimeLane {
    const COUNT: usize = 5;

    const fn index(self) -> usize {
        match self {
            Self::UiInteractive => 0,
            Self::VaultCritical => 1,
            Self::SyncInteractive => 2,
            Self::AiForeground => 3,
            Self::Background => 4,
        }
    }

    /// Target maximum queue wait before the runtime should consider adapting
    /// quality/concurrency. These are queueing budgets, not task-duration SLAs.
    pub const fn queue_wait_budget(self) -> Duration {
        match self {
            Self::UiInteractive => Duration::from_millis(8),
            Self::VaultCritical => Duration::from_millis(20),
            Self::SyncInteractive => Duration::from_millis(50),
            Self::AiForeground => Duration::from_millis(100),
            Self::Background => Duration::from_millis(500),
        }
    }
}

/// Default queue capacities intentionally keep expensive/background work small
/// so it cannot consume unbounded memory on old devices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeQueueLimits {
    pub ui_interactive: usize,
    pub vault_critical: usize,
    pub sync_interactive: usize,
    pub ai_foreground: usize,
    pub background: usize,
}

impl Default for RuntimeQueueLimits {
    fn default() -> Self {
        Self {
            ui_interactive: 64,
            vault_critical: 64,
            sync_interactive: 128,
            ai_foreground: 8,
            background: 8,
        }
    }
}

impl RuntimeQueueLimits {
    fn capacity(self, lane: RuntimeLane) -> usize {
        match lane {
            RuntimeLane::UiInteractive => self.ui_interactive,
            RuntimeLane::VaultCritical => self.vault_critical,
            RuntimeLane::SyncInteractive => self.sync_interactive,
            RuntimeLane::AiForeground => self.ai_foreground,
            RuntimeLane::Background => self.background,
        }
    }

    fn total(self) -> usize {
        self.ui_interactive
            .saturating_add(self.vault_critical)
            .saturating_add(self.sync_interactive)
            .saturating_add(self.ai_foreground)
            .saturating_add(self.background)
    }
}

/// Backpressure result. The original task is returned to the caller, allowing
/// the UI/runtime to coalesce, retry, or drop low-value work deliberately.
pub enum SubmitFailure<T> {
    QueueFull { lane: RuntimeLane, task: T },
    Closed { task: T },
}

/// One dequeued task plus scheduler metadata.
pub struct ScheduledTask<T> {
    pub lane: RuntimeLane,
    pub task: T,
    pub queue_wait: Duration,
    pub missed_queue_budget: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePressure {
    Idle,
    Normal,
    Elevated,
    Saturated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSnapshot {
    pub depths: [usize; RuntimeLane::COUNT],
    pub capacities: [usize; RuntimeLane::COUNT],
    pub total_depth: usize,
    pub total_capacity: usize,
    pub pressure: RuntimePressure,
}

struct Pending<T> {
    enqueued_at: Instant,
    task: T,
}

struct State<T> {
    queues: [VecDeque<Pending<T>>; RuntimeLane::COUNT],
    limits: RuntimeQueueLimits,
    urgent_streak: usize,
    closed: bool,
}

impl<T> State<T> {
    fn new(limits: RuntimeQueueLimits) -> Self {
        Self {
            queues: std::array::from_fn(|_| VecDeque::new()),
            limits,
            urgent_streak: 0,
            closed: false,
        }
    }
}

/// Maximum number of consecutive UI/Vault/Sync dequeues before one pending AI
/// or background task is allowed through. This prevents permanent starvation
/// while keeping interactive work dominant.
const MAX_URGENT_BURST: usize = 8;

/// Bounded, non-blocking-at-submit scheduler for the local client runtime.
///
/// The mutex protects only short queue bookkeeping. Work itself is never
/// executed while the mutex is held.
pub struct RuntimeScheduler<T> {
    state: Mutex<State<T>>,
    ready: Condvar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeQueueUpdate {
    pub previous: RuntimeQueueLimits,
    pub current: RuntimeQueueLimits,
    pub depths: [usize; RuntimeLane::COUNT],
    pub changed: bool,
}

impl<T> RuntimeScheduler<T> {
    pub fn new(limits: RuntimeQueueLimits) -> Self {
        Self {
            state: Mutex::new(State::new(limits)),
            ready: Condvar::new(),
        }
    }

    /// Enqueue without waiting for capacity. This is the only submission API
    /// intended for latency-sensitive producers such as UI event handling.
    pub fn try_submit(
        &self,
        lane: RuntimeLane,
        task: T,
    ) -> Result<(), SubmitFailure<T>> {
        let mut state = self.lock_state();
        if state.closed {
            return Err(SubmitFailure::Closed { task });
        }

        let capacity = state.limits.capacity(lane);
        let queue = &mut state.queues[lane.index()];
        if queue.len() >= capacity {
            return Err(SubmitFailure::QueueFull { lane, task });
        }

        queue.push_back(Pending {
            enqueued_at: Instant::now(),
            task,
        });
        self.ready.notify_one();
        Ok(())
    }

    /// Non-blocking dequeue for event-loop/runtime integration.
    pub fn try_next(&self) -> Option<ScheduledTask<T>> {
        let mut state = self.lock_state();
        Self::pop_next(&mut state)
    }

    /// Worker-thread dequeue. Returns `None` only after `close()` and all
    /// already-accepted work has drained.
    pub fn wait_next(&self) -> Option<ScheduledTask<T>> {
        let mut state = self.lock_state();
        loop {
            if let Some(task) = Self::pop_next(&mut state) {
                return Some(task);
            }
            if state.closed {
                return None;
            }
            state = match self.ready.wait(state) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    /// Reject future submissions, wake sleeping workers, and allow accepted
    /// work to drain.
    pub fn close(&self) {
        let mut state = self.lock_state();
        state.closed = true;
        self.ready.notify_all();
    }

    /// Reconfigure queue admission limits without discarding accepted work.
    ///
    /// If a lane already contains more tasks than the new capacity, those tasks
    /// are allowed to drain. New submissions to that lane are rejected until
    /// depth falls below the new limit.
    pub fn update_limits(&self, limits: RuntimeQueueLimits) -> RuntimeQueueUpdate {
        let mut state = self.lock_state();
        let previous = state.limits;
        state.limits = limits;
        RuntimeQueueUpdate {
            previous,
            current: state.limits,
            depths: std::array::from_fn(|index| state.queues[index].len()),
            changed: previous != state.limits,
        }
    }

    pub fn limits(&self) -> RuntimeQueueLimits {
        self.lock_state().limits
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        let state = self.lock_state();
        let limits = state.limits;
        let depths = std::array::from_fn(|index| state.queues[index].len());
        let capacities = [
            limits.ui_interactive,
            limits.vault_critical,
            limits.sync_interactive,
            limits.ai_foreground,
            limits.background,
        ];
        let total_depth = depths.iter().copied().sum::<usize>();
        let total_capacity = limits.total();

        let interactive_hot = [
            RuntimeLane::UiInteractive,
            RuntimeLane::VaultCritical,
        ]
        .into_iter()
        .any(|lane| {
            let capacity = limits.capacity(lane);
            capacity > 0 && state.queues[lane.index()].len().saturating_mul(4) >= capacity.saturating_mul(3)
        });

        let pressure = if total_depth == 0 {
            RuntimePressure::Idle
        } else if total_capacity == 0
            || total_depth.saturating_mul(10) >= total_capacity.saturating_mul(9)
        {
            RuntimePressure::Saturated
        } else if interactive_hot
            || total_depth.saturating_mul(4) >= total_capacity.saturating_mul(3)
        {
            RuntimePressure::Elevated
        } else {
            RuntimePressure::Normal
        };

        RuntimeSnapshot {
            depths,
            capacities,
            total_depth,
            total_capacity,
            pressure,
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, State<T>> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn pop_next(state: &mut State<T>) -> Option<ScheduledTask<T>> {
        let background_pending = !state.queues[RuntimeLane::AiForeground.index()].is_empty()
            || !state.queues[RuntimeLane::Background.index()].is_empty();

        let lane = if background_pending && state.urgent_streak >= MAX_URGENT_BURST {
            Self::first_pending(
                state,
                &[RuntimeLane::AiForeground, RuntimeLane::Background],
            )
        } else {
            Self::first_pending(
                state,
                &[
                    RuntimeLane::UiInteractive,
                    RuntimeLane::VaultCritical,
                    RuntimeLane::SyncInteractive,
                ],
            )
            .or_else(|| {
                Self::first_pending(
                    state,
                    &[RuntimeLane::AiForeground, RuntimeLane::Background],
                )
            })
        }?;

        if matches!(
            lane,
            RuntimeLane::UiInteractive
                | RuntimeLane::VaultCritical
                | RuntimeLane::SyncInteractive
        ) {
            state.urgent_streak = state.urgent_streak.saturating_add(1);
        } else {
            state.urgent_streak = 0;
        }

        let pending = state.queues[lane.index()]
            .pop_front()
            .expect("lane was selected only when non-empty");
        let queue_wait = pending.enqueued_at.elapsed();

        Some(ScheduledTask {
            lane,
            task: pending.task,
            queue_wait,
            missed_queue_budget: queue_wait > lane.queue_wait_budget(),
        })
    }

    fn first_pending(state: &State<T>, lanes: &[RuntimeLane]) -> Option<RuntimeLane> {
        lanes
            .iter()
            .copied()
            .find(|lane| !state.queues[lane.index()].is_empty())
    }
}

impl<T> Default for RuntimeScheduler<T> {
    fn default() -> Self {
        Self::new(RuntimeQueueLimits::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_and_vault_overtake_ai_backlog() {
        let scheduler = RuntimeScheduler::default();

        for value in 0..4 {
            assert!(scheduler
                .try_submit(RuntimeLane::AiForeground, ("ai", value))
                .is_ok());
        }
        assert!(scheduler
            .try_submit(RuntimeLane::VaultCritical, ("vault", 1))
            .is_ok());
        assert!(scheduler
            .try_submit(RuntimeLane::UiInteractive, ("ui", 1))
            .is_ok());

        let first = scheduler.try_next().expect("UI task");
        let second = scheduler.try_next().expect("Vault task");
        assert_eq!(first.lane, RuntimeLane::UiInteractive);
        assert_eq!(second.lane, RuntimeLane::VaultCritical);
    }

    #[test]
    fn full_lane_returns_original_task_without_blocking() {
        let scheduler = RuntimeScheduler::new(RuntimeQueueLimits {
            ui_interactive: 1,
            vault_critical: 1,
            sync_interactive: 1,
            ai_foreground: 1,
            background: 1,
        });

        assert!(scheduler
            .try_submit(RuntimeLane::AiForeground, 7u32)
            .is_ok());

        match scheduler.try_submit(RuntimeLane::AiForeground, 9u32) {
            Err(SubmitFailure::QueueFull { lane, task }) => {
                assert_eq!(lane, RuntimeLane::AiForeground);
                assert_eq!(task, 9);
            }
            _ => panic!("AI lane should have applied backpressure"),
        }
    }

    #[test]
    fn sustained_urgent_work_cannot_starve_ai_forever() {
        let scheduler = RuntimeScheduler::new(RuntimeQueueLimits {
            ui_interactive: 32,
            vault_critical: 1,
            sync_interactive: 1,
            ai_foreground: 2,
            background: 1,
        });

        for value in 0..16 {
            assert!(scheduler
                .try_submit(RuntimeLane::UiInteractive, value)
                .is_ok());
        }
        assert!(scheduler
            .try_submit(RuntimeLane::AiForeground, 99)
            .is_ok());

        let mut saw_ai = false;
        for _ in 0..=MAX_URGENT_BURST {
            let next = scheduler.try_next().expect("scheduled work");
            if next.lane == RuntimeLane::AiForeground {
                saw_ai = true;
                break;
            }
        }
        assert!(saw_ai, "AI must receive a bounded fairness slot");
    }

    #[test]
    fn close_rejects_new_work_but_drains_accepted_work() {
        let scheduler = RuntimeScheduler::default();
        assert!(scheduler
            .try_submit(RuntimeLane::VaultCritical, 1u8)
            .is_ok());
        scheduler.close();

        match scheduler.try_submit(RuntimeLane::UiInteractive, 2u8) {
            Err(SubmitFailure::Closed { task }) => assert_eq!(task, 2),
            _ => panic!("closed scheduler accepted new work"),
        }

        assert_eq!(
            scheduler.try_next().expect("accepted work must drain").task,
            1
        );
        assert!(scheduler.wait_next().is_none());
    }

    #[test]
    fn queue_budgets_keep_interactive_lanes_tighter_than_ai() {
        assert!(
            RuntimeLane::UiInteractive.queue_wait_budget()
                < RuntimeLane::VaultCritical.queue_wait_budget()
        );
        assert!(
            RuntimeLane::VaultCritical.queue_wait_budget()
                < RuntimeLane::SyncInteractive.queue_wait_budget()
        );
        assert!(
            RuntimeLane::SyncInteractive.queue_wait_budget()
                < RuntimeLane::AiForeground.queue_wait_budget()
        );
        assert!(
            RuntimeLane::AiForeground.queue_wait_budget()
                < RuntimeLane::Background.queue_wait_budget()
        );
    }

    #[test]
    fn lowering_ai_limit_preserves_accepted_work_and_backpressures_new_work() {
        let scheduler = RuntimeScheduler::new(RuntimeQueueLimits {
            ui_interactive: 8,
            vault_critical: 8,
            sync_interactive: 8,
            ai_foreground: 4,
            background: 4,
        });

        for value in 0..4u8 {
            assert!(scheduler
                .try_submit(RuntimeLane::AiForeground, value)
                .is_ok());
        }

        let update = scheduler.update_limits(RuntimeQueueLimits {
            ui_interactive: 8,
            vault_critical: 8,
            sync_interactive: 8,
            ai_foreground: 1,
            background: 0,
        });
        assert!(update.changed);
        assert_eq!(update.depths[RuntimeLane::AiForeground.index()], 4);

        assert!(matches!(
            scheduler.try_submit(RuntimeLane::AiForeground, 9),
            Err(SubmitFailure::QueueFull {
                lane: RuntimeLane::AiForeground,
                task: 9
            })
        ));

        for expected in 0..4u8 {
            let next = scheduler.try_next().expect("accepted AI work must drain");
            assert_eq!(next.task, expected);
        }
    }

    #[test]
    fn dynamic_limit_update_does_not_reduce_interactive_capacity_by_itself() {
        let scheduler = RuntimeScheduler::<u8>::default();
        let original = scheduler.limits();
        let mut next = original;
        next.ai_foreground = 1;
        next.background = 0;
        scheduler.update_limits(next);

        let current = scheduler.limits();
        assert_eq!(current.ui_interactive, original.ui_interactive);
        assert_eq!(current.vault_critical, original.vault_critical);
        assert_eq!(current.sync_interactive, original.sync_interactive);
        assert_eq!(current.ai_foreground, 1);
        assert_eq!(current.background, 0);
    }

    #[test]
    fn pressure_snapshot_detects_empty_and_interactive_hot_states() {
        let scheduler = RuntimeScheduler::new(RuntimeQueueLimits {
            ui_interactive: 4,
            vault_critical: 4,
            sync_interactive: 4,
            ai_foreground: 4,
            background: 4,
        });
        assert_eq!(scheduler.snapshot().pressure, RuntimePressure::Idle);

        for value in 0..3 {
            assert!(scheduler
                .try_submit(RuntimeLane::UiInteractive, value)
                .is_ok());
        }
        assert_eq!(scheduler.snapshot().pressure, RuntimePressure::Elevated);
    }
}
