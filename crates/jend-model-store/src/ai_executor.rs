//! Bounded AI executor scheduling metadata.
//!
//! This module contains no prompt/message bytes and no inference backend. It
//! defines the process-local job queue used by the separate `jend-aid` binary.
//! Payloads are generic so the daemon may own zeroizing plaintext buffers
//! without putting chat plaintext into model-store metadata types.

use std::{
    collections::{HashSet, VecDeque},
    sync::{Condvar, Mutex, MutexGuard},
};

use crate::{ModelId, ModelStoreError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AiJobId(pub [u8; 16]);

impl AiJobId {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AiExecutorLimits {
    pub active_workers: usize,
    pub max_queue: usize,
}

impl AiExecutorLimits {
    fn validate(self, hard_max_workers: usize) -> Result<Self> {
        if hard_max_workers == 0
            || self.active_workers == 0
            || self.active_workers > hard_max_workers
            || self.max_queue == 0
            || self.max_queue > 1024
        {
            return Err(ModelStoreError::InvalidAiExecutorLimits);
        }
        Ok(self)
    }
}

pub struct AiJob<T> {
    pub id: AiJobId,
    pub model_id: ModelId,
    pub payload: T,
}

pub enum AiSubmitFailure<T> {
    QueueFull(AiJob<T>),
    Closed(AiJob<T>),
}

pub enum AiCancelResult<T> {
    QueuedRemoved(AiJob<T>),
    ActiveMarked,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AiExecutorSnapshot {
    pub queued: usize,
    pub active: usize,
    pub active_workers: usize,
    pub max_queue: usize,
    pub closed: bool,
}

struct State<T> {
    limits: AiExecutorLimits,
    queue: VecDeque<AiJob<T>>,
    active: HashSet<AiJobId>,
    cancelled_active: HashSet<AiJobId>,
    closed: bool,
}

pub struct AiExecutor<T> {
    hard_max_workers: usize,
    state: Mutex<State<T>>,
    ready: Condvar,
}

impl<T> AiExecutor<T> {
    pub fn new(hard_max_workers: usize, limits: AiExecutorLimits) -> Result<Self> {
        let limits = limits.validate(hard_max_workers)?;
        Ok(Self {
            hard_max_workers,
            state: Mutex::new(State {
                limits,
                queue: VecDeque::new(),
                active: HashSet::new(),
                cancelled_active: HashSet::new(),
                closed: false,
            }),
            ready: Condvar::new(),
        })
    }

    /// Never waits for queue capacity. The original job is returned on
    /// backpressure so callers can retry/coalesce intentionally.
    pub fn try_submit(&self, job: AiJob<T>) -> core::result::Result<(), AiSubmitFailure<T>> {
        let mut state = self.lock_state();
        if state.closed {
            return Err(AiSubmitFailure::Closed(job));
        }
        if state.queue.len() >= state.limits.max_queue {
            return Err(AiSubmitFailure::QueueFull(job));
        }
        if state.active.contains(&job.id) || state.queue.iter().any(|queued| queued.id == job.id) {
            return Err(AiSubmitFailure::QueueFull(job));
        }
        state.queue.push_back(job);
        self.ready.notify_one();
        Ok(())
    }

    /// Worker-side blocking dequeue. Physical worker threads may exceed the
    /// current active limit; only `active_workers` jobs are admitted at once.
    pub fn wait_next(&self) -> Option<AiJob<T>> {
        let mut state = self.lock_state();
        loop {
            if state.active.len() < state.limits.active_workers {
                if let Some(job) = state.queue.pop_front() {
                    state.cancelled_active.remove(&job.id);
                    state.active.insert(job.id);
                    return Some(job);
                }
            }
            if state.closed && state.queue.is_empty() && state.active.is_empty() {
                return None;
            }
            state = match self.ready.wait(state) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    pub fn cancel(&self, job_id: AiJobId) -> AiCancelResult<T> {
        let mut state = self.lock_state();
        if let Some(index) = state.queue.iter().position(|job| job.id == job_id) {
            let job = state
                .queue
                .remove(index)
                .expect("queued position was just located");
            return AiCancelResult::QueuedRemoved(job);
        }
        if state.active.contains(&job_id) {
            state.cancelled_active.insert(job_id);
            return AiCancelResult::ActiveMarked;
        }
        AiCancelResult::NotFound
    }

    /// Backends should check this between safe inference/task boundaries.
    pub fn cancellation_requested(&self, job_id: AiJobId) -> bool {
        self.lock_state().cancelled_active.contains(&job_id)
    }

    pub fn finish(&self, job_id: AiJobId) -> Result<()> {
        let mut state = self.lock_state();
        if !state.active.remove(&job_id) {
            return Err(ModelStoreError::UnknownAiJob);
        }
        state.cancelled_active.remove(&job_id);
        self.ready.notify_all();
        Ok(())
    }

    /// Dynamic policy changes affect admission and future worker starts. An
    /// already-running inference is not force-killed; cancellation/preemption
    /// remains backend-safe and cooperative.
    pub fn update_limits(&self, limits: AiExecutorLimits) -> Result<AiExecutorLimits> {
        let limits = limits.validate(self.hard_max_workers)?;
        let mut state = self.lock_state();
        let previous = state.limits;
        state.limits = limits;
        self.ready.notify_all();
        Ok(previous)
    }

    pub fn snapshot(&self) -> AiExecutorSnapshot {
        let state = self.lock_state();
        AiExecutorSnapshot {
            queued: state.queue.len(),
            active: state.active.len(),
            active_workers: state.limits.active_workers,
            max_queue: state.limits.max_queue,
            closed: state.closed,
        }
    }

    pub fn close(&self) {
        let mut state = self.lock_state();
        state.closed = true;
        self.ready.notify_all();
    }

    fn lock_state(&self) -> MutexGuard<'_, State<T>> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(id: u8, value: u8) -> AiJob<u8> {
        AiJob {
            id: AiJobId([id; 16]),
            model_id: ModelId([1u8; 16]),
            payload: value,
        }
    }

    #[test]
    fn queue_applies_immediate_backpressure() {
        let executor = AiExecutor::new(
            2,
            AiExecutorLimits {
                active_workers: 1,
                max_queue: 1,
            },
        )
        .unwrap();
        assert!(executor.try_submit(job(1, 7)).is_ok());
        match executor.try_submit(job(2, 9)) {
            Err(AiSubmitFailure::QueueFull(rejected)) => assert_eq!(rejected.payload, 9),
            _ => panic!("second queued job should have been backpressured"),
        }
    }

    #[test]
    fn active_limit_blocks_second_start_until_finish() {
        let executor = AiExecutor::new(
            2,
            AiExecutorLimits {
                active_workers: 1,
                max_queue: 4,
            },
        )
        .unwrap();
        assert!(executor.try_submit(job(1, 1)).is_ok());
        assert!(executor.try_submit(job(2, 2)).is_ok());
        let first = executor.wait_next().unwrap();
        assert_eq!(executor.snapshot().active, 1);
        executor.finish(first.id).unwrap();
        let second = executor.wait_next().unwrap();
        assert_eq!(second.payload, 2);
    }

    #[test]
    fn queued_cancel_returns_payload_without_starting_it() {
        let executor = AiExecutor::new(
            1,
            AiExecutorLimits {
                active_workers: 1,
                max_queue: 2,
            },
        )
        .unwrap();
        assert!(executor.try_submit(job(3, 11)).is_ok());
        match executor.cancel(AiJobId([3u8; 16])) {
            AiCancelResult::QueuedRemoved(cancelled) => assert_eq!(cancelled.payload, 11),
            _ => panic!("queued job was not removed"),
        }
        assert_eq!(executor.snapshot().queued, 0);
    }

    #[test]
    fn active_cancel_is_cooperative_and_cleared_on_finish() {
        let executor = AiExecutor::new(
            1,
            AiExecutorLimits {
                active_workers: 1,
                max_queue: 2,
            },
        )
        .unwrap();
        assert!(executor.try_submit(job(4, 1)).is_ok());
        let active = executor.wait_next().unwrap();
        assert!(matches!(
            executor.cancel(active.id),
            AiCancelResult::ActiveMarked
        ));
        assert!(executor.cancellation_requested(active.id));
        executor.finish(active.id).unwrap();
        assert!(!executor.cancellation_requested(active.id));
    }

    #[test]
    fn dynamic_limit_change_does_not_kill_running_job() {
        let executor = AiExecutor::new(
            4,
            AiExecutorLimits {
                active_workers: 2,
                max_queue: 8,
            },
        )
        .unwrap();
        assert!(executor.try_submit(job(5, 1)).is_ok());
        let active = executor.wait_next().unwrap();
        executor
            .update_limits(AiExecutorLimits {
                active_workers: 1,
                max_queue: 1,
            })
            .unwrap();
        assert_eq!(executor.snapshot().active, 1);
        executor.finish(active.id).unwrap();
    }
}
