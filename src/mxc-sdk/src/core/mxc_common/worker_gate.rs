// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Limits concurrent workers with deadline-bounded waits for available capacity.
//! Dropping a permit releases capacity. The gate does not set operation timeouts
//! or cancel work that has already started.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct WorkerGate {
    pub(super) active: Mutex<usize>,
    pub(super) available: Condvar,
    pub(super) limit: usize,
}

impl WorkerGate {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(0),
            available: Condvar::new(),
            limit,
        })
    }

    pub(crate) fn acquire(self: &Arc<Self>, deadline: Instant) -> Result<WorkerPermit, usize> {
        self.acquire_with_budget(|| deadline.saturating_duration_since(Instant::now()))
    }

    pub(crate) fn acquire_with_budget(
        self: &Arc<Self>,
        mut remaining: impl FnMut() -> Duration,
    ) -> Result<WorkerPermit, usize> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            let remaining = remaining();
            if remaining.is_zero() {
                return Err(self.limit);
            }
            if *active < self.limit {
                *active += 1;
                return Ok(WorkerPermit(Arc::clone(self)));
            }
            let (next, _) = self
                .available
                .wait_timeout(active, remaining)
                .unwrap_or_else(|error| error.into_inner());
            active = next;
        }
    }
}

pub(crate) struct WorkerPermit(Arc<WorkerGate>);

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut active = self
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *active -= 1;
        self.0.available.notify_all();
    }
}
