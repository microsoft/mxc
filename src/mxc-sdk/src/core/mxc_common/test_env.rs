//! Crate-wide test-only serialization for environment-variable mutation.
//!
//! Both `mxc_common` and backend test guards use this lock because all
//! `mxc-sdk` unit tests now run in the same test binary.

use std::sync::{Mutex, MutexGuard};

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock() -> MutexGuard<'static, ()> {
    // Poison is irrelevant here: the env var is restored on Drop
    // regardless of whether a previous holder panicked, and the lock's
    // only purpose is to serialize accesses.
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}
