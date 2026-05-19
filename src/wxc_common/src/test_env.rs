//! Shared test-only helpers for env-var serialization across modules.
//!
//! The dispatcher tier-selection tests and the fallback-detector probe
//! tests both mutate `MXC_FORCE_TIER` (which is process-global). Each
//! module previously owned its own private `ENV_LOCK`, but that meant
//! a `fallback_detector::tests` thread and a `dispatcher::tests` thread
//! could mutate the same env var concurrently — observable as a race
//! once both test families started running under the same profile
//! (cfg(test), any profile).
//!
//! This module exposes a single shared `ENV_LOCK` that all test
//! modules in this crate take before touching the relevant env vars.
//! Hold the guard for the entire duration of the env-var-dependent
//! work so the value remains stable across the call. The provided
//! `ForceTierGuard` type encapsulates the set / clear discipline.
//!
//! Compiled in only under `#[cfg(test)]`.

use std::sync::{Mutex, MutexGuard};

/// Process-wide serialization for tests that mutate test-seam env
/// vars. Tests in any module in this crate should acquire this lock
/// (typically via [`ForceTierGuard`]) before reading or writing
/// `MXC_FORCE_TIER`.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    // Poison is irrelevant here: the env var is restored on Drop
    // regardless of whether a previous holder panicked, and the lock's
    // only purpose is to serialize accesses.
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// RAII guard that sets `MXC_FORCE_TIER` to `value` for the lifetime
/// of the guard and restores it on `Drop`. Acquires [`ENV_LOCK`]
/// internally so concurrent guards serialize.
///
/// Holding the lock *inside* the struct ensures the env-var clear in
/// `Drop` happens before the lock is released — preventing a follow-up
/// thread from observing the stale value.
pub(crate) struct ForceTierGuard {
    _lock: MutexGuard<'static, ()>,
}

impl ForceTierGuard {
    pub(crate) fn set(value: &str) -> Self {
        let guard = lock();
        // SAFETY: env-var mutation is gated by ENV_LOCK; no other
        // ForceTierGuard can be active concurrently.
        unsafe {
            std::env::set_var("MXC_FORCE_TIER", value);
        }
        ForceTierGuard { _lock: guard }
    }
}

impl Drop for ForceTierGuard {
    fn drop(&mut self) {
        // SAFETY: serialized by ENV_LOCK still held in `_lock`; the
        // lock is released only after this `Drop` returns.
        unsafe {
            std::env::remove_var("MXC_FORCE_TIER");
        }
    }
}

/// RAII helper that points `MXC_DACL_STATE_DIR` at a freshly created
/// tempdir for the duration of a test, then restores the previous
/// value on drop. Holds [`ENV_LOCK`] for its lifetime via [`lock`],
/// which serializes all env-var-touching tests within the process.
///
/// Lives here (rather than in `filesystem_dacl::tests`) so it shares
/// `ENV_LOCK` with [`ForceTierGuard`]. Without
/// the shared lock, a `filesystem_dacl` test could delete its tempdir
/// while a concurrent `dispatcher` test was mid-write to the same
/// path (the dispatcher test reads `MXC_DACL_STATE_DIR` through
/// `state_dir()` inside `DaclManager::new()` and would race the
/// `Drop` on the other test's `ScopedStateDir`).
pub(crate) struct ScopedStateDir {
    _lock: MutexGuard<'static, ()>,
    _td: tempfile::TempDir,
    prev: Option<std::ffi::OsString>,
}

impl ScopedStateDir {
    pub(crate) fn new() -> Self {
        let guard = lock();
        let td = tempfile::tempdir().expect("create tempdir");
        let prev = std::env::var_os("MXC_DACL_STATE_DIR");
        // SAFETY: serialized by ENV_LOCK; see ForceTierGuard::set.
        unsafe {
            std::env::set_var("MXC_DACL_STATE_DIR", td.path());
        }
        Self {
            _lock: guard,
            _td: td,
            prev,
        }
    }
}

impl Drop for ScopedStateDir {
    fn drop(&mut self) {
        // SAFETY: serialized by ENV_LOCK still held in `_lock`.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var("MXC_DACL_STATE_DIR", v),
                None => std::env::remove_var("MXC_DACL_STATE_DIR"),
            }
        }
    }
}
