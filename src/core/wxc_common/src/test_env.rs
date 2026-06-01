//! Test-only helper for env-var serialization used by `filesystem_dacl`
//! tests.
//!
//! Each crate has its own `ENV_LOCK` because env-var contention is
//! only observable within a single test binary. The richer
//! `ForceTierGuard` / `BfscfgPathGuard` helpers live next to their
//! consumers in `appcontainer_common::test_env`.

use std::sync::{Mutex, MutexGuard};

pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, ()> {
    // Poison is irrelevant here: the env var is restored on Drop
    // regardless of whether a previous holder panicked, and the lock's
    // only purpose is to serialize accesses.
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// RAII helper that points `MXC_DACL_STATE_DIR` at a freshly created
/// tempdir for the duration of a test, then restores the previous
/// value on drop. Holds [`ENV_LOCK`] for its lifetime via [`lock`],
/// which serializes all env-var-touching tests within the process.
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
        // SAFETY: env-var mutation is gated by ENV_LOCK; no other
        // ScopedStateDir can be active concurrently.
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
