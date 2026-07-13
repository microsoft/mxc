// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared test helpers for `filesystem_overlay`. Mirrors the pattern
//! in `filesystem_dacl`'s test module: a process-global mutex around
//! `MXC_OVERLAY_STATE_DIR` mutation, plus an RAII `ScopedStateDir`
//! that holds the mutex for the duration of a test and points the
//! env var at a fresh tempdir.
//!
//! `cargo test` runs tests in parallel by default; without this
//! mutex, concurrent ScopedStateDirs would clobber each other's
//! env-var setting and recovery tests would non-deterministically
//! see the wrong state directory.

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Process-global mutex serializing all tests that depend on the
/// `MXC_OVERLAY_STATE_DIR` override. `std::env::set_var` is not
/// thread-safe in the presence of concurrent C `getenv` callers, so
/// we hold this for the entire duration of any test that touches
/// the override.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// RAII helper that points `MXC_OVERLAY_STATE_DIR` at a fresh
/// tempdir for the test's lifetime, then restores the previous
/// value on drop. Holds [`env_lock`] for its lifetime so concurrent
/// tests serialize cleanly.
pub(crate) struct ScopedStateDir {
    _lock: MutexGuard<'static, ()>,
    _td: tempfile::TempDir,
    prev: Option<OsString>,
}

impl ScopedStateDir {
    pub(crate) fn new() -> Self {
        let lock = env_lock();
        let td = tempfile::tempdir().expect("create tempdir");
        let prev = std::env::var_os("MXC_OVERLAY_STATE_DIR");
        std::env::set_var("MXC_OVERLAY_STATE_DIR", td.path());
        Self {
            _lock: lock,
            _td: td,
            prev,
        }
    }
}

impl Drop for ScopedStateDir {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("MXC_OVERLAY_STATE_DIR", v),
            None => std::env::remove_var("MXC_OVERLAY_STATE_DIR"),
        }
    }
}
