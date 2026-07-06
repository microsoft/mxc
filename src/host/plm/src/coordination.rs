// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-process coordination primitives shared by `plm.exe` and the
//! `wxc-exec --audit` driver in the `wxc` crate. Centralises the
//! singleton bypass env-var name and the `wait_until_cleared` ctrl-
//! handler helper so the two binaries cannot drift apart and can both
//! exercise the same tested implementation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Set to `true` while a standalone `plm log` invocation is spawning
/// `wpr -start` and has not yet returned. Read by `plm.exe`'s console-
/// control handler so a Ctrl+C arriving in the spawn window is
/// bounded-waited for, instead of issuing `wpr -cancel` against a
/// not-yet-engaged kernel session and leaking it. Lifted into the
/// shared library (rather than living as a `static` inside
/// `plm/src/main.rs`) so the `log` module can flip it directly
/// without a callback round-trip.
pub static PLM_LOG_START_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Maximum time either console-control handler will wait on its
/// in-flight flag (`AUDIT_START_IN_FLIGHT` in `wxc-exec`,
/// `PLM_LOG_START_IN_FLIGHT` in `plm.exe`) before falling through to
/// `wpr -cancel`. Shared between `wxc-exec`'s `dacl_ctrl_handler`
/// (which runs TWO bounded waits back-to-back — the DACL `try_lock`
/// drain and the `wait_until_cleared` call) and `plm.exe`'s
/// `plm_ctrl_handler` so the two binaries cannot drift apart.
/// Lifting the constant here makes drift a compile-time impossibility.
///
/// The 2s budget is chosen so the combined budget of the wxc-exec
/// handler (`2 * CTRL_HANDLER_DRAIN_TIMEOUT`) stays under the
/// ~5s OS-imposed kill budget for `CTRL_CLOSE_EVENT` /
/// `CTRL_LOGOFF_EVENT` / `CTRL_SHUTDOWN_EVENT`, with ~500ms of
/// slack for the actual `wpr -cancel` spawn. Pinned by
/// `tests::ctrl_handler_drain_timeout_respects_os_budget`.
pub const CTRL_HANDLER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Env var set by `wxc-exec --audit` before spawning `plm.exe`. When
/// present, the spawned `plm` binary skips its own singleton mutex
/// acquisition because the outer `wxc-exec` already holds it for the
/// whole audit window. Avoids a deadlock between parent and child on
/// the same `Global\Mxc_Plm_Audit` name.
///
/// NOTE: kept as a signalling path for tests and for direct callers
/// that inherit env normally, but `wxc-exec --audit` itself no longer
/// uses it — `ShellExecuteExW` + `runas` does not propagate the
/// caller's environment block across the elevation boundary, so
/// wxc-exec passes the bypass signal as a hidden CLI flag instead
/// and `main.rs` calls `set_singleton_bypass_override(true)` from
/// clap. See `singleton_bypass_requested`.
pub const SINGLETON_HELD_BY_PARENT_ENV: &str = "MXC_PLM_AUDIT_SINGLETON_HELD";

/// Process-wide override for `singleton_bypass_requested`, populated
/// from the hidden `--wxc-singleton-held-by-parent` CLI flag in
/// `plm.exe`'s `main`. Needed because `ShellExecuteExW` + `runas`
/// (the elevation path used by `wxc-exec --audit`) creates the
/// elevated child with a fresh environment block for the elevated
/// token, so the env-var signalling path cannot reach us.
static SINGLETON_BYPASS_OVERRIDE: AtomicBool = AtomicBool::new(false);

/// Set the process-wide singleton-bypass override. Called from
/// `plm.exe`'s `main` after clap parses the hidden
/// `--wxc-singleton-held-by-parent` flag that `wxc-exec` passes when
/// it spawns us elevated.
pub fn set_singleton_bypass_override(v: bool) {
    SINGLETON_BYPASS_OVERRIDE.store(v, Ordering::SeqCst);
}

/// True when the audit-driving parent process has signalled that it
/// already holds the `Global\Mxc_Plm_Audit` singleton and this child
/// should skip acquisition. Reads both the env var (legacy path,
/// still honoured for direct callers and tests) and the CLI-driven
/// override.
pub fn singleton_bypass_requested() -> bool {
    SINGLETON_BYPASS_OVERRIDE.load(Ordering::SeqCst)
        || std::env::var_os(SINGLETON_HELD_BY_PARENT_ENV).is_some()
}

/// Spin until `flag` reads `false`, or `timeout` elapses. Polls every
/// `poll_interval`. Returns `true` if the flag cleared in time,
/// `false` on timeout.
///
/// Used by both `wxc-exec`'s `dacl_ctrl_handler` (waiting for `plm
/// start` to drain before issuing `wpr -cancel`) and `plm.exe`'s
/// `plm_ctrl_handler`.
pub fn wait_until_cleared(flag: &AtomicBool, timeout: Duration, poll_interval: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while flag.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(poll_interval);
    }
    true
}

/// Windows-only shared implementation of the `Global\Mxc_Plm_Audit`
/// named-mutex singleton. Both `plm.exe` and `wxc-exec --audit`
/// serialize on the same name so two concurrent PLM traces can't share
/// the single NT Kernel Logger session.
#[cfg(target_os = "windows")]
pub mod singleton {
    use std::sync::atomic::{AtomicIsize, Ordering};

    /// Outcome of `try_acquire`. Callers translate to their own error
    /// type (anyhow / String / etc).
    pub enum AcquireError {
        /// Another process already holds the singleton mutex.
        AlreadyHeld,
        /// `CreateMutexW` failed for a non-conflict reason.
        CreateFailed(windows::core::Error),
    }

    /// Attempt to acquire the host-wide PLM audit mutex, stashing the
    /// raw handle in `slot` so both `Drop`-based release and the
    /// pre-`ExitProcess` cleanup can find it.
    ///
    /// Uses the `CreateMutexW` + `WaitForSingleObject(0)` two-step
    /// pattern rather than `CreateMutexW(bInitialOwner=true)` so we
    /// correctly detect the "previous owner crashed without
    /// releasing" case (Windows surfaces this as `WAIT_ABANDONED_0`
    /// on the wait, never on the create). Treating an abandoned
    /// mutex as `AlreadyHeld` would leave a stale singleton forever
    /// after any PLM crash and force operators to reboot; we instead
    /// take ownership silently, since the abandoned wpr session (if
    /// any) is torn down separately by the caller's normal cancel
    /// path.
    pub fn try_acquire(slot: &AtomicIsize) -> Result<(), AcquireError> {
        use windows::core::w;
        use windows::Win32::Foundation::{
            CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};

        let name = w!("Global\\Mxc_Plm_Audit");
        // Open (or create) the named mutex without requesting initial
        // ownership; ownership is acquired via the wait below so we
        // can distinguish "someone else holds it" from "previous
        // owner crashed and we now own the abandoned mutex".
        let handle =
            unsafe { CreateMutexW(None, false, name) }.map_err(AcquireError::CreateFailed)?;
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        match wait {
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                // We now own the mutex (either freshly or by
                // inheriting an abandoned one).
                slot.store(handle.0 as isize, Ordering::SeqCst);
                Ok(())
            }
            WAIT_TIMEOUT => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Err(AcquireError::AlreadyHeld)
            }
            other => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                // Prefer the OS's last-error (set by WAIT_FAILED);
                // fall back to encoding the raw wait return as an
                // HRESULT for exotic values.
                let thread_err = windows::core::Error::from_thread();
                Err(AcquireError::CreateFailed(if thread_err.code().is_err() {
                    thread_err
                } else {
                    windows::core::Error::from_hresult(windows::core::HRESULT(other.0 as i32))
                }))
            }
        }
    }

    /// Release the singleton if `slot` holds a live handle. Idempotent:
    /// safe to call from `Drop`, from explicit pre-`process::exit`
    /// cleanup, and from error paths.
    pub fn release(slot: &AtomicIsize) {
        let raw = slot.swap(0, Ordering::SeqCst);
        if raw != 0 {
            let handle = windows::Win32::Foundation::HANDLE(raw as *mut _);
            unsafe {
                let _ = windows::Win32::System::Threading::ReleaseMutex(handle);
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ---- singleton bypass ------------------------------------------------
    //
    // The env-var lookup is process-global, so multiple tests racing
    // on it would interfere. Serialise them with a module-local mutex.
    // (We can't use `serial_test` without pulling in a new dep, and a
    // bespoke mutex is sufficient for these two tests.)
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn singleton_bypass_requested_returns_false_when_env_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: the lock above serializes env mutation within this
        // test binary. Other test binaries can't see this env var
        // (Cargo runs each integration test in its own process), and
        // production callers always inherit it from wxc-exec.
        std::env::remove_var(SINGLETON_HELD_BY_PARENT_ENV);
        assert!(!singleton_bypass_requested());
    }

    #[test]
    fn singleton_bypass_requested_returns_true_when_env_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var(SINGLETON_HELD_BY_PARENT_ENV, "1");
        let observed = singleton_bypass_requested();
        std::env::remove_var(SINGLETON_HELD_BY_PARENT_ENV);
        assert!(observed);
    }

    // the bypass also fires for any non-empty
    // value (Windows env "0" is still set), so the parent only needs
    // the env var to be present, not equal to "1". Pin that contract
    // so a future refactor doesn't tighten the check.
    #[test]
    fn singleton_bypass_requested_returns_true_for_any_value() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var(SINGLETON_HELD_BY_PARENT_ENV, "");
        let observed_empty = singleton_bypass_requested();
        std::env::set_var(SINGLETON_HELD_BY_PARENT_ENV, "0");
        let observed_zero = singleton_bypass_requested();
        std::env::remove_var(SINGLETON_HELD_BY_PARENT_ENV);
        assert!(observed_empty, "empty string should still count as set");
        assert!(observed_zero, "\"0\" should still count as set");
    }

    // ---- ctrl-handler drain budget --------------------------------------

    // Pin the OS-budget invariant. Windows imposes a hard ~5s kill
    // timer on `CTRL_CLOSE_EVENT` / `CTRL_LOGOFF_EVENT` /
    // `CTRL_SHUTDOWN_EVENT` handlers. The wxc-exec handler runs two
    // back-to-back bounded waits each capped at
    // `CTRL_HANDLER_DRAIN_TIMEOUT`, so `2 * CTRL_HANDLER_DRAIN_TIMEOUT`
    // must stay under that budget with some slack for the actual
    // `wpr -cancel` spawn that follows. A future bump to >2s
    // reintroduces the ETW-session leak silently — this test fails
    // the build instead.
    #[test]
    fn ctrl_handler_drain_timeout_respects_os_budget() {
        let combined = CTRL_HANDLER_DRAIN_TIMEOUT
            .checked_mul(2)
            .expect("2 * timeout overflows");
        assert!(
            combined <= Duration::from_millis(4500),
            "2 * CTRL_HANDLER_DRAIN_TIMEOUT ({combined:?}) must stay under \
             the ~5s OS kill budget for CTRL_CLOSE/LOGOFF/SHUTDOWN, with \
             ~500ms slack for `wpr -cancel` to spawn"
        );
    }

    // ---- wait_until_cleared ---------------------------------------------

    #[test]
    fn wait_until_cleared_returns_true_when_flag_already_false() {
        let flag = AtomicBool::new(false);
        let started = Instant::now();
        assert!(wait_until_cleared(
            &flag,
            Duration::from_secs(5),
            Duration::from_millis(10)
        ));
        // Should be effectively instantaneous (well under the timeout).
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "no-wait path must not sleep"
        );
    }

    #[test]
    fn wait_until_cleared_returns_false_on_timeout() {
        let flag = AtomicBool::new(true);
        let started = Instant::now();
        let result =
            wait_until_cleared(&flag, Duration::from_millis(150), Duration::from_millis(20));
        assert!(!result, "timeout must surface as false");
        // Allow generous CI scheduling slop: must wait at least the
        // timeout, but not wildly longer.
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(140),
            "must wait at least the timeout, waited {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "must not vastly exceed the timeout, waited {elapsed:?}"
        );
    }

    #[test]
    fn wait_until_cleared_returns_true_when_flag_clears_mid_wait() {
        let flag = Arc::new(AtomicBool::new(true));
        let writer_flag = Arc::clone(&flag);
        // Clear the flag from a background thread after ~50ms; the
        // wait should observe the change and return true well before
        // the 5s timeout.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            writer_flag.store(false, Ordering::SeqCst);
        });
        let started = Instant::now();
        let result = wait_until_cleared(&flag, Duration::from_secs(5), Duration::from_millis(10));
        assert!(result, "flag clearing mid-wait must surface as true");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must observe the clear well before the timeout"
        );
    }
}
