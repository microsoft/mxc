// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-process coordination primitives shared by `plm.exe` and the
//! `wxc-exec --audit` driver.

use std::time::Duration;

/// Maximum time the wxc-exec console-control handler waits to acquire
/// the DACL cleanup slot before allowing Windows to terminate the process.
/// The persistent elevated PLM child observes owner death independently.
pub const CTRL_HANDLER_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Windows-only shared implementation of the `Global\Mxc_Plm_Audit`
/// named-mutex singleton. Both `plm.exe` and `wxc-exec --audit`
/// serialize on the same name so two concurrent PLM traces can't share
/// the single NT Kernel Logger session.
#[cfg(target_os = "windows")]
pub mod singleton {
    use std::sync::atomic::{AtomicIsize, Ordering};
    use windows::Win32::Foundation::HANDLE;

    /// Distinguishes a fresh acquisition from ownership inherited after
    /// the previous process terminated while holding the mutex.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AcquireOutcome {
        Acquired,
        Abandoned,
    }

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
    pub fn try_acquire(slot: &AtomicIsize) -> Result<AcquireOutcome, AcquireError> {
        use windows::core::w;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::CreateMutexW;

        let name = w!("Global\\Mxc_Plm_Audit");
        // Open (or create) the named mutex without requesting initial
        // ownership; ownership is acquired via the wait below so we
        // can distinguish "someone else holds it" from "previous
        // owner crashed and we now own the abandoned mutex".
        let handle =
            unsafe { CreateMutexW(None, false, name) }.map_err(AcquireError::CreateFailed)?;
        match try_acquire_handle(handle) {
            Ok(outcome) => {
                slot.store(handle.0 as isize, Ordering::SeqCst);
                Ok(outcome)
            }
            Err(error) => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Err(error)
            }
        }
    }

    /// Keeps the named mutex object alive while another process owns it.
    ///
    /// The guarded elevated child opens this before WPR starts. If its owner
    /// later dies, either this observer or a replacement audit process wins
    /// the abandoned-mutex acquisition and performs stale-session cleanup.
    pub struct Observer {
        handle: HANDLE,
    }

    impl Observer {
        pub fn open() -> Result<Self, AcquireError> {
            use windows::core::w;
            use windows::Win32::System::Threading::CreateMutexW;

            let handle = unsafe { CreateMutexW(None, false, w!("Global\\Mxc_Plm_Audit")) }
                .map_err(AcquireError::CreateFailed)?;
            Ok(Self { handle })
        }

        pub fn try_acquire(&self) -> Result<AcquireOutcome, AcquireError> {
            try_acquire_handle(self.handle)
        }

        pub fn release(&self) {
            unsafe {
                let _ = windows::Win32::System::Threading::ReleaseMutex(self.handle);
            }
        }
    }

    impl Drop for Observer {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.handle);
            }
        }
    }

    fn try_acquire_handle(handle: HANDLE) -> Result<AcquireOutcome, AcquireError> {
        use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;

        match unsafe { WaitForSingleObject(handle, 0) } {
            WAIT_OBJECT_0 => Ok(AcquireOutcome::Acquired),
            WAIT_ABANDONED => Ok(AcquireOutcome::Abandoned),
            WAIT_TIMEOUT => Err(AcquireError::AlreadyHeld),
            other => {
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

    // ---- ctrl-handler drain budget --------------------------------------

    // Pin the OS-budget invariant. Windows imposes a hard ~5s kill
    // timer on `CTRL_CLOSE_EVENT` / `CTRL_LOGOFF_EVENT` /
    // `CTRL_SHUTDOWN_EVENT` handlers, so the DACL cleanup wait must
    // remain comfortably below that budget.
    #[test]
    fn ctrl_handler_drain_timeout_respects_os_budget() {
        assert!(
            CTRL_HANDLER_DRAIN_TIMEOUT <= Duration::from_millis(4500),
            "CTRL_HANDLER_DRAIN_TIMEOUT ({CTRL_HANDLER_DRAIN_TIMEOUT:?}) must stay under \
             the ~5s OS kill budget for CTRL_CLOSE/LOGOFF/SHUTDOWN"
        );
    }
}
