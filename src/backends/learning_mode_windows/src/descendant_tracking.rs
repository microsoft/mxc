// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Descendant-tracking Job Object for the learning-mode feature.
//!
//! # Why this exists
//!
//! ETW's `EVENT_FILTER_TYPE_PID` filter does not follow descendants
//! of the filtered process. A workload that spawns children
//! (`cargo build`, `npm run`, `cmd /c …`) escapes the ETW filter
//! and its denials never reach the consumer. The summary line
//! reports `childProcessesObserved` so the SDK can warn the user,
//! but the denials themselves are lost.
//!
//! This module is the first piece of the fix. It wraps the workload
//! in a Job Object with the breakaway-OK limit **unset**, which
//! means:
//!
//! - The kernel kills any descendant that tries to escape the job
//!   with `CREATE_BREAKAWAY_FROM_JOB`.
//! - Descendants of the workload are automatically members of the
//!   same job (kernel-enforced; no race window between spawn and
//!   assignment).
//! - We can later subscribe to `JOB_OBJECT_MSG_NEW_PROCESS`
//!   notifications (via `JOBOBJECT_ASSOCIATE_COMPLETION_PORT`) or
//!   to the `Microsoft-Windows-Kernel-Process` ETW provider
//!   filtered on job membership, and extend the ETW PID filter
//!   to include each new descendant. That's Phase B of the
//!   descendant-tracking work; this module is just the plumbing.
//!
//! # Lifetime / ownership
//!
//! The runner creates a `DescendantTrackingJob`, calls
//! [`DescendantTrackingJob::attach_root`] with the workload's
//! process handle before resuming the (suspended) workload, and
//! then drops the job on its own scope exit. Once a process is
//! assigned to a job the kernel keeps it there for the process
//! lifetime regardless of whether the job HANDLE is still open in
//! the creator — so dropping the wrapper does not relax the
//! restrictions on the running workload or its descendants.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};

use crate::session::SessionError;

/// RAII wrapper around an anonymous Job Object used to scope the
/// learning-mode capture to a sandbox-tree (root workload +
/// descendants).
///
/// See the module-level docs for the design rationale.
pub struct DescendantTrackingJob {
    handle: HANDLE,
}

impl DescendantTrackingJob {
    /// Create a fresh, anonymous, unrestricted Job Object.
    ///
    /// The job has no limits set on construction; in particular,
    /// `JOB_OBJECT_LIMIT_BREAKAWAY_OK` is **unset** (the default),
    /// which is exactly what we want — descendants of a process in
    /// the job cannot escape via `CREATE_BREAKAWAY_FROM_JOB`.
    pub fn new() -> Result<Self, SessionError> {
        // SAFETY: CreateJobObjectW with NULL security attributes and
        // NULL name returns an unnamed job HANDLE owned by the caller.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| SessionError::JobObject(format!("CreateJobObjectW: {e}")))?;
        Ok(Self { handle })
    }

    /// Assign the root workload to the job.
    ///
    /// Must be called while the workload is suspended (the
    /// captureDenials flow already spawns `CREATE_SUSPENDED` so this
    /// happens before any user code runs). Once assigned, every
    /// descendant the workload spawns is automatically a member of
    /// the same job.
    ///
    /// # Safety
    ///
    /// `process_handle` must be a valid Win32 process handle with
    /// `PROCESS_SET_QUOTA | PROCESS_TERMINATE` access (the standard
    /// `PROCESS_INFORMATION.hProcess` from `CreateProcess*` already
    /// has both).
    pub fn attach_root(&self, process_handle: HANDLE) -> Result<(), SessionError> {
        // SAFETY: caller guarantees `process_handle` is a valid
        // handle with the required access mask. `self.handle` was
        // produced by `CreateJobObjectW`.
        unsafe { AssignProcessToJobObject(self.handle, process_handle) }
            .map_err(|e| SessionError::JobObject(format!("AssignProcessToJobObject: {e}")))
    }

    /// Returns the underlying job HANDLE. Used by Phase B (ETW
    /// process-start subscription) and Phase C (completion port for
    /// `JOB_OBJECT_MSG_NEW_PROCESS`). For now no consumer needs it.
    #[allow(dead_code)]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for DescendantTrackingJob {
    fn drop(&mut self) {
        // SAFETY: `self.handle` was produced by `CreateJobObjectW`
        // and has not been closed elsewhere — `DescendantTrackingJob`
        // owns it. The kernel keeps the job alive as long as a
        // process is still assigned to it, even after the HANDLE is
        // closed, so dropping here does not relax the restrictions
        // on the running workload.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// SAFETY: a Win32 HANDLE is just a kernel-object pointer; sharing it
// across threads is safe as long as the Win32 APIs that consume it
// are themselves thread-safe (they are, for the calls we make:
// `AssignProcessToJobObject`, `CloseHandle`).
unsafe impl Send for DescendantTrackingJob {}
unsafe impl Sync for DescendantTrackingJob {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_drop_is_clean() {
        let job = DescendantTrackingJob::new().expect("create");
        assert!(!job.handle().is_invalid());
        drop(job);
    }
}
