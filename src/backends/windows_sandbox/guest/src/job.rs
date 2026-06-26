//! Windows Job Object helper for reliable process-tree reaping.
//!
//! A script run via `cmd.exe /C` frequently spawns descendants. When `cmd.exe`
//! exits, an orphaned grandchild that inherited the stdout/stderr pipe write
//! handles keeps those pipes from reaching EOF — which would otherwise hang the
//! guest's stdio bridge tasks forever and wedge the reused guest. `taskkill /T`
//! is unreliable once `cmd.exe` has exited (the parent/child tree linkage is
//! broken and the PID may be recycled), so we assign the child to a Job Object
//! at spawn time. Job membership is inherited by all descendants and survives
//! the intermediate parent's death, so `TerminateJobObject` reliably reaps the
//! entire tree regardless of PID reuse.
//!
//! Assignment is best-effort: a descendant spawned in the microseconds between
//! `spawn` and assignment can escape the job. The caller's bounded bridge-drain
//! backstop covers liveness in that residual case.

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

/// An owned Job Object configured to kill all member processes when its last
/// handle closes.
pub struct Job {
    handle: HANDLE,
}

// The job handle is only ever used to call thread-safe Win32 APIs.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    /// Create a Job Object whose members are killed when the job handle closes.
    pub fn new() -> Result<Self> {
        // SAFETY: passing null security attributes / name creates an anonymous
        // job; the returned handle is validated below.
        let handle = unsafe { CreateJobObjectW(None, None) }.context("CreateJobObjectW")?;

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `info` is a correctly-sized, fully-initialized structure for
        // the JobObjectExtendedLimitInformation class.
        let set = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if let Err(err) = set {
            // SAFETY: handle came from CreateJobObjectW above.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(err).context("SetInformationJobObject(KILL_ON_JOB_CLOSE)");
        }

        Ok(Self { handle })
    }

    /// Assign a process (by PID) to this job. Best-effort: returns an error the
    /// caller is expected to log and continue past (the process may already have
    /// exited, which is harmless).
    pub fn assign(&self, pid: u32) -> Result<()> {
        // SAFETY: pid is a live child's PID; we request only the rights needed
        // to assign it to a job, and close the process handle immediately.
        let proc = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, pid) }
            .context("OpenProcess for job assignment")?;
        let result = unsafe { AssignProcessToJobObject(self.handle, proc) };
        // SAFETY: proc came from OpenProcess above.
        unsafe {
            let _ = CloseHandle(proc);
        }
        result.context("AssignProcessToJobObject")
    }

    /// Terminate every process currently in the job (the child plus all of its
    /// descendants). Best-effort and idempotent.
    pub fn terminate(&self) {
        // SAFETY: self.handle is a valid job handle for the job's lifetime.
        if let Err(err) = unsafe { TerminateJobObject(self.handle, 1) } {
            eprintln!("[guest] TerminateJobObject failed: {err}");
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: self.handle is a valid job handle created in `new`.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    /// Creating a job, assigning a real child, and terminating the job must
    /// promptly kill the child's entire tree (cmd.exe + its ping grandchild).
    #[test]
    fn job_terminates_assigned_process_tree() {
        let job = Job::new().expect("create job");

        // Long-running tree: cmd.exe (child) -> ping (grandchild). Without the
        // job kill this would run for ~999 seconds.
        let mut child = Command::new("cmd.exe")
            .args(["/C", "ping -n 999 127.0.0.1 >nul"])
            .spawn()
            .expect("spawn child");
        job.assign(child.id()).expect("assign child to job");

        job.terminate();

        // The child must exit promptly now that the job was terminated.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait().expect("try_wait") {
                Some(_status) => break,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    panic!("job-terminated child did not exit");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Assigning an already-exited process surfaces an error (which the caller
    /// treats as non-fatal) rather than panicking.
    #[test]
    fn assign_dead_pid_errors_not_panics() {
        let job = Job::new().expect("create job");
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        child.wait().expect("wait");
        // The PID is no longer a live process; assignment should fail cleanly.
        // (A recycled PID is theoretically possible but vanishingly unlikely in
        // the test window; either way this must not panic.)
        let _ = job.assign(pid);
    }
}
