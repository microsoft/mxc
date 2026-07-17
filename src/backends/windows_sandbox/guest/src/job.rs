//! Job Object helper for terminating a script's process tree.
//!
//! Job membership survives the immediate child's exit, avoiding the PID-reuse
//! and broken-tree limitations of a later `taskkill /T`. Assignment remains
//! best-effort, so the caller also bounds stdio drain time.

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

    /// Assign a process to this job.
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

    /// Terminate every process currently in the job.
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

    #[test]
    fn job_terminates_assigned_process_tree() {
        let job = Job::new().expect("create job");

        let mut child = Command::new("cmd.exe")
            .args(["/C", "ping -n 999 127.0.0.1 >nul"])
            .spawn()
            .expect("spawn child");
        job.assign(child.id()).expect("assign child to job");

        job.terminate();

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

    #[test]
    fn assign_dead_pid_errors_not_panics() {
        let job = Job::new().expect("create job");
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit 0"])
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        child.wait().expect("wait");
        let _ = job.assign(pid);
    }
}
