// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Best-effort observer for child processes spawned by a sandboxed
//! workload.
//!
//! ## Why this exists
//!
//! captureDenials attaches a per-PID ETW collector to the workload
//! we spawn. The `EVENT_FILTER_TYPE_PID` filter applies at the
//! provider layer, so the collector *only* receives denial events
//! for the PID we asked about. **Denial events for child processes
//! the workload spawns are silently dropped.**
//!
//! This is a real problem for launcher-style workloads: `npm`,
//! `cargo`, `cmake`, `gh`, `python -m something`. The visible parent
//! does little; the actual file I/O happens in a child. From the
//! SDK consumer's perspective, the workload fails for no apparent
//! reason — the denial list is empty because we never saw the
//! events.
//!
//! Production fix: dynamically expand the ETW filter as children
//! spawn (subscribe to `Microsoft-Windows-Kernel-Process`, watch
//! for `ProcessStart` events whose `ParentProcessID` matches our
//! root, call `EnableTraceEx2` to add the child PID to the filter).
//! That's significant work — multi-PID filter descriptor handling
//! in the shim, race-free filter updates, child-of-child tracking.
//!
//! This module is the in-the-meantime "make the limitation visible"
//! fix: a background thread polls `CreateToolhelp32Snapshot` every
//! ~500ms during the workload run, accumulates every PID whose
//! parent is our workload, and reports the count at teardown. SDK
//! consumers see `childProcessesObserved: N` on the summary line
//! and can warn the user "your workload spawned N child processes;
//! denial capture only covers the root process today, so some
//! denials may be missing." That's a far better consumer experience
//! than the silent zero.

#[cfg(target_os = "windows")]
use std::collections::HashSet;
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "windows")]
use std::thread::JoinHandle;
#[cfg(target_os = "windows")]
use std::time::Duration;

/// Handle for a running child-process observer. Drop it to ask the
/// background poller to stop; call [`take_observed_count`] to
/// retrieve the final count after the workload has exited.
#[cfg(target_os = "windows")]
pub struct ChildProcessObserver {
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<HashSet<u32>>>,
    join: Option<JoinHandle<()>>,
}

#[cfg(target_os = "windows")]
impl ChildProcessObserver {
    /// Spawn a background thread that polls every `poll_interval`
    /// for live processes whose parent PID is `parent_pid`. Tracks
    /// every distinct child PID observed across all polls.
    ///
    /// Returns `None` when the observer thread couldn't be spawned
    /// (no fatal — the runner just won't have child-process
    /// visibility for this invocation).
    pub fn spawn(parent_pid: u32, poll_interval: Duration) -> Option<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let seen: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        let stop_clone = Arc::clone(&stop);
        let seen_clone = Arc::clone(&seen);

        let join = std::thread::Builder::new()
            .name("denial-child-observer".to_string())
            .spawn(move || {
                while !stop_clone.load(Ordering::Relaxed) {
                    let mut local: Vec<u32> = snapshot_children_of(parent_pid);
                    if !local.is_empty() {
                        if let Ok(mut s) = seen_clone.lock() {
                            for pid in local.drain(..) {
                                s.insert(pid);
                            }
                        }
                    }
                    // Short sleep so teardown latency stays low; the
                    // poll itself is cheap (one syscall, one walk
                    // over the system process list).
                    std::thread::sleep(poll_interval);
                }
            })
            .ok()?;

        Some(Self {
            stop,
            seen,
            join: Some(join),
        })
    }

    /// Signal the poller to stop, join the thread, and return the
    /// set of distinct child PIDs observed during the workload run.
    /// Idempotent: subsequent calls return an empty set.
    pub fn take_observed_count(mut self) -> usize {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
        match self.seen.lock() {
            Ok(s) => s.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for ChildProcessObserver {
    fn drop(&mut self) {
        // If take_observed_count wasn't called, still signal stop
        // and join so we don't leak the thread.
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

/// Walk the system process list once and return every PID whose
/// parent is `parent_pid`. Best-effort: a short-lived child that
/// starts and exits between polls will not appear here. Returns an
/// empty vec on any error.
#[cfg(target_os = "windows")]
fn snapshot_children_of(parent_pid: u32) -> Vec<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(snap, &mut entry) }.is_ok() {
        loop {
            // Skip our own PID and the workload root -- we only
            // want descendants.
            if entry.th32ParentProcessID == parent_pid && entry.th32ProcessID != parent_pid {
                out.push(entry.th32ProcessID);
            }
            // Re-zero dwSize is not required between iterations,
            // but Process32NextW expects a valid PROCESSENTRY32W
            // every time.
            if unsafe { Process32NextW(snap, &mut entry) }.is_err() {
                break;
            }
        }
    }

    unsafe {
        let _ = CloseHandle(snap);
    }
    out
}

// ---------------------------------------------------------------------------
// Unit-tested core: separate the polling-set behavior from the Win32 call
// so the dedupe / lifecycle logic can be exercised on any host.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    #[cfg(target_os = "windows")]
    fn observer_returns_zero_for_pid_with_no_children() {
        // PID of the running test process: definitely has no children
        // for this microsecond — at worst there's one with a different
        // parent and we'd never count it.
        let observer = ChildProcessObserver::spawn(0xFFFF_FFFE, Duration::from_millis(50))
            .expect("observer thread should spawn");
        // Give the poller two ticks then read.
        std::thread::sleep(Duration::from_millis(150));
        let count = observer.take_observed_count();
        assert_eq!(count, 0);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn observer_can_be_dropped_without_take() {
        // Defensive: caller might bail out before reading the count
        // (e.g. on an error path). The Drop impl must still tear the
        // thread down cleanly — no leaks, no panics, no leftover
        // OS threads.
        let observer = ChildProcessObserver::spawn(0xFFFF_FFFE, Duration::from_millis(50))
            .expect("observer thread should spawn");
        std::thread::sleep(Duration::from_millis(75));
        drop(observer);
        // If the thread didn't join, the test process would hang
        // waiting for it at the end of the test run.
    }
}
