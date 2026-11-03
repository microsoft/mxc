// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Finds and kills every process in one Seatbelt run.
//!
//! Each run's profile allows a unique Mach service name (the marker) and
//! denies a second one (the control). Every process in the run inherits the
//! profile, even after `setsid()`, so the host can find them with
//! `sandbox_check_by_audit_token`. The control keeps profiles that allow all
//! Mach lookups from matching. No such service exists, so the marker grants
//! nothing.
//!
//! This is best effort: a process scan cannot prove that none are left.

use std::collections::HashSet;
use std::ffi::CString;
use std::time::{Duration, Instant};

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listallpids(buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_signal_with_audittoken(token: *mut AuditToken, signal: libc::c_int) -> libc::c_int;
}

// Private libsystem_sandbox interface, present since OS X 10.9.
unsafe extern "C" {
    fn sandbox_check_by_audit_token(
        token: AuditToken,
        operation: *const libc::c_char,
        filter_type: libc::c_int,
        ...
    ) -> libc::c_int;
    static SANDBOX_CHECK_NO_REPORT: libc::c_int;
}

const SANDBOX_FILTER_NONE: libc::c_int = 0;
const SANDBOX_FILTER_GLOBAL_NAME: libc::c_int = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    val: [u32; 8],
}

impl AuditToken {
    fn identity(&self) -> (u32, u32) {
        (self.val[5], self.val[7])
    }
}

#[repr(C)]
#[derive(Default)]
struct ProcUniqueIdentifierInfo {
    uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    id_version: i32,
    original_parent_id_version: i32,
    reserved: [u64; 2],
}

const PROC_PID_UNIQUE_IDENTIFIER_INFO: libc::c_int = 17;

pub(super) struct RunMarker {
    marker: CString,
    control: CString,
}

impl RunMarker {
    pub(super) fn new() -> std::io::Result<Self> {
        // Two independent names, so no wildcard rule can allow one and deny the other.
        Ok(Self {
            marker: random_service_name()?,
            control: random_service_name()?,
        })
    }

    /// Rules to append after the rest of the profile.
    pub(super) fn profile_rules(&self) -> String {
        format!(
            "\n;; --- run marker: lets MXC find this run's processes; grants nothing ---\n\
             (allow mach-lookup (global-name \"{}\"))\n\
             (deny mach-lookup (global-name \"{}\"))\n",
            self.marker.to_string_lossy(),
            self.control.to_string_lossy()
        )
    }

    fn is_member(&self, token: AuditToken) -> bool {
        // SAFETY: the token is passed by value, and the variadic argument is the
        // NUL-terminated name that `SANDBOX_FILTER_GLOBAL_NAME` expects.
        unsafe {
            let flags = SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT;
            sandbox_check_by_audit_token(token, std::ptr::null(), SANDBOX_FILTER_NONE) == 1
                && sandbox_check_by_audit_token(
                    token,
                    c"mach-lookup".as_ptr(),
                    flags,
                    self.marker.as_ptr(),
                ) == 0
                && sandbox_check_by_audit_token(
                    token,
                    c"mach-lookup".as_ptr(),
                    flags,
                    self.control.as_ptr(),
                ) == 1
        }
    }

    /// Stops, then kills, the run's processes until two scans in a row find
    /// none that were not already killed. Fails if processes are still being
    /// found when `timeout` runs out.
    pub(super) fn kill_members(&self, timeout: Duration) -> std::io::Result<()> {
        const CLEAN_SCANS: usize = 2;

        let deadline = Instant::now() + timeout;
        // SAFETY: `getpid` has no preconditions.
        let current_pid = unsafe { libc::getpid() };
        let mut killed = HashSet::new();
        let mut clean_scans = 0;
        let mut first_error = None;
        while clean_scans < CLEAN_SCANS {
            let mut found = Vec::new();
            for pid in list_all_pids()? {
                if pid <= 0 || pid == current_pid {
                    continue;
                }
                let token = match process_audit_token(pid) {
                    Ok(Some(token)) => token,
                    Ok(None) => continue,
                    Err(error) => {
                        first_error.get_or_insert(error);
                        continue;
                    }
                };
                if killed.contains(&token.identity()) || !self.is_member(token) {
                    continue;
                }
                // Stop all before killing any, so none can react to another's death.
                signal(token, libc::SIGSTOP, &mut first_error);
                found.push(token);
            }
            if found.is_empty() {
                clean_scans += 1;
                std::thread::yield_now();
                continue;
            }
            clean_scans = 0;
            for token in found {
                signal(token, libc::SIGKILL, &mut first_error);
                killed.insert(token.identity());
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Seatbelt: the run kept starting processes after cleanup began",
                ));
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn random_service_name() -> std::io::Result<CString> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        std::io::Error::other(format!("Seatbelt: failed to create a run marker: {error}"))
    })?;
    let nonce: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    CString::new(format!("com.microsoft.mxc.run.{nonce}")).map_err(std::io::Error::other)
}

fn signal(mut token: AuditToken, signal: libc::c_int, first_error: &mut Option<std::io::Error>) {
    // SAFETY: libproc checks the token's pid version when it looks up the
    // process, so a reused pid is never signalled.
    let error = unsafe { proc_signal_with_audittoken(&mut token, signal) };
    if error != 0 && error != libc::ESRCH {
        first_error.get_or_insert(std::io::Error::from_raw_os_error(error));
    }
}

fn process_audit_token(pid: libc::pid_t) -> std::io::Result<Option<AuditToken>> {
    let mut info = ProcUniqueIdentifierInfo::default();
    let size = libc::c_int::try_from(std::mem::size_of_val(&info))
        .map_err(|_| std::io::Error::other("macOS process identity is too large"))?;
    // SAFETY: `info` is writable for `size` bytes and libproc only fills the
    // requested identity record for `pid`.
    let copied = unsafe {
        proc_pidinfo(
            pid,
            PROC_PID_UNIQUE_IDENTIFIER_INFO,
            0,
            std::ptr::from_mut(&mut info).cast::<libc::c_void>(),
            size,
        )
    };
    if copied == 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(None),
            _ => Err(error),
        };
    }
    if copied != size {
        return Err(std::io::Error::other(format!(
            "macOS returned a truncated process identity for pid {pid}"
        )));
    }
    let mut token = AuditToken { val: [0; 8] };
    token.val[5] = pid as u32;
    token.val[7] = info.id_version as u32;
    Ok(Some(token))
}

fn list_all_pids() -> std::io::Result<Vec<libc::pid_t>> {
    const ATTEMPTS: usize = 8;

    // libproc returns 0, not -1, on failure. The list always includes this
    // process, so 0 can only mean failure.
    let listing_failed = || {
        let error = std::io::Error::last_os_error();
        std::io::Error::new(
            error.kind(),
            format!("Seatbelt: failed to list processes: {error}"),
        )
    };
    // SAFETY: a null buffer asks libproc for the current process count.
    let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Err(listing_failed());
    }
    let mut capacity = count as usize + 128;
    for _ in 0..ATTEMPTS {
        let mut pids = vec![0; capacity];
        let buffer_size = pids
            .len()
            .checked_mul(std::mem::size_of::<libc::pid_t>())
            .and_then(|size| libc::c_int::try_from(size).ok())
            .ok_or_else(|| std::io::Error::other("macOS process list is too large"))?;
        // SAFETY: `pids` is writable for exactly `buffer_size` bytes.
        let listed =
            unsafe { proc_listallpids(pids.as_mut_ptr().cast::<libc::c_void>(), buffer_size) };
        if listed <= 0 {
            return Err(listing_failed());
        }
        // A full buffer may have dropped processes; retry with more room.
        if (listed as usize) < capacity {
            pids.truncate(listed as usize);
            return Ok(pids);
        }
        capacity *= 2;
    }
    Err(std::io::Error::other(
        "Seatbelt: the process list kept growing while it was being read",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    fn sandboxed_sleep(rules: &str) -> Child {
        let profile = format!("(version 1)\n(allow default)\n{rules}");
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/sleep", "30"])
            .spawn()
            .expect("start sandbox-exec")
    }

    fn token(child: &Child) -> AuditToken {
        process_audit_token(child.id() as libc::pid_t)
            .unwrap()
            .expect("process is running")
    }

    fn wait_until_sandboxed(child: &Child) {
        let deadline = Instant::now() + Duration::from_secs(5);
        // SAFETY: the token is passed by value and no filter argument is needed.
        while unsafe {
            sandbox_check_by_audit_token(token(child), std::ptr::null(), SANDBOX_FILTER_NONE)
        } != 1
        {
            assert!(
                Instant::now() < deadline,
                "sandbox-exec never applied its profile"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn kill_members_kills_only_this_runs_processes() {
        let run = RunMarker::new().unwrap();
        let mut member = sandboxed_sleep(&run.profile_rules());
        let mut other_run = sandboxed_sleep(&RunMarker::new().unwrap().profile_rules());
        let mut lookalike = sandboxed_sleep(
            "(allow mach-lookup (global-name-prefix \"com.microsoft.mxc.run.\"))\n\
             (deny mach-lookup (global-name-regex #\"\\.control$\"))\n",
        );
        for child in [&member, &other_run, &lookalike] {
            wait_until_sandboxed(child);
        }

        let result = run.kill_members(Duration::from_secs(5));
        let other_running = other_run.try_wait().unwrap().is_none();
        let lookalike_running = lookalike.try_wait().unwrap().is_none();
        let _ = other_run.kill();
        let _ = lookalike.kill();
        let _ = other_run.wait();
        let _ = lookalike.wait();

        result.unwrap();
        assert!(
            !member.wait().unwrap().success(),
            "this run's process was not killed"
        );
        assert!(other_running, "another run's process was killed");
        assert!(
            lookalike_running,
            "a wildcard profile was treated as this run"
        );
    }

    #[test]
    fn list_all_pids_includes_this_process() {
        // SAFETY: `getpid` has no preconditions.
        let current_pid = unsafe { libc::getpid() };
        assert!(list_all_pids().unwrap().contains(&current_pid));
    }
}
