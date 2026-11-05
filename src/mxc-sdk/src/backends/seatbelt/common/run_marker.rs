// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Finds and kills every process in one Seatbelt run.
//!
//! Each run's profile denies every Mach service name under the reserved
//! prefix except a few random ones (the markers). Every process in the run
//! inherits the profile, even after `setsid()`, so the host can find them with
//! `sandbox_check_by_audit_token`: a member allows every marker and denies
//! random names under the prefix (the controls) that never appear in any
//! profile. No such service exists, so the markers grant nothing.
//!
//! Another MXC run's profile denies this run's markers, so runs never match
//! each other. Processes that started before this run are never checked.
//!
//! This is best effort: a process scan cannot prove that none are left.

use std::collections::HashSet;
use std::ffi::CString;
use std::time::{Duration, Instant};

use super::seatbelt_policy::RUN_MARKER_NAME_PREFIX;

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

// A sandbox outside MXC that allows or denies names at random matches every
// name with a chance of at most about 1 in 65 million.
const MARKER_COUNT: usize = 8;
const CONTROL_COUNT: usize = 24;

pub(super) struct RunMarker {
    rules: String,
    markers: Vec<CString>,
    controls: Vec<CString>,
    // Every process with this ID or lower existed before the run.
    newest_before_run: u64,
}

impl RunMarker {
    pub(super) fn new() -> std::io::Result<Self> {
        let mut nonces = HashSet::new();
        while nonces.len() < MARKER_COUNT + CONTROL_COUNT {
            nonces.insert(random_nonce()?);
        }
        let mut markers: Vec<String> = nonces.into_iter().collect();
        let controls = markers.split_off(MARKER_COUNT);
        Self::with_nonces(&markers, &controls)
    }

    fn with_nonces(markers: &[String], controls: &[String]) -> std::io::Result<Self> {
        let names = |nonces: &[String]| {
            nonces
                .iter()
                .map(|nonce| {
                    CString::new(format!("{RUN_MARKER_NAME_PREFIX}{nonce}"))
                        .map_err(std::io::Error::other)
                })
                .collect::<std::io::Result<Vec<_>>>()
        };
        // The deny comes first so that the allow wins for this run's markers.
        let rules = format!(
            "\n;; --- run marker: lets MXC find this run's processes; grants nothing ---\n\
             (deny mach-lookup (global-name-prefix \"{RUN_MARKER_NAME_PREFIX}\"))\n\
             (allow mach-lookup (global-name-regex #\"^{}({})$\"))\n",
            RUN_MARKER_NAME_PREFIX.replace('.', "\\."),
            markers.join("|")
        );
        Ok(Self {
            rules,
            markers: names(markers)?,
            controls: names(controls)?,
            newest_before_run: newest_unique_id()?,
        })
    }

    /// Rules to append after the rest of the profile.
    pub(super) fn profile_rules(&self) -> String {
        self.rules.clone()
    }

    fn is_member(&self, token: AuditToken) -> bool {
        let allows = |name: &CString| {
            // SAFETY: the token is passed by value, and the variadic argument is
            // the NUL-terminated name that `SANDBOX_FILTER_GLOBAL_NAME` expects.
            unsafe {
                sandbox_check_by_audit_token(
                    token,
                    c"mach-lookup".as_ptr(),
                    SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT,
                    name.as_ptr(),
                ) == 0
            }
        };
        // SAFETY: the token is passed by value and no filter argument is needed.
        let sandboxed = unsafe {
            sandbox_check_by_audit_token(token, std::ptr::null(), SANDBOX_FILTER_NONE) == 1
        };
        sandboxed && self.markers.iter().all(allows) && !self.controls.iter().any(allows)
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
                let (token, unique_id) = match process_identity(pid) {
                    Ok(Some(identity)) => identity,
                    Ok(None) => continue,
                    Err(error) => {
                        first_error.get_or_insert(error);
                        continue;
                    }
                };
                if unique_id <= self.newest_before_run
                    || killed.contains(&token.identity())
                    || !self.is_member(token)
                {
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

fn random_nonce() -> std::io::Result<String> {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        std::io::Error::other(format!("Seatbelt: failed to create a run marker: {error}"))
    })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The newest process ID that macOS has handed out. These IDs only increase
/// and survive `exec` and `setsid()`.
fn newest_unique_id() -> std::io::Result<u64> {
    Ok(list_all_pids()?
        .into_iter()
        .filter_map(|pid| process_identity(pid).ok().flatten())
        .map(|(_, unique_id)| unique_id)
        .max()
        .unwrap_or(0))
}

fn signal(mut token: AuditToken, signal: libc::c_int, first_error: &mut Option<std::io::Error>) {
    // SAFETY: libproc checks the token's pid version when it looks up the
    // process, so a reused pid is never signalled.
    let error = unsafe { proc_signal_with_audittoken(&mut token, signal) };
    if error != 0 && error != libc::ESRCH {
        first_error.get_or_insert(std::io::Error::from_raw_os_error(error));
    }
}

/// The process's audit token and its never-reused unique ID.
fn process_identity(pid: libc::pid_t) -> std::io::Result<Option<(AuditToken, u64)>> {
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
    Ok(Some((token, info.unique_id)))
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
        process_identity(child.id() as libc::pid_t)
            .unwrap()
            .expect("process is running")
            .0
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
        // Markers end in 0 and controls in f, so a profile that denies names
        // ending in 8-f allows every marker and denies every control.
        let markers: Vec<String> = (0..MARKER_COUNT).map(|i| format!("{i:07x}0")).collect();
        let controls: Vec<String> = (0..CONTROL_COUNT).map(|i| format!("{i:07x}f")).collect();
        let rules = RunMarker::with_nonces(&markers, &controls)
            .unwrap()
            .profile_rules();
        let older = sandboxed_sleep(&rules);
        wait_until_sandboxed(&older);

        let run = RunMarker::with_nonces(&markers, &controls).unwrap();
        let member = sandboxed_sleep(&rules);
        let split_regex_run = sandboxed_sleep(&format!(
            "(deny mach-lookup (global-name-regex #\"[89a-f]$\"))\n{}",
            RunMarker::new().unwrap().profile_rules()
        ));
        let lookalike = sandboxed_sleep(
            "(allow mach-lookup (global-name-prefix \"com.microsoft.mxc.run.\"))\n\
             (deny mach-lookup (global-name-regex #\"\\.control$\"))\n",
        );
        let mut others = [
            (older, "a process that started before the run"),
            (split_regex_run, "another run with a split-regex profile"),
            (lookalike, "a wildcard profile"),
        ];
        wait_until_sandboxed(&member);
        for (child, _) in &others {
            wait_until_sandboxed(child);
        }

        let result = run.kill_members(Duration::from_secs(5));
        let survivors: Vec<bool> = others
            .iter_mut()
            .map(|(child, _)| child.try_wait().unwrap().is_none())
            .collect();
        for (child, _) in &mut others {
            let _ = child.kill();
            let _ = child.wait();
        }
        let mut member = member;

        result.unwrap();
        assert!(
            !member.wait().unwrap().success(),
            "this run's process was not killed"
        );
        for ((_, what), running) in others.iter().zip(survivors) {
            assert!(running, "{what} was killed as part of this run");
        }
    }

    #[test]
    fn list_all_pids_includes_this_process() {
        // SAFETY: `getpid` has no preconditions.
        let current_pid = unsafe { libc::getpid() };
        assert!(list_all_pids().unwrap().contains(&current_pid));
    }
}
