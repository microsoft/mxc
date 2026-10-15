// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource limits and usage accounting for Unix backends that launch their
//! workload as a direct child process (Bubblewrap and Seatbelt).
//!
//! Limits are rlimits and a nice value set between `fork` and `exec`, which
//! every descendant inherits. Usage is read from the exited child *before* it
//! is reaped, so the backend's `std::process::Child` keeps owning the reap and
//! its pid-reuse guarantees.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use crate::mxc_common::models::{
    ResourceLimit, ResourcePolicy, ResourcePriority, ResourceUsage, SandboxOutputMetadata,
};
use crate::mxc_common::sandbox_process::WaitError;

const BYTES_PER_MB: u64 = 1024 * 1024;
const MICROS_PER_SECOND: u64 = 1_000_000;
/// How far below the limit the CPU time a killed workload reports may fall.
/// Linux enforces `RLIMIT_CPU` on its own sampled clock, and the usage that
/// reaches the parent comes out a few milliseconds short of the limit.
const CPU_TIME_TOLERANCE_US: u64 = 100_000;
const NICE_LOW: libc::c_int = 10;
const NICE_IDLE: libc::c_int = 19;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type RlimitResource = libc::c_int;

/// The rlimits and nice value a [`ResourcePolicy`] asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixResourceLimits {
    cpu_seconds: Option<u64>,
    data_bytes: Option<u64>,
    nice: Option<libc::c_int>,
}

impl UnixResourceLimits {
    /// Translate `policy` into rlimits. `RLIMIT_CPU` counts whole seconds, so
    /// a CPU time limit is rounded up.
    pub fn new(policy: &ResourcePolicy) -> Self {
        Self {
            cpu_seconds: policy.cpu_time_ms.map(|ms| ms.div_ceil(1000)),
            data_bytes: policy.memory_mb.map(|mb| mb.saturating_mul(BYTES_PER_MB)),
            nice: match policy.priority {
                ResourcePriority::Normal => None,
                ResourcePriority::Low => Some(NICE_LOW),
                ResourcePriority::Idle => Some(NICE_IDLE),
            },
        }
    }

    /// The enforced CPU time limit, in whole seconds.
    pub fn cpu_seconds(&self) -> Option<u64> {
        self.cpu_seconds
    }

    /// The enforced CPU time limit, in microseconds.
    pub fn cpu_time_us(&self) -> Option<u64> {
        self.cpu_seconds
            .map(|seconds| seconds.saturating_mul(MICROS_PER_SECOND))
    }

    /// Apply the limits to the process `command` spawns, between `fork` and
    /// `exec`. A limit that cannot be applied fails the spawn.
    pub fn apply_to(self, command: &mut Command) {
        if self.cpu_seconds.is_none() && self.data_bytes.is_none() && self.nice.is_none() {
            return;
        }
        // SAFETY: the closure runs between fork() and exec(). It only makes
        // the async-signal-safe getrlimit, setrlimit, and setpriority system
        // calls on values copied before the fork, and allocates nothing.
        unsafe {
            command.pre_exec(move || self.apply_in_child());
        }
    }

    fn apply_in_child(&self) -> io::Result<()> {
        if let Some(seconds) = self.cpu_seconds {
            lower_limit(libc::RLIMIT_CPU, seconds)?;
        }
        if let Some(bytes) = self.data_bytes {
            lower_limit(libc::RLIMIT_DATA, bytes)?;
        }
        if let Some(nice) = self.nice {
            lower_priority(nice)?;
        }
        Ok(())
    }
}

/// Set both the soft and the hard limit to `value`, or keep a lower existing
/// hard limit. Equal soft and hard limits leave the workload no headroom to
/// raise its own limit.
fn lower_limit(resource: RlimitResource, value: u64) -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit.
    if unsafe { libc::getrlimit(resource, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = (value as libc::rlim_t).min(limit.rlim_max);
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `limit` is a valid rlimit.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Lower the calling process's priority to `nice`. A process already running
/// at a lower priority keeps it: raising priority back would need privilege
/// and is never what the policy asks for.
fn lower_priority(nice: libc::c_int) -> io::Result<()> {
    // SAFETY: plain system call on the calling process.
    if unsafe { libc::setpriority(libc::PRIO_PROCESS as _, 0, nice) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EACCES) {
        return Ok(());
    }
    Err(error)
}

/// How an exited child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    /// The child exited with this status.
    Exited(i32),
    /// The child was terminated by this signal.
    Signaled(i32),
}

impl ChildExit {
    /// Whether the workload was terminated by `signal`: directly, or as
    /// reported by a supervisor that exits with `128 + signal`, as Bubblewrap
    /// and `sh` do for a child they waited for.
    pub fn terminated_by(self, signal: libc::c_int) -> bool {
        match self {
            Self::Signaled(received) => received == signal,
            Self::Exited(status) => status == 128 + signal,
        }
    }
}

/// An exited, not yet reaped, child and the resources it used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitedChild {
    pub exit: ChildExit,
    pub usage: ResourceUsage,
}

/// Peek at child `pid` without reaping it. Returns `Ok(None)` while it runs.
///
/// The usage covers the child and every descendant it waited for, so callers
/// must peek before `std::process::Child::try_wait` or `wait` reaps it.
#[cfg(target_os = "linux")]
pub fn peek_exited_child(pid: u32) -> io::Result<Option<ExitedChild>> {
    // SAFETY: zeroed siginfo_t and rusage are valid initial values.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // glibc's waitid() has no rusage argument; the system call does, and fills
    // it for a WNOWAIT peek at a zombie as wait4() would when reaping it.
    // SAFETY: both out-pointers are valid for the duration of the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_waitid,
            libc::P_PID,
            pid as libc::id_t,
            &mut info as *mut libc::siginfo_t,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            &mut usage as *mut libc::rusage,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid filled `info` for a child state change, or left it zeroed.
    let Some(exit) = (unsafe { child_exit(&info) }) else {
        return Ok(None);
    };
    Ok(Some(ExitedChild {
        exit,
        usage: ResourceUsage {
            user_cpu_time_us: timeval_micros(usage.ru_utime),
            system_cpu_time_us: timeval_micros(usage.ru_stime),
            peak_memory_bytes: u64::try_from(usage.ru_maxrss)
                .ok()
                .map(|kilobytes| kilobytes.saturating_mul(1024)),
            limit_exceeded: None,
        },
    }))
}

/// Peek at child `pid` without reaping it. Returns `Ok(None)` while it runs.
///
/// macOS's `waitid` reports no usage, so the CPU times come from
/// `proc_pid_rusage` on the zombie, which includes the descendants it waited
/// for. It reports only the zombie's own peak footprint, not its
/// descendants', so `peak_memory_bytes` stays unknown.
#[cfg(target_os = "macos")]
pub fn peek_exited_child(pid: u32) -> io::Result<Option<ExitedChild>> {
    // SAFETY: a zeroed siginfo_t is a valid initial value.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is valid for the duration of the call.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid filled `info` for a child state change, or left it zeroed.
    let Some(exit) = (unsafe { child_exit(&info) }) else {
        return Ok(None);
    };
    // SAFETY: a zeroed rusage_info_v2 is a valid initial value.
    let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a writable rusage_info_v2, the layout RUSAGE_INFO_V2
    // asks the kernel to fill.
    let result = unsafe {
        libc::proc_pid_rusage(
            pid as libc::c_int,
            libc::RUSAGE_INFO_V2,
            (&mut usage as *mut libc::rusage_info_v2).cast(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let timebase = mach_time::timebase()?;
    Ok(Some(ExitedChild {
        exit,
        usage: ResourceUsage {
            user_cpu_time_us: timebase
                .micros(usage.ri_user_time.saturating_add(usage.ri_child_user_time)),
            system_cpu_time_us: timebase.micros(
                usage
                    .ri_system_time
                    .saturating_add(usage.ri_child_system_time),
            ),
            peak_memory_bytes: None,
            limit_exceeded: None,
        },
    }))
}

/// The CPU time live process `pid` has used itself, excluding its children,
/// in microseconds. Returns `Ok(None)` when the process no longer exists.
#[cfg(target_os = "macos")]
pub fn process_cpu_time_us(pid: libc::pid_t) -> io::Result<Option<u64>> {
    // SAFETY: a zeroed rusage_info_v2 is a valid initial value.
    let mut usage: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a writable rusage_info_v2, the layout RUSAGE_INFO_V2
    // asks the kernel to fill.
    let result = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            (&mut usage as *mut libc::rusage_info_v2).cast(),
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(None),
            _ => Err(error),
        };
    }
    let timebase = mach_time::timebase()?;
    Ok(Some(timebase.micros(
        usage.ri_user_time.saturating_add(usage.ri_system_time),
    )))
}

/// # Safety
///
/// `info` must have been filled by a successful `waitid` call, or zeroed.
unsafe fn child_exit(info: &libc::siginfo_t) -> Option<ChildExit> {
    if info.si_pid() == 0 {
        return None;
    }
    let status = info.si_status();
    Some(match info.si_code {
        libc::CLD_EXITED => ChildExit::Exited(status),
        _ => ChildExit::Signaled(status),
    })
}

#[cfg(target_os = "linux")]
fn timeval_micros(value: libc::timeval) -> u64 {
    let seconds = u64::try_from(value.tv_sec).unwrap_or(0);
    let micros = u64::try_from(value.tv_usec).unwrap_or(0);
    seconds
        .saturating_mul(MICROS_PER_SECOND)
        .saturating_add(micros)
}

#[cfg(target_os = "macos")]
mod mach_time {
    use std::io;

    #[repr(C)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    extern "C" {
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    }

    /// The ratio that converts Mach absolute time units, which
    /// `proc_pid_rusage` reports CPU time in, to nanoseconds.
    pub(super) struct Timebase {
        numer: u64,
        denom: u64,
    }

    pub(super) fn timebase() -> io::Result<Timebase> {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: `info` is a valid, writable mach_timebase_info.
        if unsafe { mach_timebase_info(&mut info) } != 0 || info.denom == 0 {
            return Err(io::Error::other("mach_timebase_info failed"));
        }
        Ok(Timebase {
            numer: u64::from(info.numer),
            denom: u64::from(info.denom),
        })
    }

    impl Timebase {
        pub(super) fn micros(&self, ticks: u64) -> u64 {
            let nanos = u128::from(ticks) * u128::from(self.numer) / u128::from(self.denom);
            u64::try_from(nanos / 1000).unwrap_or(u64::MAX)
        }
    }
}

/// Records a child's resource usage before `std::process::Child` reaps it.
///
/// Every reap of the child must go through [`Self::try_wait`] or
/// [`Self::reap_with_timeout`], which peek at the exited child first.
#[derive(Debug)]
pub struct ChildAccounting {
    limits: UnixResourceLimits,
    exited: Option<ExitedChild>,
    /// Set once the child has been reaped: its pid may be reused afterwards,
    /// so it is never peeked at again.
    reaped: bool,
    /// A limit the backend itself enforced by terminating a process.
    enforced: Option<ResourceLimit>,
}

impl ChildAccounting {
    /// Account for a child launched under `limits`.
    pub fn new(limits: UnixResourceLimits) -> Self {
        Self {
            limits,
            exited: None,
            reaped: false,
            enforced: None,
        }
    }

    /// Record that the backend terminated a process for exceeding `limit`.
    pub fn record_enforced(&mut self, limit: ResourceLimit) {
        self.enforced.get_or_insert(limit);
    }

    /// `child.try_wait()`, recording the exited child's usage first.
    ///
    /// Reports a child that a successful peek finds still running without
    /// calling `try_wait`, so it cannot exit and be reaped between the two.
    pub fn try_wait(&mut self, child: &mut Child) -> io::Result<Option<ExitStatus>> {
        if !self.reaped && self.exited.is_none() {
            match peek_exited_child(child.id()) {
                Ok(Some(exited)) => self.exited = Some(exited),
                Ok(None) => return Ok(None),
                Err(_) => {}
            }
        }
        let status = child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    /// Reap `child`, waiting at most `timeout` (forever when `None`),
    /// recording its usage first.
    pub fn reap_with_timeout(
        &mut self,
        child: &mut Child,
        timeout: Option<Duration>,
    ) -> Result<ExitStatus, WaitError> {
        const MIN_POLL: Duration = Duration::from_millis(1);
        const MAX_POLL: Duration = Duration::from_millis(50);

        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        let mut interval = MIN_POLL;
        loop {
            if let Some(status) = self.try_wait(child).map_err(WaitError::Io)? {
                return Ok(status);
            }
            let mut nap = interval;
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    return Err(WaitError::Timeout);
                }
                nap = nap.min(deadline - now);
            }
            std::thread::sleep(nap);
            interval = (interval * 2).min(MAX_POLL);
        }
    }

    /// The output metadata to report once the child has been reaped.
    ///
    /// A run that MXC ended, by timeout or kill, reports no limit: the limit
    /// did not end it.
    pub fn output_metadata(&self, natural_exit: bool) -> Option<SandboxOutputMetadata> {
        let exited = self.exited?;
        let mut usage = exited.usage;
        if natural_exit {
            usage.limit_exceeded = self
                .enforced
                .or_else(|| limit_exceeded(&self.limits, exited.exit, &usage));
        }
        Some(SandboxOutputMetadata {
            resource_usage: Some(usage),
            ..Default::default()
        })
    }
}

/// The limit a workload that exited as `exit` ran into, if MXC can tell.
///
/// The kernel ends a process at its CPU limit with `SIGXCPU` (macOS) or
/// `SIGKILL` (Linux, whose soft and hard limits are equal here). `SIGKILL`
/// alone is ambiguous, so it counts only when the workload used the limit,
/// within [`CPU_TIME_TOLERANCE_US`]. A memory limit only makes allocations fail, and how a program
/// reacts is its own business, so it is never reported here.
pub fn limit_exceeded(
    limits: &UnixResourceLimits,
    exit: ChildExit,
    usage: &ResourceUsage,
) -> Option<ResourceLimit> {
    let seconds = limits.cpu_seconds()?;
    let used = usage
        .user_cpu_time_us
        .saturating_add(usage.system_cpu_time_us);
    let reached =
        used.saturating_add(CPU_TIME_TOLERANCE_US) >= seconds.saturating_mul(MICROS_PER_SECOND);
    if exit.terminated_by(libc::SIGXCPU) || (exit.terminated_by(libc::SIGKILL) && reached) {
        Some(ResourceLimit::CpuTime)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(cpu_time_ms: Option<u64>, priority: ResourcePriority) -> ResourcePolicy {
        ResourcePolicy {
            cpu_time_ms,
            priority,
            ..Default::default()
        }
    }

    fn usage(cpu_seconds: u64) -> ResourceUsage {
        ResourceUsage {
            user_cpu_time_us: cpu_seconds * MICROS_PER_SECOND / 2,
            system_cpu_time_us: cpu_seconds * MICROS_PER_SECOND / 2,
            ..Default::default()
        }
    }

    #[test]
    fn cpu_time_is_rounded_up_to_whole_seconds() {
        for (ms, seconds) in [(1, 1), (1000, 1), (1001, 2), (120_000, 120)] {
            let limits = UnixResourceLimits::new(&policy(Some(ms), ResourcePriority::Normal));
            assert_eq!(limits.cpu_seconds(), Some(seconds), "{ms} ms");
        }
    }

    #[test]
    fn memory_is_converted_to_bytes_without_overflow() {
        let limits = UnixResourceLimits::new(&ResourcePolicy {
            memory_mb: Some(2048),
            ..Default::default()
        });
        assert_eq!(limits.data_bytes, Some(2048 * BYTES_PER_MB));

        let limits = UnixResourceLimits::new(&ResourcePolicy {
            memory_mb: Some(u64::MAX),
            ..Default::default()
        });
        assert_eq!(limits.data_bytes, Some(u64::MAX));
    }

    #[test]
    fn priorities_map_to_nice_values() {
        for (priority, nice) in [
            (ResourcePriority::Normal, None),
            (ResourcePriority::Low, Some(10)),
            (ResourcePriority::Idle, Some(19)),
        ] {
            assert_eq!(UnixResourceLimits::new(&policy(None, priority)).nice, nice);
        }
    }

    #[test]
    fn supervisors_report_signals_as_128_plus_the_signal() {
        assert!(ChildExit::Exited(128 + libc::SIGKILL).terminated_by(libc::SIGKILL));
        assert!(ChildExit::Signaled(libc::SIGXCPU).terminated_by(libc::SIGXCPU));
        assert!(!ChildExit::Exited(1).terminated_by(libc::SIGKILL));
    }

    #[test]
    fn sigxcpu_reports_the_cpu_time_limit() {
        let limits = UnixResourceLimits::new(&policy(Some(2000), ResourcePriority::Normal));
        assert_eq!(
            limit_exceeded(&limits, ChildExit::Signaled(libc::SIGXCPU), &usage(0)),
            Some(ResourceLimit::CpuTime)
        );
    }

    #[test]
    fn sigkill_reports_the_cpu_time_limit_only_after_using_it() {
        let limits = UnixResourceLimits::new(&policy(Some(2000), ResourcePriority::Normal));
        let killed = ChildExit::Exited(128 + libc::SIGKILL);
        assert_eq!(
            limit_exceeded(&limits, killed, &usage(2)),
            Some(ResourceLimit::CpuTime)
        );
        let just_short = ResourceUsage {
            user_cpu_time_us: 1_995_000,
            ..Default::default()
        };
        assert_eq!(
            limit_exceeded(&limits, killed, &just_short),
            Some(ResourceLimit::CpuTime)
        );
        assert_eq!(limit_exceeded(&limits, killed, &usage(1)), None);
    }

    #[test]
    fn nothing_is_reported_without_a_cpu_time_limit() {
        let limits = UnixResourceLimits::new(&policy(None, ResourcePriority::Low));
        assert_eq!(
            limit_exceeded(&limits, ChildExit::Signaled(libc::SIGXCPU), &usage(5)),
            None
        );
    }

    #[test]
    fn an_ordinary_failure_is_not_a_limit() {
        let limits = UnixResourceLimits::new(&policy(Some(1000), ResourcePriority::Normal));
        assert_eq!(
            limit_exceeded(&limits, ChildExit::Exited(1), &usage(5)),
            None
        );
    }

    #[test]
    fn limits_apply_to_the_child_and_usage_is_read_before_the_reap() {
        let limits = UnixResourceLimits::new(&ResourcePolicy {
            cpu_time_ms: Some(1500),
            priority: ResourcePriority::Low,
            ..Default::default()
        });
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "ulimit -t; ps -o nice= -p $$; i=0; while [ $i -lt 100000 ]; do i=$((i+1)); done; exit 3",
        ]);
        command.stdout(std::process::Stdio::piped());
        limits.apply_to(&mut command);
        let mut child = command.spawn().unwrap();
        let mut output = String::new();
        std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut output).unwrap();

        let mut accounting = ChildAccounting::new(limits);
        let Ok(status) = accounting.reap_with_timeout(&mut child, Some(Duration::from_secs(30)))
        else {
            panic!("the child did not exit");
        };
        assert_eq!(status.code(), Some(3));
        assert_eq!(accounting.exited.unwrap().exit, ChildExit::Exited(3));
        let usage = accounting
            .output_metadata(true)
            .and_then(|metadata| metadata.resource_usage)
            .unwrap();
        assert!(usage.user_cpu_time_us + usage.system_cpu_time_us > 0);
        assert_eq!(usage.limit_exceeded, None);

        // SAFETY: getpriority only queries the calling process.
        let parent = unsafe { libc::getpriority(libc::PRIO_PROCESS as _, 0) };
        let mut lines = output.lines().map(str::trim);
        assert_eq!(lines.next(), Some("2"));
        assert_eq!(
            lines.next(),
            Some(parent.max(NICE_LOW).to_string().as_str())
        );
    }
}
