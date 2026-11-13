// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-level cleanup for fatal signals.
//!
//! SIGHUP, SIGTERM, and SIGINT can interrupt the runner before normal cleanup
//! runs.  The watchdog waits for them through `sigwait`, cleans up the active
//! container, and exits with the signal-style status code.
//!
//! Only the executor binary installs it: one slot cannot describe the several
//! sandboxes a library host can hold, and a library may not exit its caller's
//! process.  There each sandbox handle tears itself down instead.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::{
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicI32, AtomicU64},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use nix::{
    sys::{
        signal::{kill, killpg, SigSet, Signal},
        wait::{waitid, Id, WaitPidFlag, WaitStatus},
    },
    unistd::{getpid, Pid},
};

#[cfg(target_os = "linux")]
use crate::lxc_common::lxc_bindings::LxcContainer;
#[cfg(target_os = "linux")]
use crate::lxc_common::network_ingress::IngressManager;
use crate::lxc_common::network_iptables::CreatedResources;
#[cfg(target_os = "linux")]
use crate::lxc_common::network_iptables::{EgressHookPoint, NetworkIptablesManager};
#[cfg(target_os = "linux")]
use crate::mxc_common::logger::{Logger, Mode};

#[derive(Default)]
struct ActiveSandbox {
    name: Option<String>,
    created: CreatedResources,
    netns_pid: Option<u32>,

    #[cfg(target_os = "linux")]
    starting_container: Option<LxcContainer>,

    #[cfg(target_os = "linux")]
    startup_monitor: Option<Child>,

    #[cfg(target_os = "linux")]
    startup_tool: Option<Child>,

    #[cfg(target_os = "linux")]
    monitor_reaper: Option<mpsc::Sender<Child>>,
}

static ACTIVE_CONTAINER: OnceLock<Mutex<ActiveSandbox>> = OnceLock::new();
static WATCHDOG_INSTALLED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
static STARTUP_LOCK: Mutex<()> = Mutex::new(());
#[cfg(target_os = "linux")]
static STARTUP_CANCELLED: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static STARTUP_TIMED_OUT: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static DEADLINE_EPOCH: OnceLock<Instant> = OnceLock::new();
#[cfg(target_os = "linux")]
static STARTUP_DEADLINE_MS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static CLEANUP_DEADLINE_MS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static CLEANUP_EXIT_CODE: AtomicI32 = AtomicI32::new(124);
#[cfg(target_os = "linux")]
const EXIT_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(target_os = "linux")]
struct StartupDeadline;

#[cfg(target_os = "linux")]
impl Drop for StartupDeadline {
    fn drop(&mut self) {
        let deadline = STARTUP_DEADLINE_MS.load(Ordering::Acquire);
        if deadline != 0 {
            arm_cleanup_deadline(deadline, 124);
        }
        STARTUP_DEADLINE_MS.store(0, Ordering::Release);
    }
}

fn lock_slot() -> std::sync::MutexGuard<'static, ActiveSandbox> {
    ACTIVE_CONTAINER
        .get_or_init(|| Mutex::new(ActiveSandbox::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
thread_local! {
    /// Opens the gate for one test thread, leaving it shut for the tests
    /// running beside it.
    static WATCHDOG_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn watchdog_installed() -> bool {
    #[cfg(test)]
    if let Some(overridden) = WATCHDOG_OVERRIDE.with(std::cell::Cell::get) {
        return overridden;
    }
    WATCHDOG_INSTALLED.load(Ordering::Acquire)
}

pub fn exit_after_signal_cleanup(exit_code: i32) -> ! {
    let _ = std::io::stdout().flush();

    #[cfg(target_os = "linux")]
    if watchdog_installed() {
        let active = lock_slot();
        if STARTUP_CANCELLED.load(Ordering::Acquire) {
            drop(active);
            loop {
                thread::park();
            }
        }
        std::process::exit(exit_code);
    }
    std::process::exit(exit_code)
}

#[cfg(target_os = "linux")]
pub(crate) fn check_startup_cancellation() -> Result<(), String> {
    if watchdog_installed() && STARTUP_CANCELLED.load(Ordering::Acquire) {
        Err("LXC startup was cancelled".to_string())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn write_fatal_diagnostic(message: &str) {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    // Reopen stderr with independent file-status flags instead of changing the original handle.
    if let Ok(mut stderr) = OpenOptions::new()
        .append(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open("/proc/self/fd/2")
    {
        let _ = stderr.write(format!("{message}\n").as_bytes());
    }
}

#[cfg(target_os = "linux")]
fn elapsed_millis() -> u64 {
    DEADLINE_EPOCH
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis() as u64
}

#[cfg(target_os = "linux")]
pub(crate) fn startup_time_remaining() -> Option<Duration> {
    if !watchdog_installed() || STARTUP_CANCELLED.load(Ordering::Acquire) {
        return None;
    }
    let deadline = STARTUP_DEADLINE_MS.load(Ordering::Acquire);
    (deadline != 0).then(|| Duration::from_millis(deadline.saturating_sub(elapsed_millis())))
}

#[cfg(target_os = "linux")]
pub(crate) fn record_startup_timeout() {
    if startup_time_remaining().is_some() {
        STARTUP_TIMED_OUT.store(true, Ordering::Release);
    }
}

#[cfg(target_os = "linux")]
fn arm_cleanup_deadline(deadline: u64, exit_code: i32) {
    CLEANUP_EXIT_CODE.store(exit_code, Ordering::Release);
    let _ = CLEANUP_DEADLINE_MS.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(if current == 0 {
            deadline
        } else {
            current.min(deadline)
        })
    });
}

#[cfg(target_os = "linux")]
fn run_deadline_guard(running: Arc<AtomicBool>) {
    while running.load(Ordering::Acquire) {
        let now = elapsed_millis();
        let startup = STARTUP_DEADLINE_MS.load(Ordering::Acquire);
        let cleanup = CLEANUP_DEADLINE_MS.load(Ordering::Acquire);
        if (startup != 0 && now >= startup) || (cleanup != 0 && now >= cleanup) {
            let code = if cleanup != 0 {
                CLEANUP_EXIT_CODE.load(Ordering::Acquire)
            } else {
                124
            };

            // Locks, diagnostics, and buffered output must not delay the final exit.
            unsafe { nix::libc::_exit(code) }
        }

        if startup != 0 && now >= startup.saturating_sub(10_000) {
            if let Some(active) = ACTIVE_CONTAINER.get() {
                if let Ok(_slot) = active.try_lock() {
                    if STARTUP_DEADLINE_MS.load(Ordering::Acquire) == startup
                        && !STARTUP_CANCELLED.load(Ordering::Acquire)
                    {
                        STARTUP_TIMED_OUT.store(true, Ordering::Release);
                        STARTUP_CANCELLED.store(true, Ordering::Release);
                        let _ = kill(getpid(), Signal::SIGTERM);
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn read_startup_output(mut file: std::fs::File) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};

    let mut output = Vec::new();
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let _ = file.take(16 * 1024).read_to_end(&mut output);
    }
    output
}

#[cfg(target_os = "linux")]
pub(crate) fn run_startup_tool(mut command: Command, timeout: Duration) -> Result<Output, String> {
    use crate::lxc_common::lxc_bindings::unblock_fatal_signals;

    let tool = command.get_program().to_string_lossy().into_owned();
    let stdout = tempfile::tempfile().map_err(|error| error.to_string())?;
    let stderr = tempfile::tempfile().map_err(|error| error.to_string())?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().map_err(|error| error.to_string())?)
        .stderr(stderr.try_clone().map_err(|error| error.to_string())?);
    unblock_fatal_signals(&mut command);
    let deadline = Instant::now() + timeout.min(startup_time_remaining().unwrap_or(timeout));
    {
        let mut slot = lock_slot();
        check_startup_cancellation()?;
        slot.startup_tool = Some(
            command
                .spawn()
                .map_err(|error| format!("Failed to run {tool}: {error}"))?,
        );
    }
    loop {
        {
            let mut slot = lock_slot();
            check_startup_cancellation()?;
            let child = slot
                .startup_tool
                .as_mut()
                .ok_or("LXC startup tool was cancelled")?;
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("Failed to wait for {tool}: {error}"))?
            {
                slot.startup_tool = None;
                drop(slot);
                return Ok(Output {
                    status,
                    stdout: read_startup_output(stdout),
                    stderr: read_startup_output(stderr),
                });
            }
            if let Some(monitor) = &slot.startup_monitor {
                if matches!(
                    waitid(
                        Id::Pid(Pid::from_raw(monitor.id() as i32)),
                        WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
                    ),
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..))
                ) {
                    return Err("lxc-start exited before startup finished".into());
                }
            }
        }
        if Instant::now() >= deadline {
            record_startup_timeout();
            return Err(format!(
                "{tool} did not finish within {}s",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn run_owned_startup(mut command: Command, readiness: Command) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    let stderr = tempfile::tempfile().map_err(|error| error.to_string())?;
    let (reaper, monitor) = mpsc::channel::<Child>();
    thread::Builder::new()
        .name("lxc-monitor-reaper".into())
        .spawn(move || {
            if let Ok(mut child) = monitor.recv() {
                let _ = child.wait();
            }
        })
        .map_err(|error| format!("spawn LXC monitor reaper: {error}"))?;

    // Foreground mode keeps the actual monitor owned; "none" avoids opening /dev/tty.
    command
        .args(["-F", "-s", "lxc.console.path=none"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr.try_clone().map_err(|error| error.to_string())?);
    {
        let mut slot = lock_slot();
        check_startup_cancellation()?;
        slot.startup_monitor = Some(
            command
                .spawn()
                .map_err(|error| format!("Failed to run lxc-start: {error}"))?,
        );
        slot.monitor_reaper = Some(reaper);
    }

    let result = run_startup_tool(readiness, Duration::from_secs(45)).and_then(|output| {
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "lxc-wait failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    });
    result.map_err(|error| {
        format!(
            "{error}; lxc-start: {}",
            String::from_utf8_lossy(&read_startup_output(stderr))
        )
    })
}

#[cfg(target_os = "linux")]
fn stopped_monitor_children(monitor: Pid, deadline: Instant) -> Result<Vec<Pid>, String> {
    use std::fs;

    let children_path = format!("/proc/{monitor}/task/{monitor}/children");
    match fs::read_to_string(&children_path) {
        Ok(children) => {
            return children
                .split_whitespace()
                .map(|child| {
                    child
                        .parse::<i32>()
                        .map(Pid::from_raw)
                        .map_err(|error| format!("{children_path}: {error}"))
                })
                .collect();
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("{children_path}: {error}")),
    }
    let status_path = format!("/proc/{monitor}/status");
    let status =
        fs::read_to_string(&status_path).map_err(|error| format!("{status_path}: {error}"))?;
    let field = |text: &str, name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse::<i32>().ok())
    };
    if field(&status, "Pid:") != Some(monitor.as_raw())
        || field(&status, "PPid:") != Some(getpid().as_raw())
    {
        return Err("Cannot compare startup child PIDs across PID namespaces".into());
    }
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("Cannot inspect /proc mount options: {error}"))?;
    let proc_options = mounts.lines().find_map(|line| {
        let (mount, filesystem) = line.split_once(" - ")?;
        let mut filesystem = filesystem.split_whitespace();
        if mount.split_whitespace().nth(4)? != "/proc" || filesystem.next()? != "proc" {
            return None;
        }
        filesystem.nth(1)
    });
    let options = proc_options.ok_or("Cannot identify the /proc mount")?;
    if options
        .split(',')
        .filter_map(|option| option.strip_prefix("hidepid="))
        .any(|value| value != "0" && value != "off")
    {
        return Err("Cannot enumerate startup children through restricted /proc".into());
    }
    let mut children = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|error| error.to_string())? {
        if Instant::now() >= deadline {
            return Err("Startup child enumeration exceeded its cleanup deadline".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(nix::libc::ESRCH) =>
            {
                continue
            }
            Err(error) => return Err(format!("Cannot inspect /proc/{pid}/status: {error}")),
        };
        let parent =
            field(&status, "PPid:").ok_or_else(|| format!("Cannot parse /proc/{pid}/status"))?;
        if parent == monitor.as_raw() {
            children.push(Pid::from_raw(pid));
        }
    }
    Ok(children)
}

#[cfg(target_os = "linux")]
fn reap_before(child: &mut Child, deadline: Instant) -> Result<(), String> {
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Startup process {} could not be reaped before its cleanup deadline",
                child.id()
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn interrupt_startup_commands(
    mut monitor: Option<Child>,
    mut tool: Option<Child>,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    if let Some(tool) = &mut tool {
        let _ = tool.kill();
    }
    if let Some(monitor) = &mut monitor {
        let pid = Pid::from_raw(monitor.id() as i32);
        let flags = WaitPidFlag::WEXITED
            | WaitPidFlag::WSTOPPED
            | WaitPidFlag::WNOHANG
            | WaitPidFlag::WNOWAIT;

        // WNOWAIT reserves the PID and process group until every signal has been sent.
        let state = waitid(Id::Pid(pid), flags).map_err(|error| error.to_string())?;
        if matches!(state, WaitStatus::StillAlive | WaitStatus::Stopped(..)) {
            let _ = kill(pid, Signal::SIGSTOP);
            loop {
                match waitid(Id::Pid(pid), flags) {
                    Ok(WaitStatus::Stopped(..)) => {
                        match stopped_monitor_children(pid, deadline) {
                            Ok(children) => {
                                for child in children {
                                    if let Err(error) = kill(child, Signal::SIGKILL) {
                                        write_fatal_diagnostic(&format!(
                                            "Cannot kill startup child {child}: {error}"
                                        ));
                                    }
                                }
                            }
                            Err(error) => write_fatal_diagnostic(&format!(
                                "{error}; a container with a custom parent-death signal may require manual cleanup"
                            )),
                        }
                        break;
                    }
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => break,
                    Err(error) => {
                        return Err(format!("Cannot observe startup monitor {pid}: {error}"))
                    }
                    _ if Instant::now() >= deadline => {
                        write_fatal_diagnostic(&format!(
                            "Startup monitor {pid} did not stop before its cleanup deadline"
                        ));
                        break;
                    }
                    _ => thread::sleep(Duration::from_millis(10)),
                }
            }
        }
        let _ = killpg(pid, Signal::SIGKILL);
        reap_before(monitor, deadline)?;
    }
    if let Some(tool) = &mut tool {
        reap_before(tool, deadline)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn with_container_startup<T>(
    container: &LxcContainer,
    start: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    if !watchdog_installed() {
        return start();
    }

    let startup = STARTUP_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let deadline = StartupDeadline;
    STARTUP_DEADLINE_MS.store(
        elapsed_millis() + EXIT_TIMEOUT.as_millis() as u64,
        Ordering::Release,
    );

    {
        let mut slot = lock_slot();
        check_startup_cancellation()?;
        slot.starting_container = Some(LxcContainer::new(
            container.name(),
            Some(container.lxc_path()),
        ));
    }

    let mut result = start();
    let mut slot = lock_slot();
    if check_startup_cancellation().is_ok() {
        if result.is_ok() {
            if let Some(monitor) = slot.startup_monitor.take() {
                match slot.monitor_reaper.take() {
                    Some(reaper) => {
                        if let Err(error) = reaper.send(monitor) {
                            slot.startup_monitor = Some(error.0);
                            result = Err(
                                "LXC monitor reaper disconnected before startup handoff".into()
                            );
                        }
                    }
                    None => {
                        slot.startup_monitor = Some(monitor);
                        result = Err("LXC startup has no monitor reaper".into());
                    }
                }
            }
        }
        if result.is_ok() {
            slot.starting_container = None;
            STARTUP_DEADLINE_MS.store(0, Ordering::Release);
            drop(deadline);
            return result;
        }
        let monitor = slot.startup_monitor.take();
        let tool = slot.startup_tool.take();
        slot.monitor_reaper = None;
        drop(slot);
        let interrupted = interrupt_startup_commands(monitor, tool);
        slot = lock_slot();
        if interrupted.is_ok() {
            slot.starting_container = None;
        } else if let Err(error) = interrupted {
            result = Err(format!("{}; {error}", result.err().unwrap_or_default()));
        }
        if check_startup_cancellation().is_ok() {
            drop(deadline);
            return result;
        }
    }

    if let Err(error) = &result {
        write_fatal_diagnostic(error);
    }

    drop(slot);
    drop(startup);
    loop {
        thread::park();
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn with_container_startup<T>(
    _container: &crate::lxc_common::lxc_bindings::LxcContainer,
    start: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    start()
}

/// Registers the container the watchdog destroys.
pub fn set_active(name: &str) {
    if !watchdog_installed() {
        return;
    }
    let mut slot = lock_slot();
    slot.name = Some(name.to_owned());
    slot.created = CreatedResources::default();
    slot.netns_pid = None;
}

pub fn set_active_pid(pid: u32) {
    if !watchdog_installed() {
        return;
    }
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.netns_pid = Some(pid);
    }
}

pub(crate) fn set_active_created(created: CreatedResources) {
    if !watchdog_installed() {
        return;
    }
    let mut slot = lock_slot();
    if slot.name.is_some() {
        slot.created = created;
    }
}

#[cfg(test)]
fn active_snapshot() -> (Option<String>, CreatedResources, Option<u32>) {
    let slot = lock_slot();
    (slot.name.clone(), slot.created, slot.netns_pid)
}

#[cfg(test)]
fn clear_active() {
    *lock_slot() = ActiveSandbox::default();
}

/// Blocks fatal signals in this thread and spawns the cleanup watchdog.
///
/// `pthread_sigmask` changes only the calling thread's mask, and new threads
/// inherit their creator's mask.  Call this before spawning any thread that
/// should leave signal delivery to the watchdog.
#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    if watchdog_installed() {
        return Ok(());
    }
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGHUP);
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGINT);
    mask.thread_block()
        .map_err(|e| format!("pthread_sigmask: {}", e))?;

    let running = Arc::new(AtomicBool::new(true));
    let guard_running = Arc::clone(&running);
    DEADLINE_EPOCH.get_or_init(Instant::now);
    if let Err(error) = thread::Builder::new()
        .name("lxc-exit-deadline".into())
        .spawn(move || run_deadline_guard(guard_running))
    {
        let _ = mask.thread_unblock();
        return Err(format!("spawn lxc-exit-deadline thread: {error}"));
    }
    match thread::Builder::new()
        .name("lxc-signal-cleanup".into())
        .spawn(move || run_watchdog(mask))
    {
        Ok(_) => {
            WATCHDOG_INSTALLED.store(true, Ordering::Release);
            Ok(())
        }
        Err(err) => {
            running.store(false, Ordering::Release);
            let _ = mask.thread_unblock();
            Err(format!("spawn lxc-signal-cleanup thread: {err}"))
        }
    }
}

/// Non-Linux stub for workspace builds on Windows and macOS.
#[cfg(not(target_os = "linux"))]
pub fn install() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_watchdog(mask: SigSet) -> ! {
    loop {
        let Ok(sig) = mask.wait() else { continue };
        let exit_code = if STARTUP_TIMED_OUT.load(Ordering::Acquire) {
            124
        } else {
            128 + sig as i32
        };
        arm_cleanup_deadline(
            elapsed_millis() + EXIT_TIMEOUT.as_millis() as u64,
            exit_code,
        );
        let (monitor, tool) = {
            let mut slot = lock_slot();
            STARTUP_CANCELLED.store(true, Ordering::Release);
            slot.monitor_reaper = None;
            (slot.startup_monitor.take(), slot.startup_tool.take())
        };
        let owned_monitor = monitor.is_some();
        if let Err(error) = interrupt_startup_commands(monitor, tool) {
            write_fatal_diagnostic(&error);
        } else if owned_monitor {
            lock_slot().starting_container = None;
        }
        if STARTUP_TIMED_OUT.load(Ordering::Acquire) {
            write_fatal_diagnostic(
                "LXC startup timed out.  MXC will exit at the one-minute deadline if cleanup remains blocked; unfinished containers may need manual cleanup.",
            );
        }
        let _startup = STARTUP_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let active = std::mem::take(&mut *lock_slot());
        if let Some(name) = active.name {
            let mut buf_logger = Logger::new(Mode::Buffer);
            if let Some(pid) = active.netns_pid {
                NetworkIptablesManager::force_cleanup(
                    &name,
                    EgressHookPoint::ContainerNetns(pid),
                    active.created,
                    &mut buf_logger,
                );
                IngressManager::force_cleanup(&name, pid, &mut buf_logger);
            }
            if let Err(error) =
                LxcContainer::new(&name, None).destroy_with_reporter(write_fatal_diagnostic)
            {
                write_fatal_diagnostic(&error);
            }
        } else if let Some(container) = active.starting_container {
            if let Err(error) = container.stop() {
                write_fatal_diagnostic(&error);
            }
        }

        // Terminate without flushing another thread's buffered output.
        unsafe { nix::libc::_exit(exit_code) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    /// Serializes the tests that share the watchdog's one registration slot.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// The watchdog flag one test needs.
    struct Watchdog {
        _lock: MutexGuard<'static, ()>,
    }

    impl Watchdog {
        fn installed() -> Self {
            Self::enter(true)
        }

        fn uninstalled() -> Self {
            Self::enter(false)
        }

        // The flag is set directly rather than through `install`, which spawns
        // a watchdog that would exit the test binary on the first Ctrl-C.
        fn enter(installed: bool) -> Self {
            let lock = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            clear_active();
            set_watchdog_override(Some(installed));
            Self { _lock: lock }
        }
    }

    impl Drop for Watchdog {
        fn drop(&mut self) {
            set_watchdog_override(None);
            clear_active();
        }
    }

    fn set_watchdog_override(value: Option<bool>) {
        WATCHDOG_OVERRIDE.with(|slot| slot.set(value));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn earliest_fatal_deadline_exits_with_startup_and_active_locks_held() {
        if std::env::var_os("MXC_TEST_FATAL_DEADLINE_CHILD").is_some() {
            let _startup = STARTUP_LOCK.lock().unwrap();
            let _active = lock_slot();
            arm_cleanup_deadline(elapsed_millis() + EXIT_TIMEOUT.as_millis() as u64, 143);
            arm_cleanup_deadline(
                elapsed_millis() + Duration::from_secs(600).as_millis() as u64,
                143,
            );
            run_deadline_guard(Arc::new(AtomicBool::new(true)));
            unreachable!();
        }

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "earliest_fatal_deadline_exits_with_startup_and_active_locks_held",
                "--test-threads=1",
            ])
            .env("MXC_TEST_FATAL_DEADLINE_CHILD", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(75);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status.and_then(|status| status.code()),
            Some(143),
            "MXC must keep its one-minute fatal deadline after a ten-minute rearm, even with cleanup locks held"
        );
    }

    #[test]
    fn the_watchdogs_view_of_a_container_is_built_and_reset_as_a_single_unit() {
        let _watchdog = Watchdog::installed();

        set_active_created(CreatedResources::for_test(true, true, true, true));
        set_active_pid(4242);
        let (name, created, netns_pid) = active_snapshot();
        assert_eq!(name, None, "no container should be registered yet");
        assert_eq!(
            created,
            CreatedResources::default(),
            "ownership published with no registered container must be discarded"
        );
        assert_eq!(
            netns_pid, None,
            "a netns PID published with no registered container must be discarded"
        );

        set_active("ctr-a");
        set_active_pid(1234);
        let v4_chain_only = CreatedResources::for_test(true, false, false, false);
        set_active_created(v4_chain_only);
        assert_eq!(
            active_snapshot(),
            (Some("ctr-a".to_owned()), v4_chain_only, Some(1234)),
            "a registered container must see its own identity and ownership"
        );

        let both_chains = CreatedResources::for_test(true, true, false, false);
        set_active_created(both_chains);
        assert_eq!(
            active_snapshot().1,
            both_chains,
            "the most recent publication is what the watchdog must act on"
        );

        set_active("ctr-b");
        assert_eq!(
            active_snapshot(),
            (Some("ctr-b".to_owned()), CreatedResources::default(), None),
            "registering a new container must reset ownership and netns PID"
        );
    }

    #[test]
    fn a_host_that_installed_no_watchdog_registers_nothing() {
        let _watchdog = Watchdog::uninstalled();

        set_active("ctr-a");
        set_active_pid(1234);
        set_active_created(CreatedResources::for_test(true, true, true, true));

        assert_eq!(
            active_snapshot(),
            (None, CreatedResources::default(), None),
            "one slot cannot describe the several sandboxes a library host can hold, \
             and no watchdog is running to act on what it holds"
        );
    }

    #[test]
    fn an_open_gate_is_confined_to_the_thread_that_opened_it() {
        let _watchdog = Watchdog::installed();

        let seen_elsewhere = std::thread::spawn(watchdog_installed)
            .join()
            .expect("the probe thread must not panic");

        assert!(
            !seen_elsewhere,
            "a test running beside this one would publish its own chain ownership \
             into the slot, overwriting whichever container this one registered"
        );
    }

    #[test]
    fn each_setter_consults_the_watchdog_gate_for_itself() {
        let _watchdog = Watchdog::installed();

        set_active("ctr-a");
        let registered = CreatedResources::for_test(true, false, false, false);
        set_active_created(registered);
        set_active_pid(1234);
        assert_eq!(
            active_snapshot(),
            (Some("ctr-a".to_owned()), registered, Some(1234)),
            "the gates can only be tested against a slot that is fully populated"
        );

        WATCHDOG_OVERRIDE.with(|slot| slot.set(Some(false)));

        set_active_pid(9999);
        assert_eq!(
            active_snapshot().2,
            Some(1234),
            "set_active_pid must consult the gate rather than lean on the registered \
             container check, which passes here"
        );

        set_active_created(CreatedResources::for_test(true, true, true, true));
        assert_eq!(
            active_snapshot().1,
            registered,
            "set_active_created must consult the gate rather than lean on the \
             registered container check, which passes here"
        );

        set_active("ctr-b");
        assert_eq!(
            active_snapshot().0,
            Some("ctr-a".to_owned()),
            "set_active must consult the gate"
        );
    }

    /// Bubblewrap builds its egress chain through the LXC crate's manager, so
    /// its ownership publications reach this slot even inside `lxc-exec`, where
    /// the watchdog is installed.
    #[test]
    fn a_backend_that_registers_no_container_publishes_no_ownership() {
        use crate::lxc_common::network_iptables::{EgressHookPoint, NetworkIptablesManager};
        use crate::mxc_common::logger::{Logger, Mode};
        use crate::mxc_common::models::{ContainerPolicy, NetworkAction, NetworkEgressPolicy};

        let _watchdog = Watchdog::installed();
        let _fake = crate::lxc_common::network_iptables::test_firewall::install();

        let mut manager =
            NetworkIptablesManager::new("mxc-bwrap-publish-test", EgressHookPoint::Unhooked);
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        manager
            .apply_firewall_rules(&policy, &mut logger)
            .expect("the fake firewall accepts every command");
        assert!(
            manager.rules_applied(),
            "the chain must have been built, or nothing was published to the slot"
        );

        assert_eq!(
            active_snapshot(),
            (None, CreatedResources::default(), None),
            "the watchdog destroys a container by name and this backend has none to give \
             it, so taking the ownership record would aim the removal at whichever LXC \
             container registered last"
        );
    }
}
