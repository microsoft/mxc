// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Guaranteed teardown for the transient one-shot Windows Sandbox runner.
//!
//! A Windows Sandbox VM runs as host processes (`WindowsSandboxServer.exe` /
//! `WindowsSandboxRemoteSession.exe`) that **outlive** the `wxc-exec` process
//! that launched them. A disposable one-shot must therefore guarantee that the
//! VM it started is torn down on *every* exit path:
//!
//! 1. **Normal return / panic unwind** — a stack-owned [`VmTeardownGuard`]
//!    whose `Drop` tears the VM down. It is armed *before* the VM is launched
//!    so no spawn-to-arm leak window exists.
//! 2. **Ctrl-C / Ctrl-Break / console close / logoff / shutdown** — an
//!    explicitly-installed `SetConsoleCtrlHandler` that fires the kills (the
//!    default handler calls `ExitProcess`, skipping Rust destructors). This
//!    handler is installed *only* by the one-shot runner; the state-aware
//!    lifecycle must not inherit auto-teardown of a provisioned VM.
//! 3. **Parent `TerminateProcess` / power loss** — leaves a per-run marker
//!    directory behind that the *next* one-shot run reclaims (see
//!    [`reconcile_existing_vm`]).
//!
//! The guard and the console handler coordinate through a single
//! process-global take-once slot, so the VM is torn down at most once.
//!
//! This is the host-global teardown the daemon already performs
//! (`taskkill /F /IM WindowsSandbox*.exe`). It tears down *any* running
//! Windows Sandbox, not just ours — acceptable because the host allows only a
//! single running instance and one-shot does not support concurrent runs.
//! Scoping teardown to a specific VM is tracked separately for the
//! state-aware backend.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

/// Host processes that keep a Windows Sandbox VM (and its single-instance
/// slot) alive. The `.exe` suffix is REQUIRED: `taskkill /IM` matches the full
/// image name, so omitting it silently fails to find the process.
const WSB_PROCESS_NAMES: [&str; 3] = [
    "WindowsSandbox.exe",
    "WindowsSandboxServer.exe",
    "WindowsSandboxRemoteSession.exe",
];

/// Subdirectory (under the system temp dir) that holds Windows Sandbox scratch
/// state across all execution models.
const MARKERS_SUBDIR: &str = "wxc-wsb";

/// Per-model subdirectory under [`MARKERS_SUBDIR`] for the disposable one-shot
/// runner. Namespacing keeps one-shot's garbage collection from ever touching
/// a future state-aware backend's scratch state, even though both live under
/// the same `wxc-wsb` root.
const ONESHOT_SUBDIR: &str = "oneshot";

/// Marker file written into each per-run directory. Its presence identifies
/// the directory as belonging to a disposable one-shot run.
const MARKER_FILE: &str = "oneshot.marker";

/// Upper bound on how long teardown waits for the host processes to exit on
/// the normal path before proceeding anyway.
const TEARDOWN_POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Shorter teardown poll budget used while unwinding from a panic, so a
/// failing run does not block for the full timeout.
const TEARDOWN_PANIC_POLL_TIMEOUT: Duration = Duration::from_secs(8);

/// Polling interval while waiting for the host processes to exit.
const TEARDOWN_POLL_INTERVAL: Duration = Duration::from_millis(750);

/// Bounded wait for the console handler to acquire the slot before giving up.
const HANDLER_SLOT_WAIT: Duration = Duration::from_secs(5);

/// Minimum age a markerless scratch directory must reach before
/// [`gc_orphan_scratch_dirs`] will remove it. Guards against sweeping a peer
/// run's directory in the brief window before it writes its marker.
const GC_MIN_AGE: Duration = Duration::from_secs(120);

/// Outcome of reconciling the host single-instance slot before a launch.
#[derive(Debug)]
pub(crate) enum Reconcile {
    /// Safe to launch. Carries an optional human-readable note (set when an
    /// orphaned disposable VM was reclaimed) for surfacing in `extended_error`.
    Proceed(Option<String>),
    /// A foreign VM is running; refuse to start a disposable sandbox. Carries
    /// a diagnostic detail string.
    Busy(String),
}

/// Teardown payload parked in the global slot. Carries the per-run scratch
/// directory so a full teardown can remove it after the VM is gone.
#[derive(Debug)]
struct OneShotTeardown {
    run_dir: PathBuf,
}

impl OneShotTeardown {
    /// Full teardown: kill the host processes, wait (bounded) for them to
    /// exit, then — only once the VM is confirmed gone — remove the marker and
    /// scratch directory. Used by the stack guard on normal-return and
    /// panic-unwind paths.
    ///
    /// The marker is removed *before* the directory and *only* when the VM is
    /// confirmed gone. If the VM might still be alive (teardown timed out) the
    /// marker is left in place so the next run reclaims it. This is what keeps
    /// a later foreign/manual sandbox from being mistaken for our orphan: once
    /// our VM is gone our marker is gone too.
    fn full(&self, poll_budget: Duration) {
        let gone = teardown_blocking(poll_budget);
        if gone {
            clear_marker_dir(&self.run_dir);
        }
    }

    /// Kill-only: issue the process kills without waiting. Used by the console
    /// handler, which must return promptly before the OS hard-terminates us.
    fn kill_only(&self) {
        kill_wsb_processes();
    }
}

/// Process-global take-once slot shared by the stack guard and the console
/// handler so the VM is torn down at most once.
static TEARDOWN_SLOT: OnceLock<Mutex<Option<OneShotTeardown>>> = OnceLock::new();

fn slot() -> &'static Mutex<Option<OneShotTeardown>> {
    TEARDOWN_SLOT.get_or_init(|| Mutex::new(None))
}

/// Take the parked teardown payload (if any). Returns `None` if nothing was
/// parked or the other path already took it. Recovers from a poisoned mutex so
/// a panic on one path cannot strand the payload (which would leak the VM).
fn take_parked() -> Option<OneShotTeardown> {
    TEARDOWN_SLOT.get().and_then(|s| {
        let mut guard = s.lock().unwrap_or_else(|p| p.into_inner());
        guard.take()
    })
}

/// Root directory holding per-run one-shot scratch directories.
pub(crate) fn markers_root() -> PathBuf {
    std::env::temp_dir()
        .join(MARKERS_SUBDIR)
        .join(ONESHOT_SUBDIR)
}

/// Write the disposable-run marker (carrying this process's PID) into
/// `run_dir`. The PID lets a later run distinguish an *active* concurrent run
/// (PID still alive → refuse) from a crashed run's orphan (PID dead →
/// reclaim).
///
/// # Errors
/// Returns the underlying I/O error if the marker cannot be written. Marker
/// creation is a required pre-launch step: without it a parent
/// `TerminateProcess` / power loss would leave an unreclaimable VM.
pub(crate) fn write_marker(run_dir: &Path) -> std::io::Result<()> {
    let marker = run_dir.join(MARKER_FILE);
    std::fs::write(&marker, format!("pid={}\n", std::process::id()))
}

/// Read the PID recorded in a per-run directory's marker, if present and
/// parseable.
fn read_marker_pid(run_dir: &Path) -> Option<u32> {
    let contents = std::fs::read_to_string(run_dir.join(MARKER_FILE)).ok()?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .and_then(|v| v.trim().parse::<u32>().ok())
}

/// Remove a per-run scratch directory, deleting its marker file *first* so
/// that even if the directory removal fails (e.g. a file still mapped) the
/// directory can no longer be mistaken for a reclaimable disposable run.
///
/// The recursive removal is best-effort and frequently fails for the *current*
/// run: the lingering `vmmem*` residue keeps the mapped rendezvous folder open
/// after the VM exits. The markerless directory left behind is harmless (it is
/// ignored by [`reconcile_existing_vm`]) and is swept by
/// [`gc_orphan_scratch_dirs`] on a later run once the handles are released.
fn clear_marker_dir(run_dir: &Path) {
    let _ = std::fs::remove_file(run_dir.join(MARKER_FILE));
    let _ = std::fs::remove_dir_all(run_dir);
}

/// Whether `pid` refers to a currently-running process.
///
/// Used to tell an active concurrent disposable run (refuse) from a crashed
/// run's orphan (reclaim). Conservative on ambiguity: an unopenable but
/// possibly-live process is better treated as alive (refuse) than as dead
/// (which could reclaim a peer's live VM). `OpenProcess` failing with
/// "invalid parameter" means the PID does not exist → dead.
fn pid_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, STILL_ACTIVE, WIN32_ERROR,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        return false;
    }
    // SAFETY: PID is a plain integer; the returned handle is closed on every
    // path. `GetExitCodeProcess` writes a single u32.
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => {
                let mut code: u32 = 0;
                let alive =
                    GetExitCodeProcess(handle, &mut code).is_ok() && code == STILL_ACTIVE.0 as u32;
                let _ = CloseHandle(handle);
                alive
            }
            Err(e) => {
                // Only a non-existent PID is treated as dead; any other error
                // (e.g. access denied) is treated as possibly-alive.
                WIN32_ERROR::from_error(&e) != Some(ERROR_INVALID_PARAMETER)
            }
        }
    }
}

/// List per-run scratch directories under `markers_root` that carry the
/// disposable-run marker.
fn list_marker_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return dirs;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join(MARKER_FILE).exists() {
            dirs.push(path);
        }
    }
    dirs
}

/// Best-effort garbage-collect leftover scratch directories that no longer
/// carry a marker.
///
/// A finished disposable run removes its marker once its VM is gone, but the
/// directory itself often cannot be deleted by that run: the lingering
/// SYSTEM-owned `vmmem*` / `vmcompute` residue retains handles on the
/// VSMB-mapped rendezvous folder for some time after the VM exits. Sweeping
/// markerless directories at the *start* of a later run reclaims that litter
/// once the OS has released the handles.
///
/// Only markerless directories are removed. Directories that still carry a
/// marker are owned by an active or orphaned run and are handled by
/// [`reconcile_existing_vm`]; they are deliberately left untouched here. This
/// runs before the caller creates its own run directory, so it can never
/// delete the in-flight run's scratch space.
///
/// A directory is additionally skipped unless it is older than
/// [`GC_MIN_AGE`]. This closes the otherwise-microsecond race in which a
/// peer run has created its directory but not yet written its marker: a
/// freshly created directory is never swept, so a peer's not-yet-marked run is
/// safe even though concurrent one-shot is already discouraged.
pub(crate) fn gc_orphan_scratch_dirs(root: &Path) {
    gc_orphan_scratch_dirs_with_age(root, GC_MIN_AGE);
}

fn gc_orphan_scratch_dirs_with_age(root: &Path, min_age: Duration) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && !path.join(MARKER_FILE).exists() && dir_older_than(&path, min_age) {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// Whether `path`'s last-modified time is at least `min_age` in the past.
/// On any metadata/clock error the directory is treated as *too young* to
/// remove, erring toward leaving litter rather than deleting a live peer's
/// directory.
fn dir_older_than(path: &Path, min_age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok())
        .map(|age| age >= min_age)
        .unwrap_or(false)
}

/// Reconcile the host single-instance slot before launching a disposable VM.
///
/// Classifies any existing per-run markers by liveness, then decides:
/// - **VM running + a live-PID marker** → another disposable run is active;
///   refuse (the host allows only one instance) rather than kill its VM.
/// - **VM running + no marker at all** → a foreign sandbox (a user's manual
///   instance, or a future state-aware VM). Refuse rather than kill it. This
///   is the core "never kill a sandbox we don't own" guarantee.
/// - **VM running + only dead-PID markers** → an orphan from a crashed
///   disposable run. Reclaim it (tear down + clean the stale markers).
/// - **No VM** → clean up dead-PID marker directories and proceed.
/// - **Probe failed** → conservatively refuse (we cannot prove the slot is
///   free, and proceeding risks the guard later killing a foreign sandbox).
pub(crate) fn reconcile_existing_vm(root: &Path) -> Reconcile {
    let running = match wsb_vm_running() {
        Some(r) => r,
        None => {
            return Reconcile::Busy(
                "could not determine whether a Windows Sandbox VM is running".to_string(),
            )
        }
    };

    let markers = list_marker_dirs(root);
    let mut any_live = false;
    let mut dead_dirs: Vec<PathBuf> = Vec::new();
    for dir in &markers {
        match read_marker_pid(dir) {
            Some(pid) if pid_alive(pid) => any_live = true,
            _ => dead_dirs.push(dir.clone()),
        }
    }

    if running {
        if any_live {
            return Reconcile::Busy("another disposable Windows Sandbox run is active".to_string());
        }
        if markers.is_empty() {
            return Reconcile::Busy(
                "a Windows Sandbox VM is running with no disposable-run marker".to_string(),
            );
        }
        eprintln!(
            "[one-shot] warning: reclaiming an orphaned disposable Windows Sandbox VM \
             (found {} stale marker dir(s))",
            dead_dirs.len()
        );
        teardown_blocking(TEARDOWN_POLL_TIMEOUT);
        for dir in &dead_dirs {
            clear_marker_dir(dir);
        }
        Reconcile::Proceed(Some(format!(
            "reclaimed an orphaned disposable Windows Sandbox VM from a prior run \
             ({} stale marker dir(s) cleaned)",
            dead_dirs.len()
        )))
    } else {
        // No VM: clean dead-PID dirs only. A live-PID dir with no VM is a peer
        // mid-launch; leave it alone.
        for dir in &dead_dirs {
            clear_marker_dir(dir);
        }
        Reconcile::Proceed(None)
    }
}

/// Check whether any Windows Sandbox host process is currently running.
///
/// Only `WindowsSandbox*` host processes count; the SYSTEM-owned `vmmem*`
/// Hyper-V memory processes linger harmlessly after teardown and do not block
/// a fresh launch, so they are deliberately excluded.
///
/// Returns `None` if the probe itself could not be run, so callers can decide
/// how to treat the ambiguity (reconcile refuses; teardown stops polling).
fn wsb_vm_running() -> Option<bool> {
    // Toolhelp32 snapshot (no PowerShell). A snapshot failure is surfaced as
    // `None` so the ambiguity is visible to callers.
    crate::control_plane::enumerate_pids_with_prefix("WindowsSandbox")
        .ok()
        .map(|pids| !pids.is_empty())
}

/// Issue `taskkill /F /IM` for each Windows Sandbox host process, without
/// waiting. Errors are best-effort: a non-zero exit means the process was not
/// running, which is not an error worth surfacing.
fn kill_wsb_processes() {
    for name in WSB_PROCESS_NAMES {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Kill the host processes, then poll (up to `poll_budget`) until they are
/// gone. Best-effort and non-panicking — safe to call while unwinding.
///
/// Returns `true` only if the VM was *confirmed* gone. A probe failure or a
/// timeout returns `false`, so callers leave the run marker in place for the
/// next run to reclaim rather than deleting it prematurely.
fn teardown_blocking(poll_budget: Duration) -> bool {
    kill_wsb_processes();
    let deadline = Instant::now() + poll_budget;
    loop {
        if wsb_vm_running() == Some(false) {
            return true;
        }
        if Instant::now() >= deadline {
            eprintln!(
                "[one-shot] warning: Windows Sandbox processes still running after teardown wait"
            );
            return false;
        }
        std::thread::sleep(TEARDOWN_POLL_INTERVAL);
    }
}

/// Stack-owned witness that guarantees the disposable VM is torn down on every
/// normal-return and panic-unwind path out of the one-shot runner.
///
/// Construct it via [`VmTeardownGuard::arm`] *immediately before* launching the
/// VM. `Drop` is best-effort and never panics (it may run while unwinding).
#[derive(Debug)]
pub(crate) struct VmTeardownGuard;

impl VmTeardownGuard {
    /// Arm one-shot teardown and return the stack guard.
    ///
    /// Parks a teardown payload for `run_dir` so the console handler can fire
    /// it, and installs the console-control handler (once per process). Must be
    /// called only by the one-shot runner — installing the handler makes Ctrl-C
    /// tear down a running VM, which is correct only for disposable runs.
    pub(crate) fn arm(run_dir: PathBuf) -> Self {
        {
            let mut guard = slot().lock().unwrap_or_else(|p| p.into_inner());
            *guard = Some(OneShotTeardown { run_dir });
        }
        install_ctrl_handler();
        Self
    }
}

impl Drop for VmTeardownGuard {
    fn drop(&mut self) {
        let budget = if std::thread::panicking() {
            TEARDOWN_PANIC_POLL_TIMEOUT
        } else {
            TEARDOWN_POLL_TIMEOUT
        };
        if let Some(token) = take_parked() {
            token.full(budget);
        }
    }
}

/// Windows console-control handler. Called by the OS on Ctrl-C, Ctrl-Break,
/// console close, logoff, and shutdown — paths that otherwise skip Rust
/// destructors. Takes the parked teardown payload and fires the kills only
/// (no wait), then returns `FALSE` so the next handler in the chain (the
/// default handler that terminates the process) still runs.
///
/// The slot mutex is held only long enough to `take()` the payload; the kills
/// run after the lock is released so teardown is not serialized under it.
unsafe extern "system" fn wsb_ctrl_handler(_ctrl_type: u32) -> windows::core::BOOL {
    let taken = TEARDOWN_SLOT.get().and_then(|s| {
        let deadline = Instant::now() + HANDLER_SLOT_WAIT;
        loop {
            if let Ok(mut guard) = s.try_lock() {
                break guard.take();
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    if let Some(token) = taken {
        token.kill_only();
    }
    // FALSE = "not fully handled; run the next handler (the default one that
    // calls ExitProcess)".
    windows::core::BOOL(0)
}

/// Install the console-control handler once per process.
fn install_ctrl_handler() {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: `wsb_ctrl_handler` has the correct `extern "system"` ABI;
        // `Add = TRUE` merely appends to the OS handler chain.
        let _ = unsafe { SetConsoleCtrlHandler(Some(wsb_ctrl_handler), true) };
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_marker_dirs_finds_only_marked_dirs() {
        let root = tempfile::tempdir().unwrap();
        let marked = root.path().join("run-a");
        let unmarked = root.path().join("run-b");
        std::fs::create_dir_all(&marked).unwrap();
        std::fs::create_dir_all(&unmarked).unwrap();
        write_marker(&marked).unwrap();

        let found = list_marker_dirs(root.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], marked);
    }

    #[test]
    fn list_marker_dirs_empty_for_missing_root() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("does-not-exist");
        assert!(list_marker_dirs(&missing).is_empty());
    }

    #[test]
    fn write_marker_creates_marker_file() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path()).unwrap();
        assert!(dir.path().join(MARKER_FILE).exists());
    }

    #[test]
    fn write_then_read_marker_round_trips_pid() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path()).unwrap();
        assert_eq!(read_marker_pid(dir.path()), Some(std::process::id()));
    }

    #[test]
    fn read_marker_pid_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_marker_pid(dir.path()), None);
    }

    #[test]
    fn clear_marker_dir_removes_dir_and_marker() {
        let root = tempfile::tempdir().unwrap();
        let run = root.path().join("run-x");
        std::fs::create_dir_all(&run).unwrap();
        write_marker(&run).unwrap();
        clear_marker_dir(&run);
        assert!(!run.exists());
    }

    #[test]
    fn gc_removes_only_markerless_dirs() {
        let root = tempfile::tempdir().unwrap();
        let leftover = root.path().join("finished");
        let active = root.path().join("active");
        std::fs::create_dir_all(leftover.join("rendezvous")).unwrap();
        std::fs::create_dir_all(&active).unwrap();
        write_marker(&active).unwrap();
        // Age threshold of zero: any markerless dir is eligible.
        gc_orphan_scratch_dirs_with_age(root.path(), Duration::ZERO);

        assert!(!leftover.exists(), "markerless leftover should be swept");
        assert!(active.exists(), "marked dir must be preserved");
    }

    #[test]
    fn gc_skips_young_markerless_dirs() {
        let root = tempfile::tempdir().unwrap();
        let young = root.path().join("just-created");
        std::fs::create_dir_all(&young).unwrap();
        // A large age guard means a freshly created dir is never swept.
        gc_orphan_scratch_dirs_with_age(root.path(), Duration::from_secs(3600));

        assert!(young.exists(), "a freshly created dir must not be swept");
    }

    #[test]
    fn current_process_pid_is_alive() {
        assert!(pid_alive(std::process::id()));
    }

    #[test]
    fn unused_high_pid_is_not_alive() {
        // PIDs are multiples of 4 on Windows and this is far above any real
        // PID, so it should not resolve to a live process.
        assert!(!pid_alive(0xFFFF_FFF0));
    }
}
