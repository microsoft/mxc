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
//! Teardown is **ownership-scoped**: the slot carries a [`VmOwnership`] state
//! (mirroring the state-aware daemon) that records how far VM ownership has
//! progressed. Cleanup only kills processes this run provably launched — it
//! never issues an image-wide `taskkill /F /IM WindowsSandbox*`, so a foreign
//! or manually-opened sandbox is never disturbed. Host-global serialisation of
//! the single VM slot is provided by the `Local\wxc-wsb-vm` mutex acquired by
//! the one-shot runner for the whole run.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::control_plane::{
    enumerate_processes_with_prefix, plan_kill_set, process_creation_time,
    running_process_creation_time, terminate_processes, TeardownOutcome, VmOwnership, VmProcId,
};

/// Image-name prefix shared by every Windows Sandbox host process
/// (`WindowsSandbox.exe`, `WindowsSandboxServer.exe`,
/// `WindowsSandboxRemoteSession.exe`). Used both as the liveness probe and as
/// the enumeration filter for scoped teardown. The SYSTEM-owned `vmmem*`
/// Hyper-V memory processes do not share this prefix and are deliberately
/// excluded (they linger harmlessly after teardown).
const WSB_PROCESS_PREFIX: &str = "WindowsSandbox";

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

/// JSON marker written into each per-run scratch directory. Records the
/// launching process's identity (so a later run can distinguish a live
/// concurrent run from a crashed one) and — after launch — positive proof of
/// the VM host processes this run owns (so a later run can reclaim our orphan
/// without ever killing a VM it cannot prove is ours).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OneShotMarker {
    /// PID of the `wxc-exec` process that owns this run.
    launcher_pid: u32,
    /// Creation time of `launcher_pid` (Win32 `FILETIME`, 100ns ticks). Pairs
    /// with the PID to defeat PID reuse. `None` if it could not be captured, in
    /// which case the launcher is treated as *dead-or-unknown* (never as a live
    /// blocker) so a recycled PID can never wedge reclaim.
    #[serde(default)]
    launcher_creation_time: Option<u64>,
    /// Identities of the Windows Sandbox host processes this run launched,
    /// captured just after launch. Empty before launch (and on the narrow
    /// crash-during-boot window). The *positive ownership proof* used by a later
    /// run's reconcile: an orphaned VM is only reclaimed when the running
    /// sandbox processes intersect this set.
    #[serde(default)]
    vm_processes: Vec<VmProcId>,
}

/// Per-marker liveness/proof state, distilled from an [`OneShotMarker`] for the
/// pure [`classify_reconcile`].
#[derive(Debug, Clone)]
struct MarkerState {
    /// Whether the launching process is *strongly* alive (PID present AND
    /// creation time matches). A missing creation time is treated as not-alive.
    launcher_alive: bool,
    /// The recorded VM-process ownership proof.
    vm_processes: Vec<VmProcId>,
}

/// Why a reconcile refused to launch.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BusyReason {
    /// The liveness probe itself failed; we cannot prove the slot is free.
    ProbeFailed,
    /// Another disposable run is active (a strongly-live launcher).
    ActiveRun,
    /// A VM is running but no marker positively proves we own it.
    ForeignUnprovable,
}

impl BusyReason {
    fn message(&self) -> String {
        match self {
            BusyReason::ProbeFailed => {
                "could not determine whether a Windows Sandbox VM is running".to_string()
            }
            BusyReason::ActiveRun => "another disposable Windows Sandbox run is active".to_string(),
            BusyReason::ForeignUnprovable => {
                "a Windows Sandbox VM is running that this run cannot prove it owns".to_string()
            }
        }
    }
}

/// Pure reconcile decision, derived from the probe result, the live VM process
/// set, and the per-marker states so it is unit-testable without a real VM.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReconcileDecision {
    /// No VM is running: launch normally (caller cleans dead-launcher dirs).
    Proceed,
    /// A running VM is provably an orphan of a prior disposable run (its live
    /// processes intersect a recorded proof): tear the orphan down using the
    /// **prior recorded proof** as the kill seed (NOT the live snapshot), then
    /// launch. Seeding with the live snapshot would promote any foreign
    /// `WindowsSandbox*` process observed at reconcile time into "proof" once
    /// the kill planner (`plan_kill_set`) starts honoring intersection
    /// semantics. The caller passes `proof` to `plan_kill_set(Owned(proof),
    /// snapshot)` to compute the actual kill set (intersect ⇒ union; disjoint
    /// ⇒ proof only — never enumerate-kill foreign).
    ReclaimThenProceed { proof: Vec<VmProcId> },
    /// Refuse to launch.
    Busy(BusyReason),
}

/// Decide what to do about the host single-instance VM slot before launching.
///
/// Ordering (per design): probe-failure → `Busy(ProbeFailed)`; a running VM
/// with any strongly-live launcher → `Busy(ActiveRun)`; a running VM whose
/// recorded proofs intersect the live set → `ReclaimThenProceed`; a running VM
/// with no proof intersection → `Busy(ForeignUnprovable)`; no VM → `Proceed`.
///
/// Launcher liveness is intentionally *strong* (PID + creation time both
/// match). A marker whose launcher is dead-or-unknown must never block a
/// proof-based reclaim, which is what avoids a recycled-PID wedge.
///
/// The reclaim seed MUST be the prior recorded proof, not the live snapshot:
/// seeding with the snapshot would let `plan_kill_set` promote a foreign VM
/// observed in the snapshot into "ownership" and kill it.
fn classify_reconcile(
    running: Option<bool>,
    current_vm: &[VmProcId],
    markers: &[MarkerState],
) -> ReconcileDecision {
    let running = match running {
        None => return ReconcileDecision::Busy(BusyReason::ProbeFailed),
        Some(r) => r,
    };
    if !running {
        return ReconcileDecision::Proceed;
    }
    if markers.iter().any(|m| m.launcher_alive) {
        return ReconcileDecision::Busy(BusyReason::ActiveRun);
    }
    // All launchers are dead-or-unknown. Reclaim only on positive proof: a
    // recorded VM process must still be live. Collect ALL recorded proofs
    // from intersecting markers (a single launch may have spawned multiple
    // host processes, and a marker may be partial). Returning the union of
    // recorded proofs (rather than `current_vm`) is what closes the GPT-
    // identified latent bug: the kill seed is bounded by recorded
    // identities and `plan_kill_set` can apply its intersection check
    // soundly.
    let mut proof: Vec<VmProcId> = Vec::new();
    let mut any_intersect = false;
    for marker in markers {
        let intersects = marker.vm_processes.iter().any(|p| current_vm.contains(p));
        if intersects {
            any_intersect = true;
            for p in &marker.vm_processes {
                if !proof.contains(p) {
                    proof.push(*p);
                }
            }
        }
    }
    if any_intersect {
        ReconcileDecision::ReclaimThenProceed { proof }
    } else {
        ReconcileDecision::Busy(BusyReason::ForeignUnprovable)
    }
}

/// Teardown payload parked in the global slot. Carries the per-run scratch
/// directory (so a full teardown can remove it once the VM is gone) and the
/// current [`VmOwnership`] (so cleanup can decide, via [`decide_cleanup`],
/// whether and what it may kill).
#[derive(Debug)]
struct OneShotTeardown {
    run_dir: PathBuf,
    ownership: VmOwnership,
}

impl OneShotTeardown {
    /// Full teardown: plan via [`plan_kill_set`], terminate, wait for confirmed
    /// exit, then — only when the polling loop returns [`TeardownOutcome::ConfirmedGone`] —
    /// remove the marker and scratch directory. Used by the stack guard on
    /// normal-return and panic paths.
    ///
    /// The marker is removed *only* when the VM is confirmed gone. If teardown
    /// could not confirm it (timeout / probe failure) the marker is left so the
    /// next run reclaims it: once our VM is gone, our marker is gone too, which
    /// is what keeps a later foreign sandbox from being mistaken for our orphan.
    ///
    /// `kill_only` (the Ctrl-C path) intentionally shares the same kill-plan
    /// derivation so an asymmetry cannot leak a VM on Ctrl-C that the normal
    /// drop would have torn down.
    fn full(&self, poll_budget: Duration) {
        let snapshot = enumerate_processes_with_prefix(WSB_PROCESS_PREFIX).unwrap_or_default();
        let plan = plan_kill_set(&self.ownership, &snapshot);
        match plan {
            None => {
                // NotLaunched / LaunchInFlight / LaunchSucceededNoProof+empty
                // snapshot. Either nothing was launched (safe to clear) or
                // there is nothing left to confirm (also safe to clear), or
                // we cannot prove ownership (must leak — leave the marker).
                match &self.ownership {
                    VmOwnership::NotLaunched | VmOwnership::LaunchSucceededNoProof => {
                        // Empty live set ⇒ nothing to wait for; safe to clear.
                        clear_marker_dir(&self.run_dir);
                    }
                    VmOwnership::LaunchInFlight => {
                        // Ambiguous launch: leak the marker for the next run
                        // to reconcile rather than presume ownership.
                    }
                    VmOwnership::Owned(_) => {
                        // plan_kill_set(Owned, _) is always Some.
                        unreachable!("Owned with any snapshot always returns Some kill plan");
                    }
                }
            }
            Some(kill_set) => match teardown_owned_blocking(&kill_set, poll_budget) {
                TeardownOutcome::ConfirmedGone => {
                    clear_marker_dir(&self.run_dir);
                }
                TeardownOutcome::StillRunning(_) | TeardownOutcome::ProbeFailed => {
                    // Preserve the marker so the next run can reclaim.
                }
            },
        }
    }

    /// Kill-only: issue the scoped process kills without waiting. Used by the
    /// console handler, which must return promptly before the OS hard-
    /// terminates us. Honours ownership exactly like [`full`] — drives off
    /// the SAME [`plan_kill_set`] so Ctrl-C cannot leak a VM that the normal
    /// drop would have torn down.
    fn kill_only(&self) {
        let snapshot = enumerate_processes_with_prefix(WSB_PROCESS_PREFIX).unwrap_or_default();
        if let Some(kill_set) = plan_kill_set(&self.ownership, &snapshot) {
            terminate_processes(&kill_set);
        }
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

/// Update the parked payload's [`VmOwnership`]. Called by the one-shot runner
/// as the launch progresses (arm → `LaunchInFlight` → `LaunchSucceededNoProof`
/// → `Owned`). The critical section is tiny — it performs no I/O, no awaits,
/// and no marker rewrite while the slot mutex is held — so it cannot deadlock
/// the guard or the console handler.
pub(crate) fn set_vm_ownership(ownership: VmOwnership) {
    if let Some(s) = TEARDOWN_SLOT.get() {
        let mut guard = s.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(token) = guard.as_mut() {
            token.ownership = ownership;
        }
    }
}

/// Root directory holding per-run one-shot scratch directories.
pub(crate) fn markers_root() -> PathBuf {
    std::env::temp_dir()
        .join(MARKERS_SUBDIR)
        .join(ONESHOT_SUBDIR)
}

/// Ensure the one-shot markers root exists, is owned by us, and is owner-only
/// DACL'd **before any per-run marker is read out of it**. A marker's recorded
/// `vm_processes` are trusted as positive ownership proof to authorize scoped
/// teardown; on a shared temp dir a cross-user attacker could otherwise
/// pre-plant a forged marker whose proof intersects a live *foreign* VM and
/// trick reconcile into tearing it down. Owner-verifying + locking the root
/// first refuses an attacker-pre-created root (fails closed). Idempotent.
pub(crate) fn secure_markers_root() -> anyhow::Result<()> {
    crate::control_plane::ensure_secure_dir(&markers_root())
}

/// Atomically write `marker` into `run_dir` (temp file + rename) so a crash
/// mid-write cannot leave a half-written, unparseable marker.
fn write_marker_struct(run_dir: &Path, marker: &OneShotMarker) -> std::io::Result<()> {
    let path = run_dir.join(MARKER_FILE);
    let tmp = run_dir.join(format!("{MARKER_FILE}.tmp"));
    let bytes = serde_json::to_vec(marker)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &path)
}

/// Write the initial disposable-run marker into `run_dir` *before* launch. It
/// records this process's identity (PID + creation time) and an empty VM-proof
/// set; the proof is filled in by [`rewrite_marker_with_proof`] right after the
/// VM launches.
///
/// # Errors
/// Returns the underlying I/O error if the marker cannot be written. Marker
/// creation is a required pre-launch step: without it a parent
/// `TerminateProcess` / power loss would leave an unreclaimable VM.
pub(crate) fn write_marker(run_dir: &Path) -> std::io::Result<()> {
    let pid = std::process::id();
    let marker = OneShotMarker {
        launcher_pid: pid,
        launcher_creation_time: process_creation_time(pid),
        vm_processes: Vec::new(),
    };
    write_marker_struct(run_dir, &marker)
}

/// Rewrite the marker with positive VM-ownership proof captured right after
/// launch. Preserves the launcher identity. Called before the rendezvous wait
/// so a crash during the (long) boot still leaves a reclaimable record.
///
/// # Errors
/// Returns the underlying I/O error if the marker cannot be rewritten. The
/// caller treats this as fatal and tears the VM down rather than leave a
/// proof-less marker that a later run could not reclaim.
pub(crate) fn rewrite_marker_with_proof(
    run_dir: &Path,
    vm_processes: &[VmProcId],
) -> std::io::Result<()> {
    let pid = std::process::id();
    let marker = OneShotMarker {
        launcher_pid: pid,
        launcher_creation_time: process_creation_time(pid),
        vm_processes: vm_processes.to_vec(),
    };
    write_marker_struct(run_dir, &marker)
}

/// Read and parse a per-run directory's marker, if present and well-formed.
fn read_marker(run_dir: &Path) -> Option<OneShotMarker> {
    let bytes = std::fs::read(run_dir.join(MARKER_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether the launcher recorded in `marker` is *strongly* alive: a process
/// with its PID is **currently running** AND its creation time matches the
/// recorded one. Both conditions are required:
/// - The *running* check ([`running_process_creation_time`]) excludes a
///   terminated launcher whose kernel object lingers because a parent retains a
///   handle — such a process still opens by PID and reports its original
///   creation time, so without the running check a crashed launcher would be
///   mistaken for a live one and wedge reclaim forever.
/// - The *creation-time* match defeats PID reuse. A missing recorded creation
///   time yields `false` (dead-or-unknown), so a recycled PID can never be
///   mistaken for the original launcher.
fn launcher_strongly_alive(marker: &OneShotMarker) -> bool {
    match marker.launcher_creation_time {
        Some(ct) => running_process_creation_time(marker.launcher_pid) == Some(ct),
        None => false,
    }
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
/// A finished run removes its marker, but often cannot delete its own directory:
/// SYSTEM-owned `vmmem*` / `vmcompute` residue keeps handles on the VSMB-mapped
/// rendezvous folder for a while after the VM exits. A later run sweeps the
/// markerless litter once the OS has released those handles.
///
/// Markered directories belong to an active or orphaned run and are left to
/// [`reconcile_existing_vm`]. This runs before the caller creates its own run
/// dir, and skips anything younger than [`GC_MIN_AGE`], so a peer run that has
/// created its directory but not yet written its marker is never swept.
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
/// Gathers the probe result, the live `WindowsSandbox*` process set, and each
/// per-run marker's launcher-liveness + ownership-proof, then defers the
/// decision to the pure [`classify_reconcile`]:
/// - **VM running + a strongly-live launcher** → another disposable run is
///   active; refuse (the host allows only one instance) rather than kill it.
/// - **VM running + a recorded proof intersecting the live set** → an orphan
///   from a crashed disposable run. Reclaim it (scoped teardown of exactly the
///   live VM, then clean the stale markers — but only once teardown confirms
///   the VM is gone).
/// - **VM running + no proof intersection** → a foreign sandbox (a user's
///   manual instance, or a future state-aware VM). Refuse rather than kill it.
///   This is the core "never kill a sandbox we don't own" guarantee.
/// - **No VM** → clean up dead-launcher marker directories and proceed.
/// - **Probe failed** → conservatively refuse.
pub(crate) fn reconcile_existing_vm(root: &Path) -> Reconcile {
    let running = wsb_vm_running();

    // A Toolhelp32 snapshot failure here (AV interference, handle exhaustion,
    // transient kernel error) must not collapse to an EMPTY process list via
    // `unwrap_or_default()`: the classifier would then see "no WindowsSandbox*
    // processes" and launch a fresh VM even though one may be running,
    // violating the single-instance constraint and producing either a
    // Windows-side UI dialog or a hung process. Fail safe instead: refuse to act on
    // unknown VM state and ask the operator to retry.
    let current_vm = match enumerate_processes_with_prefix(WSB_PROCESS_PREFIX) {
        Ok(v) => v,
        Err(e) => {
            return Reconcile::Busy(format!(
                "could not enumerate WindowsSandbox host processes (Toolhelp32 snapshot \
                 failed: {e}); refusing to launch a new VM because doing so on top of an \
                 unknown live VM would violate the host single-instance constraint. Retry; \
                 if persistent, restart the Windows Sandbox service."
            ));
        }
    };

    let marker_dirs = list_marker_dirs(root);
    let mut states: Vec<MarkerState> = Vec::with_capacity(marker_dirs.len());
    let mut dead_dirs: Vec<PathBuf> = Vec::new();
    for dir in &marker_dirs {
        match read_marker(dir) {
            Some(marker) => {
                let alive = launcher_strongly_alive(&marker);
                if !alive {
                    dead_dirs.push(dir.clone());
                }
                states.push(MarkerState {
                    launcher_alive: alive,
                    vm_processes: marker.vm_processes,
                });
            }
            None => {
                // Unparseable / absent marker: a dead launcher with no proof.
                dead_dirs.push(dir.clone());
                states.push(MarkerState {
                    launcher_alive: false,
                    vm_processes: Vec::new(),
                });
            }
        }
    }

    if std::env::var_os("WXC_WSB_RECONCILE_DEBUG").is_some() {
        eprintln!(
            "[one-shot][reconcile-debug] running={running:?} current_vm={current_vm:?} \
             marker_dirs={} states={states:?}",
            marker_dirs.len()
        );
        for dir in &marker_dirs {
            eprintln!(
                "[one-shot][reconcile-debug]   dir={} marker={:?}",
                dir.display(),
                read_marker(dir)
            );
        }
    }

    match classify_reconcile(running, &current_vm, &states) {
        ReconcileDecision::Busy(reason) => Reconcile::Busy(reason.message()),
        ReconcileDecision::Proceed => {
            // No VM: clean dead-launcher dirs only. A strongly-live launcher dir
            // with no VM is a peer mid-launch; leave it alone.
            for dir in &dead_dirs {
                clear_marker_dir(dir);
            }
            Reconcile::Proceed(None)
        }
        ReconcileDecision::ReclaimThenProceed { proof } => {
            eprintln!(
                "[one-shot] warning: reclaiming an orphaned disposable Windows Sandbox VM \
                 (found {} stale marker dir(s), {} recorded host process identity/identities \
                 from intersecting markers)",
                dead_dirs.len(),
                proof.len()
            );
            // Seed kill via plan_kill_set with the RECORDED proof (not the
            // live snapshot). Same reasoning as the daemon's startup reclaim:
            // an intersection check on (proof, snapshot) ensures any foreign
            // WindowsSandbox* process visible at reconcile time is excluded
            // from the kill set. Seeding with `current_vm` (the live snapshot)
            // instead would let a foreign VM be promoted into the kill set.
            let kill_plan =
                plan_kill_set(&VmOwnership::Owned(proof), &current_vm).unwrap_or_default();
            match teardown_owned_blocking(&kill_plan, TEARDOWN_POLL_TIMEOUT) {
                TeardownOutcome::ConfirmedGone => {
                    for dir in &dead_dirs {
                        clear_marker_dir(dir);
                    }
                    Reconcile::Proceed(Some(format!(
                        "reclaimed an orphaned disposable Windows Sandbox VM from a prior run \
                         ({} stale marker dir(s) cleaned)",
                        dead_dirs.len()
                    )))
                }
                TeardownOutcome::StillRunning(remaining) => Reconcile::Busy(format!(
                    "failed to tear down an orphaned disposable Windows Sandbox VM ({} host \
                     process(es) still alive: {:?})",
                    remaining.len(),
                    remaining
                )),
                TeardownOutcome::ProbeFailed => Reconcile::Busy(
                    "failed to tear down an orphaned disposable Windows Sandbox VM (liveness \
                     probe failed)"
                        .to_string(),
                ),
            }
        }
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
    crate::control_plane::enumerate_pids_with_prefix(WSB_PROCESS_PREFIX)
        .ok()
        .map(|pids| !pids.is_empty())
}

/// Tear down a Windows Sandbox VM with an already-planned kill set, then poll
/// (up to `poll_budget`) until the `WindowsSandbox*` processes are gone.
/// Best-effort and non-panicking — safe to call while unwinding.
///
/// **The kill set is computed upstream by [`plan_kill_set`].** This split
/// (planner / killer) matches the daemon-side [`crate::vm::teardown_via_plan`]
/// so the two backends derive their kill sets the same way; neither can kill a
/// foreign VM that merely appears in its snapshot-to-kill window.
///
/// Returns a [`TeardownOutcome`] tri-state so callers can decide whether to
/// clear the marker: only on
/// [`TeardownOutcome::ConfirmedGone`] is the live set provably empty; on
/// `StillRunning` and `ProbeFailed` the marker MUST persist so the next run
/// can reclaim by positive proof intersection.
fn teardown_owned_blocking(kill_set: &[VmProcId], poll_budget: Duration) -> TeardownOutcome {
    terminate_processes(kill_set);

    let deadline = Instant::now() + poll_budget;
    loop {
        match wsb_vm_running() {
            Some(false) => return TeardownOutcome::ConfirmedGone,
            Some(true) => {
                if Instant::now() >= deadline {
                    let remaining =
                        enumerate_processes_with_prefix(WSB_PROCESS_PREFIX).unwrap_or_default();
                    eprintln!(
                        "[one-shot] warning: {} Windows Sandbox host process(es) still running \
                         after scoped teardown wait",
                        remaining.len()
                    );
                    return TeardownOutcome::StillRunning(remaining);
                }
            }
            None => {
                if Instant::now() >= deadline {
                    eprintln!(
                        "[one-shot] warning: liveness probe failed during teardown wait; \
                         preserving marker"
                    );
                    return TeardownOutcome::ProbeFailed;
                }
            }
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
            *guard = Some(OneShotTeardown {
                run_dir,
                ownership: VmOwnership::NotLaunched,
            });
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
    fn write_then_read_marker_round_trips_identity() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path()).unwrap();
        let marker = read_marker(dir.path()).expect("marker should parse");
        assert_eq!(marker.launcher_pid, std::process::id());
        assert!(marker.vm_processes.is_empty());
    }

    #[test]
    fn read_marker_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_marker(dir.path()).is_none());
    }

    #[test]
    fn rewrite_marker_preserves_launcher_and_adds_proof() {
        let dir = tempfile::tempdir().unwrap();
        write_marker(dir.path()).unwrap();
        let proof = vec![
            VmProcId {
                pid: 1234,
                creation_time: 42,
            },
            VmProcId {
                pid: 5678,
                creation_time: 99,
            },
        ];
        rewrite_marker_with_proof(dir.path(), &proof).unwrap();
        let marker = read_marker(dir.path()).expect("marker should parse");
        assert_eq!(marker.launcher_pid, std::process::id());
        assert_eq!(marker.vm_processes, proof);
    }

    #[test]
    fn legacy_text_marker_is_unparseable() {
        // A pre-JSON `pid=N` marker must not parse (treated as a dead launcher
        // with no proof), never as a live launcher.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MARKER_FILE), "pid=1234\n").unwrap();
        assert!(read_marker(dir.path()).is_none());
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

    /// Serialises the few tests that arm the process-global [`VmTeardownGuard`]
    /// (which mutates the single [`TEARDOWN_SLOT`]) so they cannot race.
    static GUARD_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn teardown_guard_drop_runs_teardown_on_post_arm_failure() {
        // Arming the guard then failing *after* the arm (here: never
        // advancing past the default `NotLaunched` ownership and dropping the
        // guard, exactly as `run_one_shot` does when `drive` returns Err or
        // panics) must still run teardown. With `NotLaunched` ownership and no
        // VM this host launched, `full()` plans no kill and clears the per-run
        // marker dir -- so a cleared marker is the observable proof the guard's
        // Drop ran the teardown path (rather than leaking the run dir).
        let _serialize = GUARD_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = tempfile::tempdir().unwrap();
        let run_dir = root.path().join("run-postarm");
        std::fs::create_dir_all(&run_dir).unwrap();
        write_marker(&run_dir).unwrap();
        assert!(run_dir.join(MARKER_FILE).exists());

        {
            let _guard = VmTeardownGuard::arm(run_dir.clone());
            // Simulate a post-arm failure: return/scope-exit without launching
            // a VM. Ownership stays `NotLaunched`.
        } // guard drops here -> teardown runs.

        assert!(
            !run_dir.join(MARKER_FILE).exists(),
            "VmTeardownGuard::drop must run teardown (clearing the marker) on the post-arm \
             failure path, not leak the run dir"
        );
    }

    #[test]
    fn teardown_guard_drop_with_launch_in_flight_preserves_marker_for_reclaim() {
        // Mirror of the above for the ambiguous `LaunchInFlight` state: a launch
        // was issued but ownership was never proven, so teardown must NOT clear
        // the marker (it is left for the next run to reconcile rather than
        // presuming ownership and risking a foreign-VM kill).
        let _serialize = GUARD_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = tempfile::tempdir().unwrap();
        let run_dir = root.path().join("run-inflight");
        std::fs::create_dir_all(&run_dir).unwrap();
        write_marker(&run_dir).unwrap();

        {
            let _guard = VmTeardownGuard::arm(run_dir.clone());
            set_vm_ownership(VmOwnership::LaunchInFlight);
        } // guard drops here.

        assert!(
            run_dir.join(MARKER_FILE).exists(),
            "an in-flight (unproven) launch must preserve the marker for reclaim, not clear it"
        );
        // Cleanup (the test, not the guard, owns this dir now).
        let _ = std::fs::remove_dir_all(&run_dir);
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

    fn proc(pid: u32, ct: u64) -> VmProcId {
        VmProcId {
            pid,
            creation_time: ct,
        }
    }

    #[test]
    fn classify_probe_failure_is_busy() {
        assert_eq!(
            classify_reconcile(None, &[], &[]),
            ReconcileDecision::Busy(BusyReason::ProbeFailed)
        );
    }

    #[test]
    fn classify_no_vm_proceeds() {
        let markers = [MarkerState {
            launcher_alive: false,
            vm_processes: vec![proc(1, 1)],
        }];
        assert_eq!(
            classify_reconcile(Some(false), &[], &markers),
            ReconcileDecision::Proceed
        );
    }

    #[test]
    fn classify_live_launcher_is_active_run() {
        let current = [proc(100, 5)];
        let markers = [MarkerState {
            launcher_alive: true,
            vm_processes: vec![proc(100, 5)],
        }];
        assert_eq!(
            classify_reconcile(Some(true), &current, &markers),
            ReconcileDecision::Busy(BusyReason::ActiveRun)
        );
    }

    #[test]
    fn classify_proof_intersection_reclaims_with_recorded_proof() {
        let current = [proc(100, 5), proc(200, 6)];
        let markers = [MarkerState {
            launcher_alive: false,
            vm_processes: vec![proc(100, 5)],
        }];
        // ReclaimThenProceed carries the PRIOR recorded proof (deduped union
        // across intersecting markers), NOT the live snapshot. Seeding with
        // the snapshot would promote any foreign WindowsSandbox* process at
        // reconcile time into "proof" once plan_kill_set's intersection check
        // is applied downstream.
        assert_eq!(
            classify_reconcile(Some(true), &current, &markers),
            ReconcileDecision::ReclaimThenProceed {
                proof: vec![proc(100, 5)]
            }
        );
    }

    #[test]
    fn classify_proof_intersection_dedupes_across_markers() {
        // Two intersecting markers (e.g. a multi-process orphan that two prior
        // launches each partially recorded) - their proofs are unioned with
        // dedup, never the live snapshot.
        let shared = proc(100, 5);
        let extra = proc(101, 6);
        let foreign = proc(999, 999);
        let current = [shared, foreign];
        let markers = [
            MarkerState {
                launcher_alive: false,
                vm_processes: vec![shared],
            },
            MarkerState {
                launcher_alive: false,
                vm_processes: vec![shared, extra],
            },
        ];
        assert_eq!(
            classify_reconcile(Some(true), &current, &markers),
            ReconcileDecision::ReclaimThenProceed {
                proof: vec![shared, extra]
            }
        );
    }

    #[test]
    fn classify_no_proof_intersection_is_foreign() {
        let current = [proc(100, 5)];
        // Recorded proof refers to a different (dead) process instance.
        let markers = [MarkerState {
            launcher_alive: false,
            vm_processes: vec![proc(999, 1)],
        }];
        assert_eq!(
            classify_reconcile(Some(true), &current, &markers),
            ReconcileDecision::Busy(BusyReason::ForeignUnprovable)
        );
    }

    #[test]
    fn classify_pid_match_creation_time_diff_is_foreign() {
        // PID reuse defence: recorded proof has the same PID as a live
        // process but a different creation_time. Must NOT intersect.
        let current = [proc(100, 999)];
        let markers = [MarkerState {
            launcher_alive: false,
            vm_processes: vec![proc(100, 5)],
        }];
        assert_eq!(
            classify_reconcile(Some(true), &current, &markers),
            ReconcileDecision::Busy(BusyReason::ForeignUnprovable)
        );
    }

    #[test]
    fn classify_running_no_markers_is_foreign() {
        let current = [proc(100, 5)];
        assert_eq!(
            classify_reconcile(Some(true), &current, &[]),
            ReconcileDecision::Busy(BusyReason::ForeignUnprovable)
        );
    }
}
