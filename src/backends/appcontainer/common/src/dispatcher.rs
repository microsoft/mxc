// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BaseContainer-fallback tier dispatcher.
//!
//! Wires Phases 0–3 (telemetry, fallback detector, AppContainer modes,
//! DACL manager) into a single entrypoint. Given an [`ExecutionRequest`], the
//! dispatcher consults [`crate::fallback_detector::detect`] to choose
//! between Tier 1 (BaseContainer), Tier 2 (AppContainer + BFS), or Tier 3
//! (AppContainer + DACL), constructs the appropriate runner, and applies
//! [`DaclManager`] augmentation when the chosen tier requires it.
//!
//! Filesystem-policy enforcement under T1 is delegated entirely to
//! BaseContainer's own `Experimental_CreateProcessInSandbox` API
//! (`deniedPaths` via the SandboxSpec `fs_deny` field); the dispatcher
//! does **not** apply host DACLs in T1. When the OS advertises native
//! deny support the OS enforces `deniedPaths` itself; when it does not,
//! a denied-paths policy never reaches T1 (the detector falls through to
//! the AppContainer tiers, which stamp the deny DACLs). So T1 has no
//! deny ACEs to apply either way.
//!
//! # Why T2 (BFS) also gets DACL deny augmentation
//!
//! `bfscfg.exe`'s BFS model expresses read-write / read-only allow lists,
//! but does **not** model a deny semantic for paths *outside* its allow
//! list (those are implicitly inaccessible, but a path that lives inside
//! an allowed parent cannot be selectively denied via BFS). To honor
//! `policy.denied_paths` on T2 we therefore add deny ACEs targeting the
//! AppContainer SID alongside the BFS configuration.
//!
//! # Drop ordering
//!
//! Callers must keep the [`DaclManager`] returned by
//! [`Dispatched::into_runner_and_guard`] alive for the entire duration of
//! the run — its [`Drop`] removes the ACEs we added to the host
//! filesystem. Dropping it before the runner finishes would yank
//! filesystem access mid-execution.
//!
//! # Performance
//!
//! Tier 1 has the lowest per-invocation cost: a single
//! `BaseContainerRunner::new()`. Tier 2 with empty `denied_paths` is also
//! near-free. The heavy paths are Tier 2 with deny-only and Tier 3, both
//! of which stamp host-DACL ACEs via [`DaclManager`].
//!
//! The DACL cost is roughly O(N) Win32 syscalls plus one state-file
//! write per path in (Tier 3: `readwrite_paths` ∪ `readonly_paths` ∪
//! `denied_paths`; Tier 2: `denied_paths`). The same number of syscalls
//! is replayed in reverse on `Drop`. At the typical N (6–12 paths) this
//! adds tens of milliseconds to both dispatch and shutdown; at larger N
//! it scales linearly and can add hundreds of milliseconds on each side.
//! SDK callers that spawn `wxc-exec` per task pay this cost on every
//! invocation. Parent-directory ACE rollup and session-scoped
//! [`DaclManager`] caching are tracked as follow-ups.
//!
//! # Known limitation
//!
//! Two concurrent runs with the *same* `container_id` derive the same
//! AppContainer SID and therefore share the same target principal for
//! ACE bookkeeping. When the second run finishes it issues
//! `REVOKE_ACCESS` for that SID, which wipes the first run's still-live
//! grants. This is out of scope for the dispatcher; callers that need
//! parallel-safe isolation must use distinct `container_id` values.
//!
//! Windows-only by virtue of `lib.rs` gating the module behind
//! `#[cfg(target_os = "windows")]`; no inner attribute is needed.

use std::path::PathBuf;

use crate::appcontainer_runner::{derive_sid_string, AppContainerScriptRunner, FilesystemMode};
use crate::base_container_runner::BaseContainerRunner;
use crate::fallback_detector::{self, FallbackError, IsolationTier};
use wxc_common::error::WxcError;
use wxc_common::filesystem_dacl::{DaclError, DaclManager, RO_MASK, RW_MASK};
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::sandbox_process::{Runner, SandboxBackend, SandboxProcess, StdioMode};
use wxc_common::script_runner::ScriptRunner;

/// Result of a successful dispatch decision: a phased handle holding a
/// runner and (optionally) a `DaclManager`, with **private fields** so
/// callers cannot reorder their drops.
///
/// This is *not* a compile-time typestate — there are no
/// `PhantomData<State>` markers and `Dispatched<Ready>` /
/// `Dispatched<Spawned>` do not exist. The safety property
/// ("`DaclManager`'s `Drop` runs AFTER the runner has finished, or the
/// ACEs we applied would be revoked mid-execution") is enforced
/// dynamically by the single extraction point
/// [`Dispatched::into_runner_and_guard`]: it returns a tuple whose
/// binding order dictates drop order, and callers cannot `.take()`
/// either half independently because the fields are private.
///
/// If you need stronger guarantees (e.g. statically rejecting
/// `runner.drop()` before `dacl_manager` is taken at the FFI boundary),
/// promote the struct to a real typestate machine. Today, the
/// surface area we expose to wxc-exec / SDK doesn't need that.
pub struct Dispatched {
    runner: Box<dyn ScriptRunner>,
    dacl_manager: Option<DaclManager>,
    /// The selected tier, for telemetry.
    pub tier: IsolationTier,
    /// Operator-visible warnings collected during tier selection.
    pub warnings: Vec<String>,
}

impl Dispatched {
    /// Consume `self` and return `(runner, dacl_manager)`. Bind these
    /// in a single `let` such that the runner is dropped before the
    /// DACL guard — Rust drops local bindings in reverse declaration
    /// order, so the standard idiom is:
    ///
    /// ```ignore
    /// let (mut runner, _dacl_guard) = dispatched.into_runner_and_guard();
    /// // ... use runner ...
    /// // at end of scope: runner drops first, then _dacl_guard restores ACEs.
    /// ```
    pub fn into_runner_and_guard(self) -> (Box<dyn ScriptRunner>, Option<DaclManager>) {
        (self.runner, self.dacl_manager)
    }

    /// Read-only check used by unit tests to assert whether the chosen
    /// tier required DACL augmentation, without exposing the manager
    /// itself (which would let tests `.take()` it).
    #[cfg(test)]
    pub(crate) fn has_dacl_guard(&self) -> bool {
        self.dacl_manager.is_some()
    }
}

/// Errors that can abort dispatch before the runner executes.
#[derive(Debug)]
pub enum DispatchError {
    /// Fallback detection refused the request.
    Fallback(FallbackError),
    /// `DaclManager` failed to apply ACEs. `warnings` carries any
    /// retained-entry messages drained from the manager before the
    /// failed apply was rolled back via `restore()`. Entries that
    /// `restore()` itself could not clean up are persisted to disk and
    /// will be reaped on the next wxc-exec startup by
    /// `recover_orphaned_state`.
    Dacl {
        error: DaclError,
        warnings: Vec<String>,
    },
    /// AppContainer SID derivation failed.
    Sid(WxcError),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::Fallback(FallbackError::DaclFallbackDisabled) => write!(
                f,
                "BaseContainer is unavailable on this system and DACL fallback is disabled \
                 (fallback.allowDaclMutation=false). Run on a system with the BaseContainer \
                 API or bfscfg.exe, or set fallback.allowDaclMutation=true in your config."
            ),
            DispatchError::Fallback(FallbackError::WriteDacUnavailable { path, reason }) => {
                write!(
                    f,
                    "BaseContainer is unavailable; DACL fallback requires write-DAC permission \
                     on '{}', which the current user lacks ({reason}).",
                    path.display()
                )
            }
            DispatchError::Fallback(FallbackError::SystemRootUnresolved { reason }) => write!(
                f,
                "Could not resolve the Windows system directory while probing for bfscfg.exe \
                 ({reason}). This indicates a corrupted or unsupported OS configuration."
            ),
            DispatchError::Dacl { error, .. } => write!(f, "Failed to apply DACL ACEs: {error}"),
            DispatchError::Sid(e) => write!(f, "Failed to derive AppContainer SID: {e}"),
        }
    }
}

impl std::error::Error for DispatchError {}

impl From<FallbackError> for DispatchError {
    fn from(e: FallbackError) -> Self {
        DispatchError::Fallback(e)
    }
}

/// The container-id → AppContainer-name mapping used by the runners. Empty
/// container_id maps to `"CLI"` (matches both AppContainerScriptRunner and
/// BaseContainerRunner internals).
fn container_name(request: &ExecutionRequest) -> String {
    if request.container_id.is_empty() {
        "CLI".to_string()
    } else {
        request.container_id.clone()
    }
}

fn paths_to_pathbufs(paths: &[String]) -> Vec<PathBuf> {
    paths.iter().map(PathBuf::from).collect()
}

/// Drop paths that already grant `needed_mask` to the well-known
/// AppContainer SIDs (`ALL APPLICATION PACKAGES`,
/// `ALL RESTRICTED APPLICATION PACKAGES`, `Everyone`). Mirrors the
/// same effective-access check that
/// [`fallback_detector::appcontainer_already_grants`] performs for
/// the `WRITE_DAC` precheck.
fn filter_paths_needing_grant(paths: Vec<PathBuf>, needed_mask: u32) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter(|p| !fallback_detector::appcontainer_already_grants(p, needed_mask))
        .collect()
}

/// Wrap a `DaclError` together with any retained-entry warnings from the
/// manager whose apply failed. Called immediately before `mgr` goes out
/// of scope (which triggers `restore()` via Drop) so we capture the
/// apply-time warnings, not whatever `restore()` itself accumulates
/// while unwinding.
fn dacl_err(mgr: &DaclManager, error: DaclError) -> DispatchError {
    DispatchError::Dacl {
        error,
        warnings: mgr.warnings().to_vec(),
    }
}

/// Build the deny-only DACL manager used by T1 and T2 when
/// `denied_paths` is non-empty. Returns `Ok(None)` when no DACL work is
/// required.
fn build_deny_only_dacl(
    sid: &str,
    denied: &[PathBuf],
) -> Result<Option<DaclManager>, DispatchError> {
    if denied.is_empty() {
        return Ok(None);
    }
    let mut mgr = DaclManager::new().map_err(|e| DispatchError::Dacl {
        error: e,
        warnings: Vec::new(),
    })?;
    if let Err(e) = mgr.add_deny_aces(sid, denied) {
        return Err(dacl_err(&mgr, e));
    }
    Ok(Some(mgr))
}

/// Build the grant + (optional) deny DACL manager used by T3. T3 always
/// returns a `DaclManager` because grants are mandatory; if grants
/// succeed and deny fails, the manager's `Drop` rolls back the grants.
fn build_t3_dacl(
    sid: &str,
    readwrite: &[PathBuf],
    readonly: &[PathBuf],
    denied: &[PathBuf],
) -> Result<DaclManager, DispatchError> {
    let mut mgr = DaclManager::new().map_err(|e| DispatchError::Dacl {
        error: e,
        warnings: Vec::new(),
    })?;
    if let Err(e) = mgr.grant_appcontainer_access(sid, readwrite, readonly) {
        return Err(dacl_err(&mgr, e));
    }
    if !denied.is_empty() {
        if let Err(e) = mgr.add_deny_aces(sid, denied) {
            return Err(dacl_err(&mgr, e));
        }
    }
    Ok(mgr)
}

/// The concrete Windows backend chosen by the fallback dispatcher, before it is
/// adapted to either the run-to-completion surface (wrapped in [`Runner`] →
/// [`ScriptRunner`], via [`dispatch_with_fallback`]) or the streaming surface
/// ([`SandboxBackend::spawn`], via [`spawn_with_fallback`]).
///
/// Keeping tier selection in one place ([`select_backend_with_fallback`]) is
/// what guarantees the two surfaces can't drift — the streaming path previously
/// reimplemented a two-tier subset and so never reached the AppContainer + DACL
/// fallback (issue #643).
enum SelectedBackend {
    BaseContainer(BaseContainerRunner),
    AppContainer(AppContainerScriptRunner),
}

impl SandboxBackend for SelectedBackend {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        match self {
            SelectedBackend::BaseContainer(b) => b.validate(request),
            SelectedBackend::AppContainer(a) => a.validate(request),
        }
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        match self {
            SelectedBackend::BaseContainer(b) => b.spawn(request, logger, stdio),
            SelectedBackend::AppContainer(a) => a.spawn(request, logger, stdio),
        }
    }

    fn diagnose_exit(&self, request: &ExecutionRequest, exit_code: i32) -> Option<String> {
        match self {
            SelectedBackend::BaseContainer(b) => b.diagnose_exit(request, exit_code),
            SelectedBackend::AppContainer(a) => a.diagnose_exit(request, exit_code),
        }
    }
}

/// Run tier selection and construct the backend + (optional) DACL guard for
/// `request`. This is the single source of truth for the tier → (backend, DACL)
/// mapping, shared by the run-to-completion ([`dispatch_with_fallback`]) and
/// streaming ([`spawn_with_fallback`]) surfaces.
///
/// On success the returned [`DaclManager`], when present, has **already applied
/// its ACEs** and MUST outlive the run (its `Drop` restores the host ACEs). The
/// selected [`IsolationTier`] and any tier-selection warnings are returned for
/// telemetry.
fn select_backend_with_fallback(
    request: &ExecutionRequest,
) -> Result<
    (
        SelectedBackend,
        Option<DaclManager>,
        IsolationTier,
        Vec<String>,
    ),
    DispatchError,
> {
    let decision = fallback_detector::detect(&request.policy, /*prefer_bc=*/ true)?;

    let (backend, dacl_manager): (SelectedBackend, Option<DaclManager>) = match decision.tier {
        IsolationTier::BaseContainer => {
            // Tier 1 delegates filesystem-policy enforcement to
            // BaseContainer's native API. We stamp no host-DACL deny ACEs
            // here: the detector only routes a denied-paths policy to T1
            // when the OS enforces `fs_deny` natively, so there is nothing
            // for a host DACL to add.
            (
                SelectedBackend::BaseContainer(BaseContainerRunner::new()),
                None,
            )
        }
        IsolationTier::AppContainerBfs => {
            // T2 only needs deny ACEs (BFS handles the rest in-runner)
            // and only when `deniedPaths` is non-empty. Allocate the
            // path Vec and derive the SID inside that branch so the
            // common no-deny case skips both costs.
            let denied = paths_to_pathbufs(&request.policy.denied_paths);
            if denied.is_empty() {
                (
                    SelectedBackend::AppContainer(AppContainerScriptRunner::with_filesystem_mode(
                        FilesystemMode::Bfs,
                    )),
                    None,
                )
            } else {
                let sid =
                    derive_sid_string(&container_name(request)).map_err(DispatchError::Sid)?;
                let mgr = build_deny_only_dacl(&sid, &denied)?;
                // Hand the derived SID string to the runner so it does
                // not re-run `ConvertSidToStringSidW` for the firewall
                // principal-id lookup.
                (
                    SelectedBackend::AppContainer(
                        AppContainerScriptRunner::with_filesystem_mode_and_sid_string(
                            FilesystemMode::Bfs,
                            sid,
                        ),
                    ),
                    mgr,
                )
            }
        }
        IsolationTier::AppContainerDacl => {
            // T3 always stamps grant ACEs (for readwrite/readonly paths)
            // and optionally deny ACEs. Allocate per-arm so T1/T2 don't
            // pay the cost.
            //
            // Skip per-run grant ACEs on paths where the well-known
            // AppContainer SIDs already grant the equivalent access.
            // `fallback_detector::detect` performs the same effective-
            // access check up front so it can skip the `WRITE_DAC`
            // requirement; this filter is the matching application
            // side so we don't try (and fail) to stamp a redundant
            // ACE on a system path the user doesn't own. Denied paths
            // are not filtered — DENY ACEs are about subtracting
            // access, which well-known group grants can't do.
            let readwrite = filter_paths_needing_grant(
                paths_to_pathbufs(&request.policy.readwrite_paths),
                RW_MASK,
            );
            let readonly = filter_paths_needing_grant(
                paths_to_pathbufs(&request.policy.readonly_paths),
                RO_MASK,
            );
            let denied = paths_to_pathbufs(&request.policy.denied_paths);
            let sid = derive_sid_string(&container_name(request)).map_err(DispatchError::Sid)?;
            let mgr = build_t3_dacl(&sid, &readwrite, &readonly, &denied)?;
            (
                SelectedBackend::AppContainer(
                    AppContainerScriptRunner::with_filesystem_mode_and_sid_string(
                        FilesystemMode::Dacl,
                        sid,
                    ),
                ),
                Some(mgr),
            )
        }
    };

    Ok((backend, dacl_manager, decision.tier, decision.warnings))
}

/// Build a runner with appropriate DACL augmentation for the
/// BaseContainer-preferred path. The caller is responsible for the explicit
/// (no-fallback) AppContainer path.
///
/// On success the returned [`Dispatched`] contains a runner ready to
/// execute and (when applicable) a [`DaclManager`] that has already
/// applied its ACEs. Use [`Dispatched::into_runner_and_guard`] to
/// extract both; the manager MUST stay alive through the run.
pub fn dispatch_with_fallback(request: &ExecutionRequest) -> Result<Dispatched, DispatchError> {
    let (backend, dacl_manager, tier, warnings) = select_backend_with_fallback(request)?;
    let runner: Box<dyn ScriptRunner> = Box::new(Runner::new(backend));
    Ok(Dispatched {
        runner,
        dacl_manager,
        tier,
        warnings,
    })
}

/// A successful streaming dispatch: a [`SandboxProcess`] handle plus the tier
/// and warnings for telemetry. The handle already owns any [`DaclManager`]
/// guard (via [`DaclGuardedProcess`]), so ACE restore outlives the child — the
/// caller only has to keep the handle alive until the run is done.
pub struct DispatchedProcess {
    /// The spawned sandboxed process, streaming stdio over pipes.
    pub process: Box<dyn SandboxProcess>,
    /// The selected tier, for telemetry.
    pub tier: IsolationTier,
    /// Operator-visible warnings collected during tier selection.
    pub warnings: Vec<String>,
}

/// Error from the streaming [`spawn_with_fallback`] path. Kept distinct from a
/// flat error so the caller can preserve fallback semantics: tier-selection /
/// DACL failures map to `backend_unavailable` (as the run-to-completion path
/// does), while a backend spawn failure preserves the backend's
/// [`FailurePhase`](wxc_common::models::FailurePhase).
pub enum SpawnDispatchError {
    /// Tier selection or DACL application failed before the process spawned.
    /// Mirrors [`dispatch_with_fallback`]'s [`DispatchError`].
    Dispatch(DispatchError),
    /// The selected backend's `spawn` failed *after* a tier was already chosen
    /// (and any DACL ACEs applied then rolled back). Carries the backend's
    /// [`ScriptResponse`] so the caller can preserve its `failure_phase`, plus
    /// the selected `tier` and tier-selection `warnings` so the caller can log
    /// them on the failure path too — matching the run-to-completion path, which
    /// logs both at resolve time before the (separate, later) spawn attempt.
    ///
    /// `response` is boxed to keep this cold-path error variant small (it would
    /// otherwise trip `clippy::result_large_err` on every `spawn_with_fallback`
    /// return).
    Spawn {
        response: Box<ScriptResponse>,
        tier: IsolationTier,
        warnings: Vec<String>,
    },
}

/// Streaming counterpart of [`dispatch_with_fallback`]: select the tier, apply
/// any DACL augmentation, spawn the sandboxed process with `stdio`, and return a
/// [`SandboxProcess`] handle that owns the DACL guard so ACE restore outlives
/// the child.
///
/// This exists so the streaming (`mxc-sdk`) path gets the **same** three-tier
/// fallback as the executor binaries' run-to-completion path — including the
/// AppContainer + DACL (Tier 3) tier used when neither BaseContainer nor
/// `bfscfg.exe` (Tier 2 BFS) is available. See issue #643.
///
/// # Drop ordering
///
/// When a DACL guard is attached, the returned handle is a [`DaclGuardedProcess`]
/// whose field order drops the inner process (killing the child tree and
/// tearing down firewall / BFS enforcement) **before** the [`DaclManager`]
/// (restoring host ACEs) — the same order the run-to-completion path enforces
/// via [`Dispatched::into_runner_and_guard`].
pub fn spawn_with_fallback(
    request: &ExecutionRequest,
    logger: &mut Logger,
    stdio: StdioMode,
) -> Result<DispatchedProcess, SpawnDispatchError> {
    let (mut backend, dacl_manager, tier, warnings) =
        select_backend_with_fallback(request).map_err(SpawnDispatchError::Dispatch)?;

    // Spawn with the DACL ACEs (if any) already applied. On a spawn failure the
    // `dacl_manager` local drops here, restoring any ACEs that were stamped; we
    // hand the already-selected `tier`/`warnings` to the error so the caller can
    // still log them (the run-to-completion path logs them at resolve time,
    // before its separate spawn attempt).
    let inner = match backend.spawn(request, logger, stdio) {
        Ok(inner) => inner,
        Err(response) => {
            return Err(SpawnDispatchError::Spawn {
                response: Box::new(response),
                tier,
                warnings,
            })
        }
    };

    // Attach the guard to the handle only when there is one — T1 and T2-without-
    // deny need no DACL work, so their handle is returned unwrapped.
    let process: Box<dyn SandboxProcess> = match dacl_manager {
        Some(dacl_manager) => Box::new(DaclGuardedProcess {
            inner,
            _dacl_manager: dacl_manager,
        }),
        None => inner,
    };

    Ok(DispatchedProcess {
        process,
        tier,
        warnings,
    })
}

/// A streaming [`SandboxProcess`] paired with the [`DaclManager`] guard whose
/// `Drop` restores the host ACEs the DACL tier applied.
///
/// **Field order is load-bearing.** Rust drops struct fields in declaration
/// order, so `inner` (which kills the child tree and tears down the per-run
/// firewall / BFS enforcement) drops **before** `_dacl_manager` (which restores
/// host ACEs). This matches the run-to-completion path's `(runner, dacl_manager)`
/// drop order (see [`Dispatched::into_runner_and_guard`]): the host ACEs must
/// not be revoked until the child and its descendants are gone.
///
/// Every [`SandboxProcess`] method delegates to `inner`; the guard is otherwise
/// inert until drop.
struct DaclGuardedProcess {
    inner: Box<dyn SandboxProcess>,
    _dacl_manager: DaclManager,
}

impl SandboxProcess for DaclGuardedProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        self.inner.take_stdin()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.inner.take_stdout()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.inner.take_stderr()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        self.inner.try_wait()
    }

    fn id(&self) -> u32 {
        self.inner.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        self.inner.wait()
    }

    fn stdout_closer(&self) -> Option<Box<dyn wxc_common::sandbox_process::StreamCloser>> {
        self.inner.stdout_closer()
    }

    fn stderr_closer(&self) -> Option<Box<dyn wxc_common::sandbox_process::StreamCloser>> {
        self.inner.stderr_closer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainerPolicy, ExecutionRequest};
    // `ForceTierGuard` lives in `crate::test_env` so the lock is
    // shared with the `fallback_detector::tests` module — otherwise
    // a dispatcher test and a fallback-detector test running on
    // different threads could each mutate `MXC_FORCE_TIER` under
    // independent locks and race.
    use crate::test_env::{BcUsableGuard, ForceTierGuard, ENV_LOCK};

    fn test_request(policy: ContainerPolicy) -> ExecutionRequest {
        ExecutionRequest {
            container_id: "MxcDispatcherTest".to_string(),
            policy,
            ..ExecutionRequest::default()
        }
    }

    fn empty_policy() -> ContainerPolicy {
        ContainerPolicy::default()
    }
    fn policy_with_denied_temp() -> (ContainerPolicy, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut p = ContainerPolicy::default();
        p.denied_paths
            .push(dir.path().to_string_lossy().into_owned());
        (p, dir)
    }
    fn policy_with_rw_temp() -> (ContainerPolicy, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut p = ContainerPolicy::default();
        p.readwrite_paths
            .push(dir.path().to_string_lossy().into_owned());
        (p, dir)
    }
    #[test]
    fn dispatch_t1_no_denied_paths_no_dacl() {
        let _g = ForceTierGuard::set("base-container");
        let req = test_request(empty_policy());
        let d = dispatch_with_fallback(&req).expect("T1 dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::BaseContainer));
        assert!(
            !d.has_dacl_guard(),
            "T1 with no denied_paths should not allocate DaclManager"
        );
    }
    #[test]
    fn dispatch_t1_with_denied_paths_has_no_dacl() {
        // T1 delegates filesystem-policy enforcement (including
        // `deniedPaths`) to BaseContainer's native API; the dispatcher
        // attaches no `DaclManager` on the T1 path regardless of the
        // `deniedPaths` contents.
        let _g = ForceTierGuard::set("base-container");
        let (policy, _tmp) = policy_with_denied_temp();
        let req = test_request(policy);
        let d = dispatch_with_fallback(&req).expect("T1+deny dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::BaseContainer));
        assert!(
            !d.has_dacl_guard(),
            "T1 must not attach a DaclManager — BC handles deny natively"
        );
    }
    #[test]
    fn dispatch_t2_with_denied_paths_has_dacl() {
        let _g = ForceTierGuard::set("appcontainer-bfs");
        let (policy, _tmp) = policy_with_denied_temp();
        let req = test_request(policy);
        let d = dispatch_with_fallback(&req).expect("T2+deny dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::AppContainerBfs));
        assert!(d.has_dacl_guard());
    }
    #[test]
    fn dispatch_t3_always_has_dacl() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let (policy, _tmp) = policy_with_rw_temp();
        let req = test_request(policy);
        let d = dispatch_with_fallback(&req).expect("T3 dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::AppContainerDacl));
        assert!(
            d.has_dacl_guard(),
            "T3 always requires DaclManager (grants applied)"
        );
    }
    #[test]
    fn dispatch_fallback_disabled_errors() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let (mut policy, _tmp) = policy_with_rw_temp();
        policy.fallback.allow_dacl_mutation = false;
        let req = test_request(policy);
        let res = dispatch_with_fallback(&req);
        assert!(matches!(
            res,
            Err(DispatchError::Fallback(FallbackError::DaclFallbackDisabled))
        ));
    }

    #[test]
    fn dispatch_error_display_messages_non_empty() {
        let f = DispatchError::Fallback(FallbackError::DaclFallbackDisabled);
        assert!(!format!("{f}").is_empty());

        let w = DispatchError::Fallback(FallbackError::WriteDacUnavailable {
            path: PathBuf::from("C:\\foo"),
            reason: "ACCESS_DENIED".to_string(),
        });
        let s = format!("{w}");
        assert!(s.contains("C:\\foo"));
        assert!(s.contains("ACCESS_DENIED"));

        let s = DispatchError::Sid(WxcError::Initialization("bad sid".to_string()));
        assert!(format!("{s}").contains("AppContainer SID"));
    }

    /// `DispatchError::Dacl { error, warnings }` is the shape consumers
    /// (SDK envelope, error formatters) depend on. Force an actual
    /// apply failure by passing a non-existent path through
    /// `build_deny_only_dacl` — `apply_one` -> `canonicalize_local`
    /// fails with `io::Error` rooted at the missing path. The
    /// resulting `DispatchError::Dacl` must:
    ///   - be the `Dacl` variant (not `Fallback`),
    ///   - carry a `warnings: Vec<String>` (its presence/empty-or-not
    ///     is the documented contract; populated entries are added
    ///     mid-multi-path runs),
    ///   - format with a message that mentions the offending path
    ///     via its inner `DaclError`.
    #[test]
    fn dispatch_error_dacl_variant_shape_on_apply_failure() {
        use crate::test_env::ScopedStateDir;
        let _scope = ScopedStateDir::new();

        // Construct a path that is guaranteed not to exist. Using a
        // tempdir + unique suffix keeps the test resilient against
        // any pre-existing junk in %TEMP%.
        let nonexistent = std::env::temp_dir()
            .join(format!("mxc-dispatcher-error-shape-{}", std::process::id()))
            .join("does-not-exist");
        let err = build_deny_only_dacl("S-1-1-0", std::slice::from_ref(&nonexistent))
            .expect_err("non-existent path should fail apply");
        match err {
            DispatchError::Dacl { error, warnings } => {
                // Shape contract: warnings is Vec<String> (possibly
                // empty for a first-path apply failure). Every entry,
                // when present, is non-empty.
                for w in &warnings {
                    assert!(!w.is_empty(), "warning entries must be non-empty");
                }
                // Inner error references the offending path. The
                // canonicalize failure may surface as either
                // `DaclError::Win32` or another path-bearing variant;
                // both must serialize to a message mentioning the path.
                let s = format!("{error}");
                assert!(
                    s.contains("does-not-exist"),
                    "inner DaclError message should mention offending path: {s}"
                );
            }
            other => panic!("expected DispatchError::Dacl, got: {other:?}"),
        }
    }

    /// `filter_paths_needing_grant` is the per-path side of the
    /// `ce7713d` optimization ("skip per-run ACE when AC SID already
    /// has access"). Direct exercise: stamp an Everyone (S-1-1-0)
    /// grant on a temp dir — Everyone is in every AppContainer
    /// token's well-known-SID set — and assert
    /// `filter_paths_needing_grant` drops the path. A tempdir without
    /// any stamp must survive the filter because %TEMP%'s shadow
    /// ACLs do not grant the well-known AC SIDs `RW_MASK`.
    #[test]
    fn filter_paths_needing_grant_drops_well_known_grant() {
        use crate::test_env::ScopedStateDir;
        let _scope = ScopedStateDir::new();
        let td_grant = tempfile::tempdir().expect("temp dir grant");
        let td_no_grant = tempfile::tempdir().expect("temp dir no-grant");

        // Stamp an Everyone grant on td_grant via `grant_appcontainer_access`
        // and persist it for the duration of the test by holding the
        // manager. Drop at end of scope rolls it back.
        let mut mgr = wxc_common::filesystem_dacl::DaclManager::new().expect("dacl mgr");
        mgr.grant_appcontainer_access(
            "S-1-1-0",
            std::slice::from_ref(&td_grant.path().to_path_buf()),
            &[],
        )
        .expect("grant");

        let input = vec![
            td_grant.path().to_path_buf(),
            td_no_grant.path().to_path_buf(),
        ];
        let kept = filter_paths_needing_grant(input, RW_MASK);
        assert!(
            !kept.iter().any(|p| p == td_grant.path()),
            "grant-stamped path should be filtered out: kept={kept:?}"
        );
        assert!(
            kept.iter().any(|p| p == td_no_grant.path()),
            "non-stamped path should survive the filter: kept={kept:?}"
        );

        // Best-effort cleanup; Drop will also run restore().
        mgr.restore().ok();
    }

    #[test]
    fn dispatch_t1_naturally_selected_when_bc_usable() {
        // Natural T1 selection (no force). Skip when the backend isn't usable.
        // Asserts only the resolved tier; it does not exec.
        //
        // Hold ENV_LOCK and clear MXC_FORCE_TIER so a concurrent
        // `ForceTierGuard` test can't leak a forced value into `detect`.
        let _lock = {
            let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            // SAFETY: env-var mutation in tests; serialized by ENV_LOCK.
            unsafe {
                std::env::remove_var("MXC_FORCE_TIER");
            }
            lock
        };
        if !crate::fallback_detector::is_base_container_usable() {
            eprintln!("skipping: BaseContainer backend not usable on this machine");
            return;
        }
        let req = test_request(empty_policy());
        let d = dispatch_with_fallback(&req).expect("dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::BaseContainer));
    }

    #[test]
    fn dispatch_falls_back_to_t3_when_bc_unusable() {
        // The core regression: a present-but-disabled BaseContainer must not be
        // built. Forcing usable=false, dispatch resolves to Tier 3 directly so
        // the doomed BaseContainerRunner is never constructed.
        let _g = BcUsableGuard::set(false);
        let req = test_request(empty_policy());
        let d = dispatch_with_fallback(&req).expect("dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::AppContainerDacl));
    }

    // -------------------------------------------------------------------
    // Streaming dispatch (`select_backend_with_fallback` /
    // `spawn_with_fallback`) — issue #643.
    //
    // These assert the *shared* selector both surfaces call constructs the
    // backend variant matching the chosen tier and attaches a DaclManager
    // exactly when the tier needs host-ACE augmentation. Because the streaming
    // path (`spawn_with_fallback`) and the run-to-completion path
    // (`dispatch_with_fallback`) now both go through this one function, they
    // can no longer disagree on tier selection the way the old two-tier
    // streaming path did.
    // -------------------------------------------------------------------

    #[test]
    fn select_backend_t1_builds_base_container_no_dacl() {
        let _g = ForceTierGuard::set("base-container");
        let req = test_request(empty_policy());
        let (backend, dacl, tier, _w) =
            select_backend_with_fallback(&req).expect("T1 selection should succeed");
        assert!(matches!(tier, IsolationTier::BaseContainer));
        assert!(
            matches!(backend, SelectedBackend::BaseContainer(_)),
            "T1 must construct the BaseContainer backend, not AppContainer"
        );
        assert!(
            dacl.is_none(),
            "T1 delegates deny to the native API; no host DACL"
        );
    }

    #[test]
    fn select_backend_t2_no_deny_builds_appcontainer_no_dacl() {
        let _g = ForceTierGuard::set("appcontainer-bfs");
        let req = test_request(empty_policy());
        let (backend, dacl, tier, _w) =
            select_backend_with_fallback(&req).expect("T2 selection should succeed");
        assert!(matches!(tier, IsolationTier::AppContainerBfs));
        assert!(matches!(backend, SelectedBackend::AppContainer(_)));
        assert!(
            dacl.is_none(),
            "T2 without deniedPaths needs no host DACL (BFS handles it in-runner)"
        );
    }

    #[test]
    fn select_backend_t2_with_deny_builds_appcontainer_with_dacl() {
        let _g = ForceTierGuard::set("appcontainer-bfs");
        let (policy, _tmp) = policy_with_denied_temp();
        let req = test_request(policy);
        let (backend, dacl, tier, _w) =
            select_backend_with_fallback(&req).expect("T2+deny selection should succeed");
        assert!(matches!(tier, IsolationTier::AppContainerBfs));
        assert!(matches!(backend, SelectedBackend::AppContainer(_)));
        assert!(
            dacl.is_some(),
            "T2 deniedPaths require deny ACEs via a DaclManager"
        );
    }

    #[test]
    fn select_backend_t3_builds_appcontainer_with_dacl() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let (policy, _tmp) = policy_with_rw_temp();
        let req = test_request(policy);
        let (backend, dacl, tier, _w) =
            select_backend_with_fallback(&req).expect("T3 selection should succeed");
        assert!(matches!(tier, IsolationTier::AppContainerDacl));
        assert!(matches!(backend, SelectedBackend::AppContainer(_)));
        assert!(
            dacl.is_some(),
            "T3 always applies grant ACEs via a DaclManager"
        );
    }

    #[test]
    fn select_backend_streaming_falls_back_to_t3_when_bc_unusable() {
        // Streaming analog of `dispatch_falls_back_to_t3_when_bc_unusable` and
        // the direct regression guard for issue #643: with BaseContainer
        // present-but-unusable and BFS not compiled in, the shared selector the
        // streaming path calls must still resolve to Tier 3 (AppContainer +
        // DACL) — where the old two-tier streaming path instead failed closed
        // with the "bfscfg.exe is not available" error.
        let _g = BcUsableGuard::set(false);
        let req = test_request(empty_policy());
        let (backend, dacl, tier, _w) =
            select_backend_with_fallback(&req).expect("selection should succeed");
        assert!(matches!(tier, IsolationTier::AppContainerDacl));
        assert!(matches!(backend, SelectedBackend::AppContainer(_)));
        assert!(dacl.is_some());
    }

    /// `DaclGuardedProcess` must forward every `SandboxProcess` method to the
    /// wrapped handle unchanged; the guard is inert until drop (when it restores
    /// host ACEs, after `inner` has torn the child down — enforced by field
    /// order, documented on the struct).
    #[test]
    fn dacl_guarded_process_delegates_to_inner() {
        use crate::test_env::ScopedStateDir;
        use std::io::{Read, Write};
        use wxc_common::sandbox_process::SandboxProcess;

        /// Minimal fake recording which delegated calls arrived and returning
        /// distinctive canned values.
        #[derive(Default)]
        struct FakeProcess {
            stdin_taken: bool,
            killed: bool,
        }
        impl SandboxProcess for FakeProcess {
            fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
                self.stdin_taken = true;
                None
            }
            fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
                None
            }
            fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
                None
            }
            fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
                Ok(Some(7))
            }
            fn id(&self) -> u32 {
                4242
            }
            fn kill(&mut self) -> std::io::Result<()> {
                self.killed = true;
                Ok(())
            }
            fn wait(&mut self) -> std::io::Result<i32> {
                Ok(7)
            }
        }

        let _scope = ScopedStateDir::new();
        // A manager with no ACEs applied: `Drop`/`restore` is a no-op, so the
        // test only exercises delegation, not real host-ACE mutation.
        let dacl_manager = DaclManager::new().expect("dacl mgr");
        let mut guarded = DaclGuardedProcess {
            inner: Box::new(FakeProcess::default()),
            _dacl_manager: dacl_manager,
        };

        assert_eq!(guarded.id(), 4242, "id() must delegate");
        assert!(
            matches!(guarded.try_wait(), Ok(Some(7))),
            "try_wait() must delegate"
        );
        assert!(matches!(guarded.wait(), Ok(7)), "wait() must delegate");
        assert!(guarded.take_stdin().is_none(), "take_stdin() must delegate");
        assert!(guarded.kill().is_ok(), "kill() must delegate");
    }
}
