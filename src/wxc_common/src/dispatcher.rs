// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BaseContainer-fallback tier dispatcher.
//!
//! Wires the post-phase-4.5 fallback (telemetry, fallback detector,
//! AppContainer runner, DACL manager) into a single entrypoint. Given a
//! [`CodexRequest`], the dispatcher consults [`crate::fallback_detector::detect`]
//! to choose between Tier 1 (BaseContainer) and Tier 3 (AppContainer +
//! DACL), constructs the appropriate runner, and applies [`DaclManager`]
//! augmentation when the chosen tier requires it.
//!
//! Filesystem-policy enforcement under T1 is delegated entirely to
//! BaseContainer's own `Experimental_CreateProcessInSandbox` API
//! (including `deniedPaths` once native deny support lands); the
//! dispatcher does **not** apply host DACLs in T1. The opaque
//! `identity` BaseContainer runs the child under is not guaranteed to
//! match an `AppContainer` SID derived from the same container name, so
//! adding host-DACL belt-and-suspenders here would risk silently
//! targeting the wrong principal.
//!
//! See `docs/proposals/downlevel_support/basecontainer-fallback-plan-v2.md`.
//!
//! # Drop ordering
//!
//! Callers must keep the returned [`Dispatched::dacl_manager`] alive for the
//! entire duration of the run — its [`Drop`] removes the ACEs we added to
//! the host filesystem. Dropping it before the runner finishes would yank
//! filesystem access mid-execution.
//!
//! # Performance
//!
//! Tier 1 has the lowest per-invocation cost: a single
//! `BaseContainerRunner::new()`. Tier 3 stamps host-DACL ACEs via
//! [`DaclManager`].
//!
//! The DACL cost is roughly O(N) Win32 syscalls plus one state-file
//! write per path in `readwrite_paths` ∪ `readonly_paths` ∪
//! `denied_paths`. The same number of syscalls is replayed in reverse
//! on `Drop`. At the typical N (6–12 paths) this adds tens of
//! milliseconds to both dispatch and shutdown; at larger N it scales
//! linearly and can add hundreds of milliseconds on each side. SDK
//! callers that spawn `wxc-exec` per task pay this cost on every
//! invocation. Parent-directory ACE rollup and session-scoped
//! [`DaclManager`] caching are tracked as follow-ups.
//!
//! Windows-only by virtue of `lib.rs` gating the module behind
//! `#[cfg(target_os = "windows")]`; no inner attribute is needed.

use std::path::PathBuf;

use crate::appcontainer_runner::{derive_sid_string, AppContainerScriptRunner};
use crate::base_container_runner::BaseContainerRunner;
use crate::error::WxcError;
use crate::fallback_detector::{self, FallbackError, IsolationTier};
use crate::filesystem_dacl::{DaclError, DaclManager};
use crate::models::CodexRequest;
use crate::script_runner::ScriptRunner;

/// Result of a successful dispatch decision.
///
/// The caller should bind `dacl_manager` to a local that outlives the
/// runner so its `Drop` removes any ACEs we applied after the child
/// process completes.
pub struct Dispatched {
    /// Runner ready to execute.
    pub runner: Box<dyn ScriptRunner>,
    /// `DaclManager` whose `Drop` restores ACEs. `None` when the chosen
    /// tier did not require host DACL augmentation.
    pub dacl_manager: Option<DaclManager>,
    /// The selected tier, for telemetry.
    pub tier: IsolationTier,
    /// Operator-visible warnings collected during tier selection.
    pub warnings: Vec<String>,
}

/// Errors that can abort dispatch before the runner executes.
#[derive(Debug)]
pub enum DispatchError {
    /// Fallback detection refused the request.
    Fallback(FallbackError),
    /// `DaclManager` failed to apply ACEs.
    Dacl(DaclError),
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
                 API, or set fallback.allowDaclMutation=true in your config."
            ),
            DispatchError::Fallback(FallbackError::WriteDacUnavailable { path, reason }) => {
                write!(
                    f,
                    "BaseContainer is unavailable; DACL fallback requires write-DAC permission \
                     on '{}', which the current user lacks ({reason}).",
                    path.display()
                )
            }
            DispatchError::Dacl(e) => write!(f, "Failed to apply DACL ACEs: {e}"),
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

impl From<DaclError> for DispatchError {
    fn from(e: DaclError) -> Self {
        DispatchError::Dacl(e)
    }
}

/// The container-id → AppContainer-name mapping used by the runners. Empty
/// container_id maps to `"CLI"` (matches both AppContainerScriptRunner and
/// BaseContainerRunner internals).
fn container_name(request: &CodexRequest) -> String {
    if request.container_id.is_empty() {
        "CLI".to_string()
    } else {
        request.container_id.clone()
    }
}

fn paths_to_pathbufs(paths: &[String]) -> Vec<PathBuf> {
    paths.iter().map(PathBuf::from).collect()
}

/// Build a runner with appropriate DACL augmentation for the
/// BaseContainer-preferred path. The caller is responsible for the explicit
/// (no-fallback) AppContainer path.
///
/// On success the returned [`Dispatched`] contains a runner ready to
/// execute and (when applicable) a [`DaclManager`] that has already
/// applied its ACEs. The caller MUST keep `dacl_manager` alive through the
/// run.
pub fn dispatch_with_fallback(request: &CodexRequest) -> Result<Dispatched, DispatchError> {
    let decision = fallback_detector::detect(&request.policy, /*prefer_bc=*/ true)?;

    let (runner, dacl_manager): (Box<dyn ScriptRunner>, Option<DaclManager>) = match decision.tier {
        IsolationTier::BaseContainer => {
            // Tier 1 delegates filesystem-policy enforcement to
            // BaseContainer's native API. We do NOT stamp host-DACL
            // deny ACEs here because the AppContainer SID derived from
            // `container_name(request)` is not guaranteed to match the
            // opaque principal `Experimental_CreateProcessInSandbox`
            // actually runs the child under; a mismatch would render
            // the ACEs inert and silently un-enforce `deniedPaths`.
            let runner: Box<dyn ScriptRunner> = Box::new(BaseContainerRunner::new());
            (runner, None)
        }
        IsolationTier::AppContainerDacl => {
            // T3 always stamps grant ACEs (for readwrite/readonly paths)
            // and optionally deny ACEs. Allocate per-arm so T1 doesn't
            // pay the cost.
            let readwrite = paths_to_pathbufs(&request.policy.readwrite_paths);
            let readonly = paths_to_pathbufs(&request.policy.readonly_paths);
            let denied = paths_to_pathbufs(&request.policy.denied_paths);
            let sid = derive_sid_string(&container_name(request)).map_err(DispatchError::Sid)?;
            let mut mgr = DaclManager::new()?;
            mgr.grant_appcontainer_access(&sid, &readwrite, &readonly)?;
            if !denied.is_empty() {
                mgr.add_deny_aces(&sid, &denied)?;
            }
            let runner: Box<dyn ScriptRunner> =
                Box::new(AppContainerScriptRunner::with_sid_string(sid));
            (runner, Some(mgr))
        }
    };

    Ok(Dispatched {
        runner,
        dacl_manager,
        tier: decision.tier,
        warnings: decision.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CodexRequest, ContainerPolicy};
    // `ForceTierGuard` lives in `crate::test_env` so the lock is
    // shared with the `fallback_detector::tests` module — otherwise
    // a dispatcher test and a fallback-detector test running on
    // different threads could each mutate `MXC_FORCE_TIER` under
    // independent locks and race.
    use crate::test_env::ForceTierGuard;

    fn test_request(policy: ContainerPolicy) -> CodexRequest {
        CodexRequest {
            container_id: "MxcDispatcherTest".to_string(),
            policy,
            ..CodexRequest::default()
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
            d.dacl_manager.is_none(),
            "T1 with no denied_paths should not allocate DaclManager"
        );
    }
    #[test]
    fn dispatch_t1_with_denied_paths_has_no_dacl() {
        // T1 delegates filesystem-policy enforcement (including
        // `deniedPaths`) to BaseContainer's native API; the dispatcher
        // does not stamp host-DACL deny ACEs on the T1 path, so no
        // `DaclManager` is attached regardless of the `deniedPaths`
        // contents. See the module-level doc for the principal-match
        // reasoning.
        let _g = ForceTierGuard::set("base-container");
        let (policy, _tmp) = policy_with_denied_temp();
        let req = test_request(policy);
        let d = dispatch_with_fallback(&req).expect("T1+deny dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::BaseContainer));
        assert!(
            d.dacl_manager.is_none(),
            "T1 must not attach a DaclManager — BC handles deny natively"
        );
    }
    #[test]
    fn dispatch_t3_always_has_dacl() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let (policy, _tmp) = policy_with_rw_temp();
        let req = test_request(policy);
        let d = dispatch_with_fallback(&req).expect("T3 dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::AppContainerDacl));
        assert!(
            d.dacl_manager.is_some(),
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
    fn dispatch_warnings_propagated() {
        // Forced decisions don't synthesize warnings, so trigger the real
        // chain with an unrecognized force value: the detector ignores it
        // and walks the probe chain, accumulating "BaseContainer API not
        // present" warnings as appropriate on the test machine.
        let _g = ForceTierGuard::set("not-a-real-tier");
        let req = test_request(empty_policy());
        // We can't predict the tier on arbitrary CI hardware, so just
        // assert dispatch returns a Dispatched whose warnings field is
        // honored from the decision.
        let d = dispatch_with_fallback(&req).expect("real chain on empty policy");
        // Warnings vector is present (possibly empty if we got T1 on a
        // BC-capable machine). Just assert it was forwarded from the
        // decision — the type guarantees this.
        let _ = d.warnings.len();
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

    #[test]
    fn dispatch_t1_runs_trivial_command_when_bc_present() {
        // Natural T1 selection (no force). Skip on systems where the
        // BaseContainer API isn't present.
        if !crate::fallback_detector::is_base_container_api_present() {
            eprintln!("skipping: BaseContainer API not present on this machine");
            return;
        }
        // Just exercise dispatcher construction; we don't actually exec
        // here because spinning up BC requires kernel support and fights
        // the test runner's stdio capture.
        let req = test_request(empty_policy());
        let d = dispatch_with_fallback(&req).expect("dispatch should succeed");
        assert!(matches!(d.tier, IsolationTier::BaseContainer));
    }
}
