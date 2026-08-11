// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Adapts `plm::elevated`'s guarded WPR capture protocol to
//! `appcontainer_common::guarded_capture`'s DI traits.
//!
//! `appcontainer_common` cannot depend on `plm` directly (see
//! `appcontainer_common::guarded_capture`'s module docs for the crate-layering
//! rationale). `mxc_engine` sits above both — it already has the Windows
//! backend crates as dependencies — so it owns the concrete adapter and hands
//! it to the dispatcher only for requests that actually need the fallback
//! (`request.policy.capture_denials.is_some()` on a non-native tier).

use appcontainer_common::guarded_capture::{GuardedCaptureFactory, GuardedCaptureSession};
use learning_mode_core::{AnalysisResult, ProcessLifetime};

/// Resolve `plm.exe`'s path, expected to sit next to the current executable
/// (mirroring `wxc-exec --audit`'s own `plm_exe_path` convention — see
/// `core/wxc/src/audit.rs`). `mxc_engine` cannot reuse that helper directly
/// (`wxc` depends on `mxc_engine`, not the other way around), so it is
/// duplicated here at the same, small scope.
fn plm_exe_path() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to resolve the current executable's path: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "the current executable has no parent directory".to_string())?;
    Ok(dir.join("plm.exe"))
}

/// [`GuardedCaptureSession`] backed by a live `plm::elevated::GuardedSession`.
struct PlmGuardedCaptureSession {
    session: plm::elevated::GuardedSession,
}

impl GuardedCaptureSession for PlmGuardedCaptureSession {
    fn stop_analyzed(&mut self, lifetimes: &[ProcessLifetime]) -> Result<AnalysisResult, String> {
        self.session
            .stop_analyzed(lifetimes)
            .map_err(|e| format!("guarded WPR stop/analyze failed: {e:#}"))
    }
}

/// [`GuardedCaptureFactory`] that starts a guarded WPR capture session via the
/// elevated `plm.exe` guardian, using [`plm::elevated::start_guarded_session_with_executable`].
pub struct PlmGuardedCaptureFactory;

impl GuardedCaptureFactory for PlmGuardedCaptureFactory {
    fn start(&self, owner_pid: u32) -> Result<Box<dyn GuardedCaptureSession>, String> {
        let plm_path = plm_exe_path()?;
        start_with_plm_path(&plm_path, owner_pid)
    }
}

/// Start a guarded session against an explicit `plm.exe` path. Split out from
/// [`PlmGuardedCaptureFactory::start`] so unit tests can exercise the
/// missing-guardian rejection deterministically, against a synthetic path,
/// rather than depending on whether `plm.exe` happens to already exist next to
/// the current test binary in a given build/CI environment.
fn start_with_plm_path(
    plm_path: &std::path::Path,
    owner_pid: u32,
) -> Result<Box<dyn GuardedCaptureSession>, String> {
    if !plm_path.exists() {
        return Err(format!(
            "plm.exe not found at {} (required for the guarded WPR captureDenials fallback)",
            plm_path.display()
        ));
    }
    let session = plm::elevated::start_guarded_session_with_executable(plm_path, owner_pid)
        .map_err(|e| format!("guarded WPR session start failed: {e:#}"))?;
    Ok(Box::new(PlmGuardedCaptureSession { session }))
}

/// Build the guarded-capture factory to hand to the dispatcher for `request`,
/// or `None` when `captureDenials` isn't requested. Centralizing this (rather
/// than constructing a `PlmGuardedCaptureFactory` unconditionally at every call
/// site) keeps `run.rs` / `dispatch.rs` from wiring a factory the request never
/// needed.
pub fn factory_for_request(
    request: &wxc_common::models::ExecutionRequest,
) -> Option<std::sync::Arc<dyn GuardedCaptureFactory>> {
    if request.policy.capture_denials.is_some() {
        Some(std::sync::Arc::new(PlmGuardedCaptureFactory))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_rejects_a_nonexistent_plm_path() {
        // Deterministic regardless of build/CI environment: point at a path
        // that is guaranteed not to exist rather than relying on whether
        // `plm.exe` happens to already sit next to the test binary.
        let missing = std::env::temp_dir().join("mxc-guarded-capture-test-nonexistent-plm.exe");
        assert!(!missing.exists(), "test setup: path must not exist");

        let error = match start_with_plm_path(&missing, std::process::id()) {
            Ok(_) => panic!("a nonexistent plm.exe path must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("plm.exe"), "got: {error}");
    }

    #[test]
    fn factory_for_request_is_none_without_capture_denials() {
        let request = wxc_common::models::ExecutionRequest::default();
        assert!(factory_for_request(&request).is_none());
    }

    #[test]
    fn factory_for_request_is_some_with_capture_denials() {
        let mut request = wxc_common::models::ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());
        assert!(factory_for_request(&request).is_some());
    }
}
