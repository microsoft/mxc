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
use learning_mode_core::AnalysisResult;
use std::os::windows::ffi::OsStringExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};

const GUARDIAN_CONFIRM_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

fn confirm_guardian_release_after_discard_failure(
    discard_error: String,
    mut confirm_release: impl FnMut() -> Result<(), String>,
    mut on_retry: impl FnMut(&str),
) -> Result<(), String> {
    loop {
        match confirm_release() {
            Ok(()) => {
                return Err(format!(
                    "guarded WPR discard failed: {discard_error}; guardian termination was \
                     confirmed by the cleanup fallback"
                ));
            }
            Err(error) => on_retry(&error),
        }
    }
}

/// Resolve `plm.exe` next to the module containing `mxc_engine`.
///
/// This is the executor directory for `wxc-exec.exe` and the native runtime
/// asset directory for `mxc_ffi.dll`. `current_exe()` is not sufficient for
/// library consumers because a framework-dependent .NET app reports
/// `dotnet.exe`, not the loaded MXC native module.
fn plm_exe_path() -> Result<std::path::PathBuf, String> {
    let module = module_containing_plm_resolver()?;
    let dir = module
        .parent()
        .ok_or_else(|| "the MXC native module has no parent directory".to_string())?;
    Ok(dir.join("plm.exe"))
}

fn module_containing_plm_resolver() -> Result<std::path::PathBuf, String> {
    let mut module = HMODULE::default();
    let address = plm_exe_path as *const () as *const u16;
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(address),
            &mut module,
        )
    }
    .map_err(|error| format!("failed to locate the MXC native module: {error}"))?;

    let mut path = vec![0u16; 32_768];
    let len = unsafe { GetModuleFileNameW(Some(module), &mut path) } as usize;
    if len == 0 {
        return Err(format!(
            "failed to resolve the MXC native module path: {}",
            windows::core::Error::from_thread()
        ));
    }
    if len >= path.len() {
        return Err("the MXC native module path exceeds the Windows path limit".to_string());
    }
    path.truncate(len);
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_wide(
        &path,
    )))
}

/// [`GuardedCaptureSession`] backed by a live `plm::elevated::GuardedSession`.
struct PlmGuardedCaptureSession {
    session: plm::elevated::GuardedSession,
}

impl GuardedCaptureSession for PlmGuardedCaptureSession {
    fn attach_process_tree(
        &mut self,
        job_handle: usize,
        root_process_handle: usize,
    ) -> Result<(), String> {
        self.session
            .attach_process_tree(job_handle, root_process_handle)
            .map_err(|e| format!("guarded WPR process-tree attach failed: {e:#}"))
    }

    fn discard(&mut self) -> Result<(), String> {
        let discard_error = match self.session.discard() {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };

        confirm_guardian_release_after_discard_failure(
            format!("{discard_error:#}"),
            || self.session.cancel().map_err(|error| format!("{error:#}")),
            |error| {
                eprintln!(
                    "[mxc] guarded WPR guardian termination remains unconfirmed after \
                     discard failure; sandbox enforcement is still active: {error}"
                );
                std::thread::sleep(GUARDIAN_CONFIRM_RETRY_DELAY);
            },
        )
    }

    fn stop_analyzed(&mut self) -> Result<AnalysisResult, String> {
        self.session
            .stop_analyzed()
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

    #[test]
    fn resolver_locates_the_current_native_module() {
        let module = module_containing_plm_resolver().expect("test module path should resolve");
        assert!(module.is_absolute());
        assert!(module.is_file());
    }

    #[test]
    fn discard_failure_retries_with_backoff_until_release_is_confirmed() {
        let mut attempts = 0;
        let mut retries = Vec::new();

        let error = confirm_guardian_release_after_discard_failure(
            "discard protocol failed".to_string(),
            || {
                attempts += 1;
                if attempts < 3 {
                    Err(format!("confirmation attempt {attempts} failed"))
                } else {
                    Ok(())
                }
            },
            |error| retries.push(error.to_string()),
        )
        .unwrap_err();

        assert_eq!(attempts, 3);
        assert_eq!(
            retries,
            [
                "confirmation attempt 1 failed",
                "confirmation attempt 2 failed"
            ]
        );
        assert!(error.contains("discard protocol failed"));
        assert!(error.contains("guardian termination was confirmed"));
    }
}
