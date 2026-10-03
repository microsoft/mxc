// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AppContainer + BaseContainer backend family, including the
//! T1/T2/T3 isolation-tier fallback ladder and the Windows-only
//! support modules they depend on (job objects, BFS policy,
//! network/proxy plumbing, sandbox tracking, launch diagnostics).
//!
//! All modules are Windows-only. The crate links unconditionally so
//! `wxc-exec` (which always targets Windows) can depend on it
//! without feature gates, while cross-platform consumers of
//! `wxc_common` are unaffected by AppContainer code.

#[cfg(target_os = "windows")]
pub mod appcontainer_runner;
#[cfg(target_os = "windows")]
mod base_container_helpers;
#[cfg(target_os = "windows")]
pub mod base_container_runner;
#[cfg(target_os = "windows")]
pub mod capture_output;
#[cfg(target_os = "windows")]
pub mod dispatcher;
#[cfg(target_os = "windows")]
pub mod fallback_detector;
#[cfg(target_os = "windows")]
pub mod filesystem_bfs;
#[cfg(target_os = "windows")]
pub mod guarded_capture;
#[cfg(target_os = "windows")]
pub mod job_object;
#[cfg(target_os = "windows")]
pub mod launch_diagnostics;
#[cfg(target_os = "windows")]
mod native_capture;
#[cfg(target_os = "windows")]
pub mod network_manager;
#[cfg(target_os = "windows")]
mod network_policy_helpers;
#[cfg(target_os = "windows")]
pub mod probe;
#[cfg(target_os = "windows")]
pub mod process_mitigation;
#[cfg(target_os = "windows")]
pub mod proxy_coordinator;
#[cfg(target_os = "windows")]
mod pseudo_console;
#[cfg(target_os = "windows")]
pub mod sandbox_tracking;
#[cfg(target_os = "windows")]
mod secenv;
#[cfg(target_os = "windows")]
mod stdio;
#[cfg(target_os = "windows")]
pub use native_capture::CaptureSession;
#[cfg(target_os = "windows")]
pub use secenv::{
    is_security_environment_api_available, probe_security_environment_exports,
    ProcessSecurityEnvironment, SecurityEnvironmentApi as ProcessSecurityEnvironmentApi,
    SecurityEnvironmentExportReport, SecurityEnvironmentStartupInfo,
    PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};

#[cfg(target_os = "windows")]
pub(crate) fn process_timeout_elapsed(started_at: std::time::Instant, timeout_ms: u32) -> bool {
    timeout_ms != u32::MAX
        && started_at.elapsed() >= std::time::Duration::from_millis(u64::from(timeout_ms))
}

/// Working-directory resolution for both Windows launch paths. Deliberately
/// **not** `cfg`-gated: the mapping is pure, and keeping it portable means its
/// regression tests (notably "never resolve to a `NULL` cwd") run on every CI
/// lane rather than only the Windows one.
pub mod working_directory;

/// Test-only helpers shared across this crate's unit-test modules.
/// Mirrors the helper that previously lived in `wxc_common::test_env`;
/// kept private to each crate so each test binary has its own
/// `ENV_LOCK` (the process-globals are only contended within a test
/// binary).
#[cfg(all(test, target_os = "windows"))]
pub(crate) mod test_env;

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use std::time::{Duration, Instant};

    #[test]
    fn finite_process_timeout_expires_after_deadline() {
        let started_at = Instant::now() - Duration::from_millis(10);

        assert!(super::process_timeout_elapsed(started_at, 5));
        assert!(!super::process_timeout_elapsed(started_at, 50));
    }

    #[test]
    fn infinite_process_timeout_never_expires() {
        let started_at = Instant::now() - Duration::from_secs(1);

        assert!(!super::process_timeout_elapsed(started_at, u32::MAX));
    }
}
