// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ScriptResponse carries a Vec<DeniedResource>; Result<_, ScriptResponse>
// trips clippy::result_large_err. The response is moved once into the
// dispatch path and serialised, so boxing the Err variant doesn't buy
// anything here.
#![allow(clippy::result_large_err)]

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
pub mod base_container_runner;
#[cfg(target_os = "windows")]
mod denial_stream;
#[cfg(target_os = "windows")]
pub mod dispatcher;
#[cfg(target_os = "windows")]
pub mod fallback_detector;
#[cfg(target_os = "windows")]
pub mod filesystem_bfs;
#[cfg(target_os = "windows")]
pub mod job_object;
#[cfg(target_os = "windows")]
pub mod launch_diagnostics;
#[cfg(target_os = "windows")]
pub mod network_manager;
#[cfg(target_os = "windows")]
pub mod probe;
#[cfg(target_os = "windows")]
pub mod process_mitigation;
#[cfg(target_os = "windows")]
pub mod proxy_coordinator;
#[cfg(target_os = "windows")]
pub mod sandbox_tracking;

/// Test-only helpers shared across this crate's unit-test modules.
/// Mirrors the helper that previously lived in `wxc_common::test_env`;
/// kept private to each crate so each test binary has its own
/// `ENV_LOCK` (the process-globals are only contended within a test
/// binary).
#[cfg(all(test, target_os = "windows"))]
pub(crate) mod test_env;
