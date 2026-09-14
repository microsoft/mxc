// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native Windows ProcessContainer backend using the PSEC and transitional
//! SBOX BaseContainer contracts.
//!
//! All modules are Windows-only. The crate links unconditionally so
//! `wxc-exec` can depend on it without feature gates.

#[cfg(target_os = "windows")]
mod base_container_helpers;
#[cfg(target_os = "windows")]
pub mod base_container_runner;
#[cfg(target_os = "windows")]
pub mod capture_output;
#[cfg(target_os = "windows")]
pub mod dispatcher;
#[cfg(target_os = "windows")]
mod environment;
#[cfg(target_os = "windows")]
pub mod guarded_capture;
#[cfg(target_os = "windows")]
pub mod job_object;
#[cfg(target_os = "windows")]
pub mod launch_diagnostics;
#[cfg(target_os = "windows")]
mod network_policy_helpers;
#[cfg(target_os = "windows")]
pub mod probe;
#[cfg(target_os = "windows")]
pub mod process_mitigation;
#[cfg(target_os = "windows")]
pub mod proxy_coordinator;
#[cfg(target_os = "windows")]
pub mod sandbox_tracking;
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
