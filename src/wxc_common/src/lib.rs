// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Platform-agnostic modules (shared by wxc-exec and lxc-exec)
pub mod cmdline;
pub mod config_parser;
pub mod encoding;
pub mod error;
#[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
pub mod hyperlight_runner;
pub mod id;
pub mod log_symbols;
pub mod logger;
#[cfg(all(feature = "microvm", any(target_os = "windows", target_os = "linux")))]
pub mod microvm_staging;
pub mod models;
pub mod mxc_error;
#[cfg(all(feature = "microvm", any(target_os = "windows", target_os = "linux")))]
pub mod nanvix_runner;
pub mod script_runner;
pub mod state_aware_backend;
pub mod state_aware_dispatch;
pub mod state_aware_request;
pub mod ui_policy;
pub mod validator;

// Windows-specific modules
#[cfg(target_os = "windows")]
pub mod appcontainer_runner;
#[cfg(target_os = "windows")]
pub mod dispatcher;
#[cfg(target_os = "windows")]
pub mod fallback_detector;
#[cfg(target_os = "windows")]
pub mod filesystem_bfs;
#[cfg(target_os = "windows")]
pub mod filesystem_dacl;
#[cfg(target_os = "windows")]
pub mod job_object;
#[cfg(target_os = "windows")]
pub mod network_manager;
#[cfg(target_os = "windows")]
pub mod probe;
#[cfg(target_os = "windows")]
pub mod process_mitigation;
#[cfg(target_os = "windows")]
pub mod process_util;
#[cfg(target_os = "windows")]
pub mod proxy_coordinator;
#[cfg(target_os = "windows")]
pub mod sandbox_protocol;
#[cfg(target_os = "windows")]
pub mod string_util;
#[cfg(target_os = "windows")]
pub mod windows_sandbox_runner;

// Diagnostic logging (registry/env-controlled real-time output)
#[cfg(target_os = "windows")]
pub mod diagnostic;

// BaseContainer (composable sandbox) support
#[cfg(target_os = "windows")]
pub mod base_container_runner;
#[cfg(target_os = "windows")]
pub mod launch_diagnostics;
#[cfg(target_os = "windows")]
pub mod sandbox_tracking;

// Isolation Session (IsoEnvBroker Session API) support
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub mod isolation_session;

// Linux-specific modules
#[cfg(target_os = "linux")]
pub mod linux_proxy_coordinator;

/// Test-only helpers shared across unit-test modules.
///
/// Gated by `#[cfg(test)]` so this module compiles in only when
/// building the crate's own test binary (under any profile, including
/// CI's `--profile release`). Production binaries never link this.
/// All current consumers (`dispatcher`, `fallback_detector`, `probe`,
/// `filesystem_dacl`) are Windows-only, so the module is additionally
/// gated on `target_os = "windows"` to avoid dead-code warnings under
/// `-D warnings` when running `cargo clippy --all-targets` on Linux.
#[cfg(all(test, target_os = "windows"))]
pub(crate) mod test_env;
