// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Platform-agnostic modules (shared by wxc-exec, lxc-exec, mxc-exec-mac
// and every backend crate).
pub mod cmdline;
pub mod config_parser;
pub mod encoding;
pub mod error;
pub mod id;
pub mod log_symbols;
pub mod logger;
#[cfg(all(feature = "microvm", any(target_os = "windows", target_os = "linux")))]
pub mod microvm_staging;
pub mod models;
pub mod mxc_error;
pub mod sandbox_process;
pub mod script_runner;
pub mod state_aware_backend;
pub mod state_aware_dispatch;
pub mod state_aware_request;
pub mod ui_policy;
pub mod validator;

// Dedicated well-typed wire model + schema generation. Compiled under the
// `schema-gen` feature for now; it is intended to become the always-compiled
// parser deserialization target.
#[cfg(feature = "schema-gen")]
pub mod wire;

// Thin Windows-only helpers that are not backend-specific. Backend
// runners live in dedicated crates under `backends/`; only utilities
// shared across host tools (e.g. wxc_host_prep, mxc_diagnostic_console)
// and ≥1 backend stay here.
#[cfg(target_os = "windows")]
pub mod diagnostic;
#[cfg(target_os = "windows")]
pub mod filesystem_dacl;
#[cfg(target_os = "windows")]
pub mod process_util;
#[cfg(target_os = "windows")]
pub mod string_util;

// Unix-specific modules (shared by the Seatbelt and Bubblewrap backends).
#[cfg(unix)]
pub mod interruptible_reader;

// Linux-specific modules
#[cfg(target_os = "linux")]
pub mod linux_proxy_coordinator;

/// Test-only helper for env-var serialization within this crate's
/// `filesystem_dacl` tests. The same shape lives in
/// `backends/appcontainer/common/src/test_env.rs`; each crate has its
/// own `ENV_LOCK` because the env-var contention is only within a
/// single test binary.
#[cfg(all(test, target_os = "windows"))]
pub(crate) mod test_env;
