// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Platform-agnostic modules (shared by wxc-exec, lxc-exec, mxc-exec-mac
// and every backend crate).
pub mod audit;
pub mod cmdline;
mod common_request_ir;
mod config_deserialize;
pub mod config_parser;
pub mod default_env;
pub mod encoding;
pub mod error;
pub mod exec_stream;
pub mod filesystem_access;
pub mod filesystem_canonical;
pub mod filesystem_object;
pub mod filesystem_resolve;
pub mod id;
pub mod log_symbols;
pub mod logger;
#[cfg(all(feature = "microvm", any(target_os = "windows", target_os = "linux")))]
pub mod microvm_staging;
pub mod models;
pub mod mxc_error;
pub mod network_blocks;
mod network_parser;
pub mod policy_identity;
pub use network_parser::host_is_canonical_loopback;
pub mod proxy_env;
pub mod sandbox_process;
pub mod script_runner;
pub(crate) mod splice;
pub mod state_aware_backend;
pub mod state_aware_binding;
pub mod state_aware_dispatch;
pub(crate) mod state_aware_input;
pub mod state_aware_operation;
pub mod state_aware_request;
pub mod telemetry;
pub mod ui_policy;
pub mod validator;

// Reusable DTOs shared by exact-contract adapters and typed SDK builders.
pub(crate) mod wire;

// Adapters that map specific JSON contracts into the internal config input.
pub(crate) mod config_contract_adapters;

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
#[cfg(target_os = "windows")]
pub mod system_dir;

// Unix-specific modules (shared by the Seatbelt and Bubblewrap backends).
#[cfg(unix)]
pub mod interruptible_reader;

// Unix cooperative network proxy coordinator, used by the Bubblewrap (Linux)
// and Seatbelt (macOS) backends.
#[cfg(unix)]
pub mod unix_proxy_coordinator;

/// Test-only helper for env-var serialization within this crate's
/// `filesystem_dacl` tests. The same shape lives in
/// `backends/process_container/common/src/test_env.rs`; each crate has its
/// own `ENV_LOCK` because the env-var contention is only within a
/// single test binary.
#[cfg(all(test, target_os = "windows"))]
pub(crate) mod test_env;
