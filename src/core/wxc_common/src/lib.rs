// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Platform-agnostic modules (shared by wxc-exec, lxc-exec, mxc-exec-mac
// and every backend crate).
pub mod cmdline;
mod config_deserialize;
pub mod config_parser;
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
mod network_parser;
pub use network_parser::directional_network_support;
pub use network_parser::host_is_canonical_loopback;
pub use network_parser::supports_directional_network;
pub mod proxy_env;
pub mod sandbox_process;
pub mod script_runner;
pub mod state_aware_backend;
pub mod state_aware_dispatch;
pub mod state_aware_request;
// Not yet reachable from production dispatch; see Gudge.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod state_aware_wire;
pub mod telemetry;
pub mod ui_policy;
pub mod validator;

// Dedicated well-typed wire model. It is the parser's deserialization target;
// the JSON Schema is generated from it under the `schema-gen` feature.
pub mod wire;

// Adapters that map between specific JSON contracts and the 'wire' model.
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
/// `backends/appcontainer/common/src/test_env.rs`; each crate has its
/// own `ENV_LOCK` because the env-var contention is only within a
/// single test binary.
#[cfg(all(test, target_os = "windows"))]
pub(crate) mod test_env;
