// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Platform-agnostic modules (shared by wxc-exec and lxc-exec)
pub mod config_parser;
pub mod encoding;
pub mod error;
pub mod logger;
pub mod models;
pub mod nanvix_runner;
pub mod script_runner;
pub mod validator;

// Windows-specific modules
#[cfg(target_os = "windows")]
pub mod appcontainer;
#[cfg(target_os = "windows")]
pub mod filesystem_bfs;
#[cfg(target_os = "windows")]
pub mod network_manager;
#[cfg(target_os = "windows")]
pub mod process_util;
#[cfg(target_os = "windows")]
pub mod proxy_coordinator;
#[cfg(target_os = "windows")]
pub mod sandbox_protocol;
#[cfg(target_os = "windows")]
pub mod sandbox_runner;
#[cfg(target_os = "windows")]
pub mod string_util;
