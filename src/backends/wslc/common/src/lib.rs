// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSLC Common — WSL Container SDK integration for MXC.
//!
//! Provides Rust FFI bindings to the WSLC SDK C API, plus the two execution
//! models built on it, both implemented by
//! [`WSLContainerRunner`](wsl_container_runner::WSLContainerRunner) over one
//! shared container lifecycle: run-to-completion (`ScriptRunner`, used by
//! `wxc-exec`) and streaming (`SandboxBackend`, in [`sandbox`], used by the
//! Rust SDK).

pub mod policy_mapping;
pub mod sandbox;
mod stream_buffer;
pub mod wsl_container_runner;
pub mod wslc_bindings;

pub use wsl_container_runner::WSLContainerRunner;
pub use wslc_bindings::is_available;
