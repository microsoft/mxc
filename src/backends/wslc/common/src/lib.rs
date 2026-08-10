// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSLC Common — WSL Container SDK integration for MXC.
//!
//! [`wslcsdk_sys`] holds the bindgen-generated FFI declarations for the WSLC
//! SDK C API; [`wslc_bindings`] wraps them in the runtime loader and RAII
//! guards the rest of the crate uses.
//!
//! On top of those sit the two execution models, both implemented by
//! [`WSLContainerRunner`](wsl_container_runner::WSLContainerRunner) over one
//! shared container lifecycle: run-to-completion (`ScriptRunner`, used by
//! `wxc-exec`) and streaming (`SandboxBackend`, in [`sandbox`], used by the
//! Rust SDK).

pub mod container_steps;
pub mod daemon_client;
pub mod daemon_protocol;
pub mod daemon_record;
pub mod policy_mapping;
pub mod sandbox;
mod stream_buffer;
pub mod wsl_container_runner;
pub mod wslc_bindings;
pub mod wslcsdk_sys;

pub use wsl_container_runner::WSLContainerRunner;
pub use wslc_bindings::is_available;
