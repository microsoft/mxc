// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ScriptResponse carries a Vec<DeniedResource>; Result<_, ScriptResponse>
// trips clippy::result_large_err. The response is moved once into the
// dispatch path and serialised, so boxing the Err variant doesn't buy
// anything here.
#![allow(clippy::result_large_err)]

//! WSLC Common — WSL Container SDK integration for MXC.
//!
//! Provides Rust FFI bindings to the WSLC SDK C API and will contain
//! the WSL Container runner and policy mapping modules.

pub mod policy_mapping;
pub mod wsl_container_runner;
pub mod wslc_bindings;
