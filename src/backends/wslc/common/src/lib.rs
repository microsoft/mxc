// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSLC Common — WSL Container SDK integration for MXC.
//!
//! Provides Rust FFI bindings to the WSLC SDK C API and will contain
//! the WSL Container runner and policy mapping modules.

pub mod policy_mapping;
pub mod wsl_container_runner;
pub mod wslc_bindings;
