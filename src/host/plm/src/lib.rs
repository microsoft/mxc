// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Library surface for the permissive learning mode (PLM) crate.
//! Pure-data modules compile cross-platform; Windows-only items are
//! gated per-module. The `plm` binary in `main.rs` is Windows-only.

pub mod coordination;
pub mod profile_gen;

#[cfg(target_os = "windows")]
pub mod log;

#[cfg(target_os = "windows")]
pub mod start;

#[cfg(target_os = "windows")]
pub mod stop;

#[cfg(target_os = "windows")]
pub mod wpr_path;
