// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ScriptResponse carries a Vec<DeniedResource>; Result<_, ScriptResponse>
// trips clippy::result_large_err. The response is moved once into the
// dispatch path and serialised, so boxing the Err variant doesn't buy
// anything here.
#![allow(clippy::result_large_err)]

//! `bwrap_common` — shared library for the Bubblewrap sandbox backend.
//!
//! - [`bwrap_command`] builds the `bwrap` CLI argument vector from a
//!   [`ExecutionRequest`](wxc_common::models::ExecutionRequest). It is
//!   platform-agnostic (pure argument generation) so it compiles and is
//!   fully unit-tested on every host.
//! - [`bwrap_runner`] is gated to `target_os = "linux"` since it actually
//!   spawns the `bwrap` binary.

pub mod bwrap_command;
#[cfg(target_os = "linux")]
pub mod bwrap_runner;
