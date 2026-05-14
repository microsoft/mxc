// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `bwrap_common` — shared library for the Bubblewrap sandbox backend.
//!
//! - [`bwrap_command`] builds the `bwrap` CLI argument vector from a
//!   [`CodexRequest`](wxc_common::models::CodexRequest). It is
//!   platform-agnostic (pure argument generation) so it compiles and is
//!   fully unit-tested on every host.
//! - [`bwrap_runner`] is gated to `target_os = "linux"` since it actually
//!   spawns the `bwrap` binary.

pub mod bwrap_command;
pub mod bwrap_runner;
