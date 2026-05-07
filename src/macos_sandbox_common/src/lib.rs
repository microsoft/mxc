// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `macos_sandbox_common` — shared library for the macOS sandbox backend.
//!
//! - [`profile_builder`] is platform-agnostic (pure string generation) so it
//!   compiles and is fully unit-tested on every host. This lets reviewers
//!   validate profile generation without a Mac.
//! - [`macos_sandbox_runner`] is gated to `target_os = "macos"` since it spawns
//!   `/usr/bin/sandbox-exec`.

pub mod profile_builder;

#[cfg(target_os = "macos")]
pub mod macos_sandbox_runner;
