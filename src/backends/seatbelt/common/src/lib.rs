// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ScriptResponse carries a Vec<DeniedResource>; Result<_, ScriptResponse>
// trips clippy::result_large_err. The response is moved once into the
// dispatch path and serialised, so boxing the Err variant doesn't buy
// anything here.
#![allow(clippy::result_large_err)]

//! `seatbelt_common` — shared library for the macOS sandbox backend.
//!
//! - [`profile_builder`] is platform-agnostic (pure string generation) so it
//!   compiles and is fully unit-tested on every host. This lets reviewers
//!   validate profile generation without a Mac.
//! - [`seatbelt_runner`] is gated to `target_os = "macos"` since it spawns
//!   `/usr/bin/sandbox-exec`.

pub mod profile_builder;

#[cfg(target_os = "macos")]
pub mod seatbelt_runner;
