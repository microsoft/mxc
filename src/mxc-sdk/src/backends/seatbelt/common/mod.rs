// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `seatbelt_common` — shared library for the macOS sandbox backend.
//!
//! - [`profile_builder`] formats prepared inputs without host discovery, so it
//!   is unit-tested on every host.
//! - macOS-only preparation resolves paths and discovers host directories.
//! - [`seatbelt_policy`] owns the backend's network invariants and effective-
//!   policy helpers. Also platform-agnostic, so the rules are unit-tested
//!   everywhere even though only macOS can execute them.
//! - [`default_env`] resolves the schema-0.9 default `process.env` block.
//!   Platform-agnostic for the same reason.
//! - [`seatbelt_runner`] is gated to `target_os = "macos"` since it calls
//!   `sandbox_init()`.

pub mod default_env;
pub mod profile_builder;
pub mod seatbelt_policy;

#[cfg(target_os = "macos")]
pub(crate) mod profile_preparation;
#[cfg(target_os = "macos")]
pub mod seatbelt_runner;
