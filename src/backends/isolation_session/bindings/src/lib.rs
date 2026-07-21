// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generated WinRT bindings for the IsoEnvBroker Session API.
//!
//! This crate contains Rust projections generated from the
//! `Windows.AI.IsolationSession` WinMD using `windows-bindgen`.
//!
//! See `external/windows-sdk/isolation-session/GENERATION_INFO.toml`
//! for provenance details.

#[allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]
pub mod bindings;

/// The IsoSession runtime instance this crate was built against, baked in by
/// `build.rs` from the SDK NuGet's `GENERATION_INFO.toml` (`instance` key) via
/// `cargo:rustc-env=ISOSESSION_INSTANCE`.
///
/// `None` when the build had no instance to bake (source-only build whose
/// committed provenance fallback carries no `instance`). The IsolationSession
/// backend uses this to verify the installed runtime folder matches the build.
///
/// Exposed here because `cargo:rustc-env` only reaches the crate whose
/// build script emitted it — `option_env!` in a downstream crate would always
/// see `None`.
pub const EXPECTED_INSTANCE: Option<&str> = option_env!("ISOSESSION_INSTANCE");
