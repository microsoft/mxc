// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generated WinRT bindings for the IsolationSession Preview API.
//!
//! Inbox builds use the committed OS-generated projection. Builds with the
//! `lifted` feature regenerate the projection from the pinned SDK package
//! restored from NuGet.org.
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
#[cfg(feature = "lifted")]
pub mod bindings {
    // Generated into OUT_DIR by build.rs from the SDK nuget's Preview WinMD.
    // The outer #[allow] above covers the generated items (the file's own
    // inner #![allow] does not propagate through include! into this module).
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(not(feature = "lifted"))]
pub mod bindings;
