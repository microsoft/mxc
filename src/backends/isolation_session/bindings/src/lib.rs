// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generated WinRT bindings for the IsolationSession Preview API.
//!
//! The bindings are generated **at build time** by `build.rs` from the WinMD
//! inside the checked-in SDK nuget
//! (`external/windows-sdk/isolation-session/*.nupkg`) using `windows-bindgen`,
//! so the crate is always built directly against the pinned SDK package rather
//! than a committed snapshot.
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
pub mod bindings {
    // Generated into OUT_DIR by build.rs from the SDK nuget's Preview WinMD.
    // The outer #[allow] above covers the generated items (the file's own
    // inner #![allow] does not propagate through include! into this module).
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
