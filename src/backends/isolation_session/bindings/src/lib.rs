// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generated WinRT bindings for the IsolationSession APIs.
//!
//! `bindings` contains the stable Preview projection used for provisioning and
//! lifecycle management. `official_bindings` contains the official projection
//! required for IsoTask-aware process creation.
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
pub mod official_bindings;
