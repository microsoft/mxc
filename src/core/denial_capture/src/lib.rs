// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-PID denial capture for MXC sandboxed workloads.
//!
//! Goals (prototype scope):
//! - Provide the public `DeniedResource` type the SDK surfaces to callers.
//! - Provide the internal `DenialEvent` type produced by ETW extractors plus
//!   the extractor functions themselves (`build_denial_from_access_check`,
//!   `build_denial_from_learning_mode`).
//! - Provide path normalization that maps `\Device\HarddiskVolumeN\…` kernel
//!   form to user-visible `<drive>:\…` form.
//!
//! The scoped ETW session itself lives in `denial_capture::session` (added
//! in Phase 3). This crate is deliberately runtime-free at the public API
//! layer so the SDK can deserialize `DeniedResource` on any platform.
//!
//! Both `DenialEvent` (internal) and `DeniedResource` (public) ship in the
//! same crate so the conversion is local and round-trippable.

pub mod extractors;
pub mod model;

#[cfg(target_os = "windows")]
pub mod path_norm;

pub use extractors::{
    build_denial_from_access_check, build_denial_from_learning_mode, DecodedEventParts,
};
pub use model::{AccessType, DenialEvent, DeniedResource, ResourceType};
