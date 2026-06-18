// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows learning-mode backend for MXC sandboxed workloads.
//!
//! This crate implements the Windows-side pieces of the learning_mode box:
//!
//! - **ETW kernel-audit session** (`session`): per-PID scoped trace that
//!   captures `Microsoft-Windows-Kernel-Audit` access-check + Learning-
//!   Mode-Violation events.
//! - **Event extractors** (`extractors`, `tdh_decode`): TDH-based property
//!   decoders that turn raw ETW records into the intermediate
//!   [`DenialEvent`].
//! - **Shim RPC wire format** (`wire`): named-pipe protocol used to ask
//!   the privileged `mxc-learning-mode-shim` service to loan a trace
//!   handle scoped to a PID + AppContainer SID.
//! - **Path canonicalisation** (`path_norm`): turns kernel-form
//!   `\Device\HarddiskVolumeN\...` paths into drive-letter form.
//! - **Stderr/named-pipe streaming protocol** (`denial_stream`): NDJSON
//!   wire format and dedupe used by the runners to surface denials.
//! - **Child-process Toolhelp observer** (`child_process_observer`):
//!   PID-discovery thread used to keep the ETW filter in sync with
//!   spawned descendants.
//!
//! The cross-platform public types (`DeniedResource`, `ResourceType`,
//! `AccessType`) live in the [`denial_channel`] crate and are
//! re-exported here for back-compat.

pub mod extractors;
pub mod model;
pub mod wire;

#[cfg(target_os = "windows")]
pub mod path_norm;

#[cfg(target_os = "windows")]
pub mod session;

#[cfg(target_os = "windows")]
pub mod tdh_decode;

#[cfg(target_os = "windows")]
pub mod denial_stream;

#[cfg(target_os = "windows")]
pub mod child_process_observer;

#[cfg(target_os = "windows")]
pub mod backend;

#[cfg(target_os = "windows")]
pub use backend::WindowsLearningModeBackend;

pub use extractors::{
    build_denial_from_access_check, build_denial_from_learning_mode, DecodedEventParts,
};
pub use model::DenialEvent;
pub use denial_channel::{AccessType, DeniedResource, ResourceType};
