// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-platform orchestration layer for the learning-mode capture
//! feature.
//!
//! ## Box-2 of the learning-mode architecture
//!
//! The captureDenials feature is organised into three layered boxes:
//!
//! 1. **`denial_channel`** — wire types ([`DeniedResource`],
//!    [`ResourceType`], [`AccessType`]) and the cross-platform NDJSON
//!    parser; re-exported from this crate so callers only need to
//!    import `learning_mode`.
//! 2. **`learning_mode`** (this crate) — OS-agnostic orchestration:
//!    re-exports the [`LearningModeBackend`] trait + shared types
//!    from [`learning_mode_api`] (split out to break a cargo
//!    dependency cycle) and provides the [`orchestrator::current_backend`]
//!    dispatcher.
//! 3. **`learning_mode_<os>`** — per-OS adapters that implement
//!    [`LearningModeBackend`]:
//!    - `learning_mode_windows` — ETW kernel-audit + shim RPC.
//!    - `learning_mode_linux` — stub (`Err(NotSupported)`).
//!    - `learning_mode_macos` — stub (`Err(NotSupported)`).
//!
//! Runners (and the SDK orchestrator) talk to this crate only. They
//! call [`orchestrator::current_backend`] to obtain a
//! [`LearningModeBackend`] and drive it through
//! [`LearningModeBackend::begin_capture`] +
//! [`CaptureHandle::stop_and_drain`].

pub use learning_mode_api::{
    AccessType, CaptureHandle, CaptureOptions, CaptureSummary, DeniedResource, LearningModeBackend,
    LearningModeError, ResourceType,
};

pub mod orchestrator;
