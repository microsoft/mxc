// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-platform core for the captureDenials / learning-mode pipeline.
//!
//! MXC's learning-mode capture flow has three stages:
//!
//! 1. **Capture** — a backend runs the workload under an OS learning mode
//!    and seals a native trace (on Windows, an ETW `.etl`). This lives in
//!    the per-OS backend crates.
//! 2. **Analyse** — the trace is decoded into cross-platform
//!    [`DeniedResource`] records. The per-OS decoder implements
//!    [`DenialAnalyzer`]; this crate owns the trait and the model.
//! 3. **Emit** — the records plus a terminating [`DenialSummary`] are
//!    written to a single JSON output file that host applications read to
//!    regenerate their sandbox policy. See [`emit`].
//!
//! This crate is the cross-platform hinge between stages 2 and 3: it
//! defines the public [`DeniedResource`] model, the [`DenialSummary`]
//! terminator, the [`DenialsDocument`] output shape plus its [`emit`]ter,
//! and the [`DenialAnalyzer`] decode trait. It carries no OS-specific code
//! so the wire format never encodes a platform assumption.
//!
//! ## Mode caveat
//!
//! What a capture contains depends on the active OS learning mode.
//! File/path and UI denials are recorded under both `learningMode`
//! (block-and-log) and `permissiveLearningMode` (allow-and-log), but
//! **capability** ([`ResourceType::Capability`]) denials are currently
//! only recorded under permissive learning mode. Consumers must not
//! assume capability records are present under plain `learningMode`.

#![deny(missing_docs)]

pub mod analyze;
pub mod emit;
pub mod model;
pub mod summary;

pub use analyze::{AnalyzeError, DenialAnalyzer};
pub use emit::{write_document, DenialsDocument, DenialsOutputPointer};
pub use model::{AccessType, DedupKey, DeniedResource, ResourceType};
pub use summary::DenialSummary;
