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
//!    written to the canonical JSON output that host applications read to
//!    regenerate policy. A deterministic Data Loop sibling contains bounded,
//!    sensitive-value-redacted signatures for excluded decoder outcomes.
//!
//! This crate is the cross-platform hinge between stages 2 and 3: it
//! defines the public [`DeniedResource`] model, the [`DenialSummary`]
//! terminator, the [`DenialsDocument`] and [`DataLoopDocument`] output shapes,
//! and the [`DenialAnalyzer`] decode trait. It carries no OS-specific code so
//! the wire format never encodes a platform assumption.
//!
//! ## Mode caveat
//!
//! What a capture contains depends on the active OS learning mode.
//! File/path, UI, and capability denials may be recorded under both
//! `learningMode` (`block`) and `permissiveLearningMode` (`allow`). The
//! concrete ETW event shape differs by mode, and records without a decoded
//! resource identifier are omitted rather than emitted as empty resources.

#![deny(missing_docs)]

pub mod analyze;
pub mod data_loop;
pub mod emit;
pub mod model;
pub mod paired_output;
pub mod summary;

pub use analyze::{AnalysisResult, AnalyzeError, DenialAnalyzer, ProcessLifetime};
pub use data_loop::{
    data_loop_sibling_path, write_data_loop_document, DataLoopAggregate, DataLoopDocument,
    DataLoopDocumentSummary, DataLoopExclusionReason, DataLoopProvider, DataLoopSignature,
    DataLoopSummary, MAX_DATA_LOOP_GROUPS, MAX_DATA_LOOP_SIGNATURE_BYTES,
};
pub use emit::{write_document, DenialsDocument, DenialsOutputPointer};
pub use model::{AccessType, DedupKey, DeniedResource, ResourceType};
pub use paired_output::{write_paired_output_files, ExistingOutputPolicy};
pub use summary::DenialSummary;
