// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-platform data shapes for the captureDenials/learning-mode
//! pipeline.
//!
//! This crate intentionally has no OS dependencies. It is consumed
//! by:
//!
//! - **`learning_mode_windows`**: extracts denials from the
//!   platform-native source, converts into the `DeniedResource`
//!   shape declared here, and writes them to the denial channel.
//! - **`learning_mode_linux`** / **`learning_mode_macos`** (stubs
//!   today): will do the same with platform-native sources when
//!   implemented.
//! - **`learning_mode`** (the core orchestrator): re-exports these
//!   types so consumers depend on one crate.
//! - The SDK's TypeScript NDJSON parser, whose `DeniedResource`
//!   type is an ergonomic superset of this wire shape: it parses the
//!   same fields, but adds a `kind` discriminator and anticipates
//!   resource-type values (e.g. `registry`) that this minimal model
//!   currently folds into `Other`.

pub mod model;

pub use model::{AccessType, DeniedResource, ResourceType};
