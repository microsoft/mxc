// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exact version identities and lifecycle metadata for MXC configuration
//! contracts.
//!
//! This crate provides the dependency-light boundary used to select a
//! configuration contract from raw JSON source. It owns exact version matching,
//! contract lifecycle metadata, and version declaration probing.
//!
//! The version probe validates only the required `version` declaration. It does
//! not validate the remainder of the selected configuration contract.
//!
//! This crate must not depend on MXC runtime, execution-engine, or containment
//! backend crates. It is not yet consumed by the production configuration
//! parser; version-specific request types and parser dispatch will be added in
//! later phases.

mod registry;
mod version;

pub mod published;

pub use registry::{descriptor, supported_versions, ContractDescriptor, ContractStatus, CONTRACTS};
pub use version::{probe_version, ContractVersion, ContractVersion::*, VersionProbeError};
