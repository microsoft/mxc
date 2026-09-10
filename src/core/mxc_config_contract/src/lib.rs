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
//! Contract values may also be constructed by trusted typed producers such as
//! the version-specific Rust policy builders. `OptionalField::present` marks an
//! explicitly present member, while `Default` represents omission; constructed
//! requests still pass through the version adapter and shared semantic
//! validation.
//!
//! This crate must not depend on MXC runtime, execution-engine, or containment
//! backend crates. The production configuration parser reuses the development
//! contract's narrow phase probe when preparing a trailing CLI command.
//! Version-specific request types and exact parser dispatch remain
//! non-authoritative until the later cutover phase.

mod registry;
mod version;

pub mod dev;
pub mod published;

pub use registry::{descriptor, supported_versions, ContractDescriptor, ContractStatus, CONTRACTS};
pub use version::{probe_version, ContractVersion, ContractVersion::*, VersionProbeError};
