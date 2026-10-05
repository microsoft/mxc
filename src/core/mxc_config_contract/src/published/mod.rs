// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Immutable published configuration contracts.
//!
//! Once published, contract modules must not be modified. Runtime adaptation
//! belongs outside this module.

/// The published `0.9.0-alpha` configuration contract.
pub mod v0_9_0_alpha;
/// The published `1.0.0` configuration contract.
pub mod v1_0_0;
