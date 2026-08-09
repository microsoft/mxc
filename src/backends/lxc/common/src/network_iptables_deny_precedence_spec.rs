// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Black-box specification for deny-precedence and for the fail-closed
//! response to a block-list entry that resolves to no address.
//!
//! Written against the documented contract of the policy rule builder, not
//! against its body.
//!
//! Add `use super::*;` when the first test lands; an unused import fails the
//! `-D warnings` gate while this module is still empty.
