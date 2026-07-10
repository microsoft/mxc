// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compatibility re-export for callers that used the original resolver module.

pub use crate::path_specificity::{effective_intent, resolve_mount_order, resolve_path_plan};
pub use crate::path_specificity::{FsIntent, ResolvedMount};
