// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared error strings surfaced by the Windows AppContainer and
//! BaseContainer runners when a policy field is accepted by the schema
//! but not yet honored by the runtime. Centralising the wording here
//! keeps both runners in lockstep and avoids duplicating the same
//! string literals.

pub(crate) const DENIED_PATHS_NOT_SUPPORTED_MSG: &str =
    "filesystem.deniedPaths is not yet supported on Windows. Paths are denied by \
     default unless granted via readwritePaths or readonlyPaths. Remove deniedPaths, \
     or narrow readwritePaths/readonlyPaths to exclude the path you wanted to deny.";

pub(crate) const HOST_LISTS_NOT_SUPPORTED_MSG: &str =
    "network.allowedHosts / network.blockedHosts are not yet supported on Windows. \
     Remove the host list(s) and rely on defaultNetworkPolicy (allow / deny) or a \
     proxy instead.";
