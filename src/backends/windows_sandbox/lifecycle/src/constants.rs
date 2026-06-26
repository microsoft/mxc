// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-cutting string constants for the Windows Sandbox lifecycle crate,
//! centralised so a rename touches one place instead of a scattered set of
//! string literals.
//!
//! Constants that are intrinsically tied to a single RAII guard or codec
//! (e.g. the named-mutex names in [`crate::control_plane`], which live next to
//! the `HostVmLock` / `TransitionLock` that own them, or the frame-kind bytes
//! in [`crate::ipc_exec`]) are deliberately left co-located with their owner —
//! they are named, documented, and used in exactly one place. This module is
//! for literals that would otherwise be duplicated or appear bare at a call
//! site far from any natural home.

/// Image name of the detached host-side state-aware daemon binary, spawned by
/// the `start` phase (resolved as a sibling of the running `wxc-exec`). Single
/// source of truth so a rename here cannot silently desync from the binary the
/// build/packaging scripts actually produce.
pub const DAEMON_BINARY_NAME: &str = "wxc-windows-sandbox-daemon.exe";
