// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ScriptResponse carries a Vec<DeniedResource>; Result<_, ScriptResponse>
// trips clippy::result_large_err. The response is moved once into the
// dispatch path and serialised, so boxing the Err variant doesn't buy
// anything here.
#![allow(clippy::result_large_err)]

//! IsolationSession backend — executes scripts in an isolated Windows
//! session via the in-proc `Windows.AI.IsolationSession` `IsoSessionOps`
//! API. `IsolationSessionRunner` is the only externally-reachable type;
//! the granular lifecycle wrapper (`IsolationSessionManager`) and helpers
//! are module-private.
//!
//! Trait impls split by lifecycle shape:
//! - `one_shot`: `ScriptRunner` — register → provision → start → exec →
//!   stop → deprovision in a single process.
//! - `state_aware`: `StatefulSandboxBackend` — per-phase methods called
//!   across multiple `wxc-exec` invocations by an external orchestrator.

#[cfg(target_os = "windows")]
mod console_mode;
#[cfg(target_os = "windows")]
mod console_relay;
#[cfg(target_os = "windows")]
mod error;
#[cfg(target_os = "windows")]
mod folder_sharing;
#[cfg(target_os = "windows")]
mod manager;
#[cfg(target_os = "windows")]
mod one_shot;
#[cfg(target_os = "windows")]
mod pipe_relay;
#[cfg(target_os = "windows")]
mod policy;
#[cfg(target_os = "windows")]
mod process_options;
#[cfg(target_os = "windows")]
mod protected_paths_filter;
#[cfg(target_os = "windows")]
mod state_aware;

/// Stateless marker type. Trait impls live in `one_shot` (`ScriptRunner`)
/// and `state_aware` (`StatefulSandboxBackend`).
#[cfg(target_os = "windows")]
pub struct IsolationSessionRunner;

#[cfg(target_os = "windows")]
impl IsolationSessionRunner {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "windows")]
impl Default for IsolationSessionRunner {
    fn default() -> Self {
        Self::new()
    }
}
