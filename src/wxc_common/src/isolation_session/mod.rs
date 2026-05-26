// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

mod console_mode;
mod console_relay;
mod error;
mod folder_sharing;
mod manager;
mod one_shot;
mod pipe_relay;
mod policy;
mod process_options;
mod protected_paths_filter;
mod state_aware;

/// Stateless marker type. Trait impls live in `one_shot` (`ScriptRunner`)
/// and `state_aware` (`StatefulSandboxBackend`).
pub struct IsolationSessionRunner;

impl IsolationSessionRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IsolationSessionRunner {
    fn default() -> Self {
        Self::new()
    }
}
