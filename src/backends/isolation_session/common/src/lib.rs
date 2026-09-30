// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "windows")]

//! IsolationSession backend — executes scripts in an isolated Windows
//! session via the in-proc `Windows.AI.IsolationSession.Preview` `IsoSessionOps`
//! API. `IsolationSessionRunner` is the only externally-reachable type;
//! the granular lifecycle wrapper (`IsolationSessionManager`) and helpers
//! are module-private.
//!
//! Trait impls split by lifecycle shape:
//! - `one_shot`: `ScriptRunner` — provision → start → exec → stop →
//!   deprovision in a single process, relaying the workload onto this
//!   process's stdio.
//! - `sandbox`: `SandboxBackend` — the same one-shot lifecycle for an
//!   in-process caller, handing back live pipes and reclaiming the session
//!   when the exec reaches a terminal state.
//! - `state_aware`: `StatefulSandboxBackend` — per-phase methods called
//!   across multiple `wxc-exec` invocations by an external orchestrator.

pub mod availability;
mod console_mode;
mod console_relay;
mod error;
mod manager;
mod one_shot;
mod owned_thread;
mod pipe_relay;
mod policy;
mod process_options;
mod sandbox;
pub use sandbox::{spawn_one_shot, OneShotSpawnFailure};
mod sandbox_id;
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
