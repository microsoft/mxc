// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession backend — executes scripts in an isolated Windows
//! session via the in-proc `Windows.AI.IsolationSession.Preview` `IsoSessionOps`
//! API. `IsolationSessionRunner` is the only externally-reachable type;
//! the granular lifecycle wrapper (`IsolationSessionManager`) and helpers
//! are module-private.
//!
//! Trait impls split by lifecycle shape:
//! - `one_shot`: `ScriptRunner` — provision → start → exec → stop →
//!   deprovision in a single process.
//! - `state_aware`: `StatefulSandboxBackend` — per-phase methods called
//!   across multiple `wxc-exec` invocations by an external orchestrator.

#[cfg(target_os = "windows")]
mod app_id;
#[cfg(target_os = "windows")]
mod console_mode;
#[cfg(target_os = "windows")]
mod console_relay;
#[cfg(target_os = "windows")]
mod error;
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
mod state_aware;

#[cfg(target_os = "windows")]
pub use manager::is_service_available;

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
