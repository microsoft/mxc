// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware backend trait and supporting types.
//!
//! Backends opt into state-aware dispatch by implementing
//! `StatefulSandboxBackend` alongside (or instead of) `ScriptRunner`. The trait
//! exposes the five lifecycle phases — provision, start, exec, stop,
//! deprovision — plus per-phase validation hooks.
//!
//! Methods take `&ExecutionRequest` (the same one-shot domain model used by every
//! existing backend) plus the typed `sandbox_id` for non-provision phases and
//! an optional backend-specific config object. Cross-cutting policy fields
//! flow through `request.policy`; per-exec process info flows through
//! `request.script_code` / `working_directory` / `script_timeout` / `env`.
//!
//! Most phase methods have default no-op bodies — only `exec` is strictly
//! required. The default `provision` body mints `<ID_PREFIX>:<token>` for
//! stateless-underneath backends; backends with native session work override
//! it.

use serde::{de::DeserializeOwned, Serialize};

use crate::id::mint_random_token;
use crate::models::ExecutionRequest;
use crate::mxc_error::MxcError;

/// Platform pipe-handle wrapper used by `ExecHandle`. On Windows this is a
/// kernel `HANDLE`; on Unix-like targets it is a raw file descriptor.
#[cfg(target_os = "windows")]
pub type PipeHandle = windows::Win32::Foundation::HANDLE;

#[cfg(not(target_os = "windows"))]
pub type PipeHandle = i32;

/// A null / invalid [`PipeHandle`] — the sentinel a backend returns for a
/// stream it does not expose (e.g. IsolationSession, which relays internally).
#[cfg(target_os = "windows")]
pub fn null_pipe_handle() -> PipeHandle {
    windows::Win32::Foundation::HANDLE(std::ptr::null_mut())
}

/// A null / invalid [`PipeHandle`] — see the Windows variant.
#[cfg(not(target_os = "windows"))]
pub fn null_pipe_handle() -> PipeHandle {
    -1
}

/// Provision-phase result. Carries the freshly-minted `sandbox_id` and
/// optional backend-typed metadata.
#[derive(Debug)]
pub struct ProvisionResult<M> {
    pub sandbox_id: String,
    pub metadata: Option<M>,
}

/// Start-phase result. Backends with no useful metadata return `None`.
#[derive(Debug)]
pub struct StartResult<M> {
    pub metadata: Option<M>,
}

/// Stop-phase result.
#[derive(Debug)]
pub struct StopResult<M> {
    pub metadata: Option<M>,
}

/// Deprovision-phase result.
#[derive(Debug)]
pub struct DeprovisionResult<M> {
    pub metadata: Option<M>,
}

/// Streaming exec handle. The dispatcher relays `stdout` / `stderr` to the
/// executor's own streams, forwards executor stdin into `stdin`, awaits exit
/// via `waiter`, and calls `terminator` on cancellation signals. Pipe-handle
/// ownership stays with the underlying process object; the relay does not
/// close them.
pub struct ExecHandle {
    pub stdout: PipeHandle,
    pub stderr: PipeHandle,
    pub stdin: PipeHandle,
    pub waiter: Box<dyn FnOnce() -> Result<i32, MxcError> + Send>,
    pub terminator: Box<dyn FnOnce() + Send>,
}

// Manual Debug impl: the boxed closures can't derive Debug. Pipe handles are
// printed; the closures render as opaque markers.
impl std::fmt::Debug for ExecHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecHandle")
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("stdin", &self.stdin)
            .field("waiter", &"<fn>")
            .field("terminator", &"<fn>")
            .finish()
    }
}

/// State-aware backend trait. Backends declare their `ID_PREFIX` and the
/// per-phase typed config / metadata associated types, then override only
/// the phase methods where they have substantive work.
pub trait StatefulSandboxBackend {
    /// Backend identifier prefix. Forms the leading `<tag>:` segment of every
    /// `sandbox_id` minted by the default `provision` body, and is the routing
    /// key the dispatcher uses to resolve non-provision calls to this backend.
    const ID_PREFIX: &'static str;

    /// Wire-format `containment` value for this backend, matching the SDK's
    /// `StateAwareContainmentBackend` member name (e.g. `"isolation_session"`).
    /// Used by the dispatcher to navigate
    /// `experimental.<BACKEND_KEY>.<phase>` in the request envelope and to
    /// resolve provision-phase requests to the right backend implementation.
    const BACKEND_KEY: &'static str;

    type ProvisionConfig: DeserializeOwned;
    type StartConfig: DeserializeOwned;
    type ExecConfig: DeserializeOwned;
    type StopConfig: DeserializeOwned;
    type DeprovisionConfig: DeserializeOwned;
    type ProvisionMetadata: Serialize;
    type StartMetadata: Serialize;
    type StopMetadata: Serialize;
    type DeprovisionMetadata: Serialize;

    /// Optional. Default mints `<ID_PREFIX>:<random-token>` and returns no
    /// metadata. Override when the backend has native provision work.
    fn provision(
        &mut self,
        _request: &ExecutionRequest,
        _config: Option<Self::ProvisionConfig>,
    ) -> Result<ProvisionResult<Self::ProvisionMetadata>, MxcError> {
        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, mint_random_token()),
            metadata: None,
        })
    }

    /// Optional. Default returns success with no metadata.
    fn start(
        &mut self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StartConfig>,
    ) -> Result<StartResult<Self::StartMetadata>, MxcError> {
        Ok(StartResult { metadata: None })
    }

    /// Required. Executes the workload and returns a streaming handle.
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::ExecConfig>,
    ) -> Result<ExecHandle, MxcError>;

    /// Optional. Default returns success with no metadata.
    fn stop(
        &mut self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::StopConfig>,
    ) -> Result<StopResult<Self::StopMetadata>, MxcError> {
        Ok(StopResult { metadata: None })
    }

    /// Optional. Default returns success with no metadata.
    fn deprovision(
        &mut self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<Self::DeprovisionConfig>,
    ) -> Result<DeprovisionResult<Self::DeprovisionMetadata>, MxcError> {
        Ok(DeprovisionResult { metadata: None })
    }

    /// Per-phase validation hooks. The dispatcher calls these before the
    /// corresponding phase method. Default: accept all requests. Override to
    /// add backend-specific checks (config field semantics, policy honor
    /// enforcement, id format checks beyond the prefix).
    fn validate_provision(
        &self,
        _request: &ExecutionRequest,
        _config: Option<&Self::ProvisionConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_start(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StartConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_exec(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::ExecConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_stop(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::StopConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }

    fn validate_deprovision(
        &self,
        _sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&Self::DeprovisionConfig>,
    ) -> Result<(), MxcError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_error::MxcErrorCode;

    /// Minimal trait fixture exercising every default body. Uses `()` for all
    /// associated types; `exec` is the only required method — wired to a
    /// recognisable error so accidental calls show up in test output rather
    /// than panicking.
    struct StubBackend;

    impl StatefulSandboxBackend for StubBackend {
        const ID_PREFIX: &'static str = "stub";
        const BACKEND_KEY: &'static str = "stub_backend";
        type ProvisionConfig = ();
        type StartConfig = ();
        type ExecConfig = ();
        type StopConfig = ();
        type DeprovisionConfig = ();
        type ProvisionMetadata = ();
        type StartMetadata = ();
        type StopMetadata = ();
        type DeprovisionMetadata = ();

        fn exec(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<ExecHandle, MxcError> {
            Err(MxcError::backend_error("StubBackend::exec not implemented"))
        }
    }

    #[test]
    fn default_provision_mints_id_with_prefix_and_token() {
        let mut b = StubBackend;
        let r = b.provision(&ExecutionRequest::default(), None).unwrap();
        // Expected shape: "stub:" followed by 8 lowercase hex chars.
        assert!(r.sandbox_id.starts_with("stub:"), "got {:?}", r.sandbox_id);
        let token = &r.sandbox_id["stub:".len()..];
        assert_eq!(
            token.len(),
            8,
            "token portion should be 8 chars: {:?}",
            token
        );
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "token portion should be lowercase hex: {:?}",
            token,
        );
        assert!(r.metadata.is_none());
    }

    #[test]
    fn default_provision_produces_distinct_ids() {
        let mut b = StubBackend;
        let a = b.provision(&ExecutionRequest::default(), None).unwrap();
        let c = b.provision(&ExecutionRequest::default(), None).unwrap();
        assert_ne!(a.sandbox_id, c.sandbox_id);
    }

    #[test]
    fn default_start_returns_no_metadata() {
        let mut b = StubBackend;
        let r = b
            .start("stub:abcd1234", &ExecutionRequest::default(), None)
            .unwrap();
        assert!(r.metadata.is_none());
    }

    #[test]
    fn default_stop_returns_no_metadata() {
        let mut b = StubBackend;
        let r = b
            .stop("stub:abcd1234", &ExecutionRequest::default(), None)
            .unwrap();
        assert!(r.metadata.is_none());
    }

    #[test]
    fn default_deprovision_returns_no_metadata() {
        let mut b = StubBackend;
        let r = b
            .deprovision("stub:abcd1234", &ExecutionRequest::default(), None)
            .unwrap();
        assert!(r.metadata.is_none());
    }

    #[test]
    fn default_validate_hooks_all_pass() {
        let b = StubBackend;
        let req = ExecutionRequest::default();
        b.validate_provision(&req, None).unwrap();
        b.validate_start("stub:abcd1234", &req, None).unwrap();
        b.validate_exec("stub:abcd1234", &req, None).unwrap();
        b.validate_stop("stub:abcd1234", &req, None).unwrap();
        b.validate_deprovision("stub:abcd1234", &req, None).unwrap();
    }

    #[test]
    fn required_exec_returns_error_on_stub() {
        // Confirms `exec` is wired and reachable; the stub returns a typed
        // error rather than panicking so a misrouted dispatcher test would
        // surface this code rather than aborting the test binary.
        let mut b = StubBackend;
        let err = b
            .exec("stub:abcd1234", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
    }
}
