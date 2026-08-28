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
use crate::state_aware_request::SectionRoot;

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

/// Who will consume an exec's streams — the state-aware counterpart to
/// [`StdioMode`](crate::sandbox_process::StdioMode).
///
/// This is deliberately **not** `StdioMode`. That enum offers `Inherit`,
/// meaning the OS hands the child the executor's own stdin/stdout/stderr. No
/// state-aware backend can do that: the workload runs inside an isolation
/// session, inside a VM, or behind an SDK callback, so its streams always have
/// to be materialised on this side of the boundary and copied across. For this
/// contract `Inherit` is not merely ambiguous, it is unimplementable.
///
/// What a state-aware backend needs to know is who is on the other end, because
/// that decides the **topology** of the streams it returns:
///
/// * [`Executor`](Self::Executor) — the calling process relays onto its own
///   stdio. The backend may allocate a pseudo-console inside the sandbox when
///   that process is on a TTY; a pseudo-console has a single output stream, so
///   stderr is then merged into stdout and [`ExecHandle::stderr`] is null, which
///   is a correct result rather than a failure.
///
///   The dispatcher's relay forwards **no** input, so a stdin pipe whose write
///   end the backend retains would never be written or closed, and a workload
///   reading stdin would block forever. Return a null [`ExecHandle::stdin`]. A
///   backend that relays internally, as IsolationSession does through its
///   pseudo-console, forwards this process's stdin itself.
/// * [`Library`](Self::Library) — the caller drives the streams itself. The
///   backend must return separate raw stdout and stderr pipes, allocate no
///   pseudo-console, and leave the host's console untouched.
///
/// These distinguish who consumes the streams, not whether the caller is
/// in-process: a console application hosting an interactive sandboxed shell is
/// in-process and wants `Executor`.
///
/// The value is **authoritative**. A backend that probes the host to shape stdio
/// may consult that probe only under `Executor`, where the probing process is
/// the relay target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecConsumer {
    /// The calling process relays the streams to its own stdio.
    Executor,
    /// The caller drives the returned streams itself.
    Library,
}

/// The error a backend returns when it is asked to serve
/// [`ExecConsumer::Library`] and cannot.
///
/// Must be raised **before running anything**: the workload is arbitrary and may
/// not be idempotent, so a later refusal has already caused the side effects the
/// caller is told did not happen.
///
/// Shared so the refusal reads identically whichever backend raises it, and so
/// the check cannot drift into a per-backend spelling.
pub fn unsupported_library_exec(backend: &str) -> MxcError {
    MxcError::backend_error(format!(
        "the {backend} backend cannot return exec streams to the caller: it relays the sandbox's \
         output to this process's own stdout and stderr rather than handing back pipes. Run the \
         exec attached to this process's stdio instead, which requires this process's stdout and \
         stdin to be terminals. Nothing has been run."
    ))
}

/// How an exec finished — as distinct from *why a wait failed*.
///
/// A timeout is an **outcome**, not an error: the backend observed the deadline
/// and the workload is no longer running. Reserving `Err` for a genuine
/// inability to determine the exit is what lets a caller tell "it ran too long"
/// apart from "I could not find out what happened", which are different problems
/// with different responses.
///
/// # Which consumers can see `TimedOut`
///
/// Only [`ExecConsumer::Library`]. The executor path has nowhere to put it:
/// `ScriptResponse` carries an `exit_code` and no timeout field, so `wxc-exec`
/// reports a timed-out workload as the exit code its killed process produced.
/// A backend serving `ExecConsumer::Executor` therefore keeps returning
/// [`Exited`](Self::Exited) exactly as before — giving the CLI a timeout channel
/// is a change to its output contract, and belongs with that work rather than
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOutcome {
    /// The process exited with this code.
    Exited(i32),
    /// The request's timeout elapsed while the process was running, and the
    /// process is no longer running when this is reported.
    ///
    /// **Deadline spent, and the process is gone** — deliberately not "the
    /// backend killed it". A workload that overruns its deadline and then exits
    /// on its own a moment later has still missed the deadline, and reporting
    /// the exit code it happened to produce would hide that from a caller who
    /// asked for one. What killed it is not the caller's question; whether the
    /// deadline held is.
    ///
    /// The exit code is deliberately absent: on the killed path it would
    /// describe the kill rather than the workload, and on the late-exit path
    /// reporting it is exactly the confusion this variant exists to prevent.
    ///
    /// **How far "gone" reaches is the backend's to state.** Backends that own
    /// a process tree or a container kill the whole thing; a backend whose only
    /// primitive is the foreground process confirms that process and leaves
    /// descendants to whatever owns the sandbox's lifetime. Neither is implied
    /// here — see the backend's own documentation.
    TimedOut,
}

/// Streaming exec handle. The dispatcher relays `stdout` / `stderr` to the
/// executor's own streams, awaits exit via `waiter`, and calls `terminator` to
/// tear the exec down.
///
/// # Handle ownership
///
/// Ownership of `stdout` and `stderr` stays with the underlying process object:
/// consumers duplicate them and never close the originals.
///
/// `stdin` is **not consumed by the executor relay**, which forwards no input.
/// The streaming path hands it to an in-process caller, which duplicates it
/// rather than taking it. A pipe reaches EOF only once *every* write handle is
/// closed, so dropping that duplicate is not enough — `stdin_closer` closes the
/// backend's own end. A backend that exposes `stdin` must supply one.
///
/// # Reporting failure
///
/// Both closures are fallible, and for the same reason: the backend is the only
/// layer that knows, and a consumer that cannot be told has to guess.
///
/// - `waiter` returns an [`ExecOutcome`], so a timeout is reported as one rather
///   than disguised as the exit code of a killed process. `Err` means the exit
///   could not be determined — **not** that the process is gone.
/// - `terminator` returns `Result`, so a kill that the platform refused reaches
///   the caller instead of being swallowed. It reports whether the request was
///   *accepted*; a backend that can also confirm the process died should say so
///   in its own documentation, because this type cannot express the difference.
///
/// `stdin_closer` is infallible: it runs from `Drop`, where nothing can act on a
/// failure.
pub struct ExecHandle {
    pub stdout: PipeHandle,
    pub stderr: PipeHandle,
    pub stdin: PipeHandle,
    pub waiter: Box<dyn FnOnce() -> Result<ExecOutcome, MxcError> + Send>,
    pub terminator: Box<dyn FnOnce() -> Result<(), MxcError> + Send>,
    /// Closes the backend's own stdin write end. `None` when the backend
    /// exposes no stdin.
    pub stdin_closer: Option<Box<dyn FnOnce() + Send>>,
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
    /// Used by the dispatcher to navigate the per-phase config section in the
    /// request envelope (see [`SECTION_ROOT`](Self::SECTION_ROOT)) and to
    /// resolve provision-phase requests to the right backend implementation.
    const BACKEND_KEY: &'static str;

    /// Which envelope section holds this backend's per-phase config. Defaults
    /// to the permissive `experimental.<BACKEND_KEY>` block; a backend promoted
    /// to the stable surface overrides this to [`SectionRoot::Stable`] so its
    /// config is read from the top-level `<BACKEND_KEY>` section instead.
    const SECTION_ROOT: SectionRoot = SectionRoot::Experimental;

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
    ///
    /// `consumer` carries the **caller's** intent and is authoritative — see
    /// [`ExecConsumer`] for the full contract, including why this is not
    /// [`StdioMode`](crate::sandbox_process::StdioMode) and what each variant
    /// implies for the topology of the returned streams.
    ///
    /// # Honored by one backend so far
    ///
    /// The above states what an implementation must satisfy to be driven
    /// through the streaming entry points. It is not yet a description of every
    /// backend's behaviour:
    ///
    /// - **IsolationSession** honors both variants. Under `Library` it starts
    ///   the process without waiting, hands back its real pipe handles, a waiter
    ///   that blocks on exit and a terminator that kills, and does not touch the
    ///   host console. Under `Executor` it relays internally and returns null
    ///   handles.
    /// - **Windows Sandbox** and **WSLc** honor `Executor` only. They relay
    ///   internally and return null handles; a `Library` request is refused
    ///   without running the workload.
    ///
    /// Reaching any of this from an in-process caller additionally requires the
    /// experimental opt-in, which the state-aware entry points expose as an
    /// `experimental` parameter.
    ///
    /// # Backends that cannot serve `Library`
    ///
    /// A backend that relays the workload's output to the *host process's* own
    /// stdio, rather than returning streams, must refuse [`ExecConsumer::Library`]
    /// **before running anything** — see [`unsupported_library_exec`], which is
    /// the shared refusal. Returning a handle with no streams instead is a
    /// contract violation: by then the workload has run, so the refusal the
    /// caller eventually receives describes side effects that have already
    /// happened and output that has already gone somewhere it never asked for.
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<Self::ExecConfig>,
        consumer: ExecConsumer,
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
            _consumer: ExecConsumer,
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
            .exec(
                "stub:abcd1234",
                &ExecutionRequest::default(),
                None,
                ExecConsumer::Executor,
            )
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
    }
}
