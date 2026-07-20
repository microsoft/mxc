// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware dispatcher: routes a parsed state-aware request to the right
//! backend's `StatefulSandboxBackend` impl, runs the per-phase typed flow, and
//! produces either a JSON response envelope (non-exec phases or dispatch
//! failure) or an exit code (exec phase, which streams its output live).
//!
//! `run_state_aware` is the entry point invoked from `wxc-exec`'s main flow.
//! It resolves the backend (by `containment` for provision, by `sandbox_id`
//! prefix for non-provision phases) and either dispatches to the registered
//! state-aware backend or surfaces `unsupported_phase` for backends without a
//! state-aware impl.
//!
//! `dispatch_state_aware<B>` is the per-backend phase router, generic over the
//! `StatefulSandboxBackend` impl. It validates, calls the right phase method,
//! and wraps the typed result into a wire-format response envelope.

use serde::Serialize;
use serde_json::Value;

use crate::id::parse_sandbox_id_prefix;
use crate::models::ContainmentBackend;
use crate::mxc_error::{MxcError, ResponseEnvelope};
use crate::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};
use crate::state_aware_request::{ParsedStateAwareRequest, Phase};
use crate::validator::validate_exec_common;

/// Outcome of dispatching one state-aware request. Distinguishes the two
/// success modes: non-exec phases produce a JSON envelope; exec phases stream
/// their output live and exit with the script's exit code.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// JSON envelope to write to stdout (non-exec phases or dispatch failure).
    Envelope(Value),
    /// Exec phase completed; the executor process should exit with this code.
    /// Stdout already carried the script's output; no JSON envelope is emitted.
    ExecCompleted { exit_code: i32 },
}

/// Fallback dispatch for backends whose state-aware impl isn't reachable
/// from `wxc_common` (e.g. it lives in a backend crate that depends on
/// `wxc_common`, so a direct call here would create a cycle). Callers in
/// `wxc-exec` resolve known backends and invoke `dispatch_state_aware`
/// directly; anything they don't handle falls through to this function,
/// which surfaces `unsupported_phase` for the resolved backend.
pub fn run_state_aware(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<DispatchOutcome, MxcError> {
    let _ = dry_run;

    let backend = resolve_backend(&parsed)?;
    Err(MxcError::unsupported_phase(format!(
        "backend {:?} does not implement state-aware lifecycle",
        backend
    )))
}

/// Per-backend phase router. The `run_state_aware` arm for a participating
/// backend constructs `B` and delegates here.
pub fn dispatch_state_aware<B: StatefulSandboxBackend>(
    backend: &mut B,
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<DispatchOutcome, MxcError> {
    let request = parsed.request.clone();
    let phase = parsed.phase;
    match phase {
        Phase::Provision => {
            let config =
                parsed.deserialize_config::<B::ProvisionConfig>(B::BACKEND_KEY, "provision")?;
            backend.validate_provision(&request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.provision(&request, config)?;
            Ok(DispatchOutcome::Envelope(provision_envelope(result)?))
        }
        Phase::Start => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config = parsed.deserialize_config::<B::StartConfig>(B::BACKEND_KEY, "start")?;
            backend.validate_start(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.start(&sandbox_id, &request, config)?;
            Ok(DispatchOutcome::Envelope(metadata_envelope(result)?))
        }
        Phase::Exec => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config = parsed.deserialize_config::<B::ExecConfig>(B::BACKEND_KEY, "exec")?;
            validate_exec_common(&request)?;
            backend.validate_exec(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let handle = backend.exec(&sandbox_id, &request, config)?;
            let exit_code = relay_exec_to_stdio(handle)?;
            Ok(DispatchOutcome::ExecCompleted { exit_code })
        }
        Phase::Stop => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config = parsed.deserialize_config::<B::StopConfig>(B::BACKEND_KEY, "stop")?;
            backend.validate_stop(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.stop(&sandbox_id, &request, config)?;
            Ok(DispatchOutcome::Envelope(metadata_envelope(result)?))
        }
        Phase::Deprovision => {
            let sandbox_id = parsed.sandbox_id_required()?.to_string();
            let config =
                parsed.deserialize_config::<B::DeprovisionConfig>(B::BACKEND_KEY, "deprovision")?;
            backend.validate_deprovision(&sandbox_id, &request, config.as_ref())?;
            if dry_run {
                return Ok(DispatchOutcome::Envelope(empty_result_envelope()));
            }
            let result = backend.deprovision(&sandbox_id, &request, config)?;
            Ok(DispatchOutcome::Envelope(metadata_envelope(result)?))
        }
    }
}

/// Resolves the target backend: from `containment` for provision, from the
/// `sandbox_id` prefix for non-provision phases.
pub fn resolve_backend(parsed: &ParsedStateAwareRequest) -> Result<ContainmentBackend, MxcError> {
    if parsed.phase == Phase::Provision {
        return parsed.containment.clone().ok_or_else(|| {
            MxcError::malformed_request("provision phase requires a containment field")
        });
    }
    let sandbox_id = parsed.sandbox_id_required()?;
    let prefix = parse_sandbox_id_prefix(sandbox_id)?;
    backend_from_prefix(prefix)
}

/// Maps a state-aware sandbox-id prefix to its `ContainmentBackend`.
/// Subsequent state-aware backends register their prefix here.
fn backend_from_prefix(prefix: &str) -> Result<ContainmentBackend, MxcError> {
    match prefix {
        "iso" => Ok(ContainmentBackend::IsolationSession),
        "wsb" => Ok(ContainmentBackend::WindowsSandbox),
        // Future state-aware backends extend this list.
        other => Err(MxcError::unsupported_containment(format!(
            "no state-aware backend registered for prefix {:?}",
            other
        ))),
    }
}

/// Streams the running process's pipes to executor stdio and waits for exit.
///
/// Backends that perform their own internal relay (e.g. IsolationSession,
/// which reuses the one-shot path's relay threads) hand back zero pipe
/// handles plus a waiter closure that yields the already-captured exit code
/// — this function is a thin call-through in that case. When a backend
/// surfaces live pipe handles, this function will gain `process_util`-driven
/// relay threads and a waiter join; that path lands when the first such
/// backend appears.
fn relay_exec_to_stdio(handle: ExecHandle) -> Result<i32, MxcError> {
    (handle.waiter)()
}

// ---------- Wire-format envelope construction ----------

/// `{ "result": { "sandboxId": "...", "metadata": {...}? } }`
#[derive(Serialize)]
struct ProvisionWireBody<M: Serialize> {
    #[serde(rename = "sandboxId")]
    sandbox_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<M>,
}

/// `{ "metadata": {...}? }` — used by start / stop / deprovision phases.
#[derive(Serialize)]
struct MetadataWireBody<M: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<M>,
}

fn provision_envelope<M: Serialize>(r: ProvisionResult<M>) -> Result<Value, MxcError> {
    let body = ProvisionWireBody {
        sandbox_id: r.sandbox_id,
        metadata: r.metadata,
    };
    let envelope = ResponseEnvelope::Result(body);
    serde_json::to_value(&envelope).map_err(|e| {
        MxcError::backend_error(format!("provision envelope serialisation failed: {}", e))
    })
}

fn metadata_envelope<R: HasMetadata>(r: R) -> Result<Value, MxcError> {
    let body = MetadataWireBody {
        metadata: r.into_metadata(),
    };
    let envelope = ResponseEnvelope::Result(body);
    serde_json::to_value(&envelope).map_err(|e| {
        MxcError::backend_error(format!("metadata envelope serialisation failed: {}", e))
    })
}

fn empty_result_envelope() -> Value {
    serde_json::json!({"result": {}})
}

// Lets `metadata_envelope` accept any of the per-phase result types without a
// long manual match.
trait HasMetadata {
    type Metadata: Serialize;
    fn into_metadata(self) -> Option<Self::Metadata>;
}

impl<M: Serialize> HasMetadata for StartResult<M> {
    type Metadata = M;
    fn into_metadata(self) -> Option<M> {
        self.metadata
    }
}
impl<M: Serialize> HasMetadata for StopResult<M> {
    type Metadata = M;
    fn into_metadata(self) -> Option<M> {
        self.metadata
    }
}
impl<M: Serialize> HasMetadata for DeprovisionResult<M> {
    type Metadata = M;
    fn into_metadata(self) -> Option<M> {
        self.metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ExecutionRequest;
    use crate::mxc_error::MxcErrorCode;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::cell::Cell;

    /// Fully-configurable backend stub for dispatcher tests.
    /// Each phase is wired to either succeed (the default — empty result with
    /// no metadata) or fail with a typed `MxcError` (set via the `*_error`
    /// fields). Calls to each phase method are counted on `*_calls` so tests
    /// can assert the routing landed on the right method.
    struct StubBackend {
        provision_calls: Cell<u32>,
        start_calls: Cell<u32>,
        exec_calls: Cell<u32>,
        stop_calls: Cell<u32>,
        deprovision_calls: Cell<u32>,
        validate_provision_calls: Cell<u32>,
        validate_start_calls: Cell<u32>,
        validate_exec_calls: Cell<u32>,
        validate_stop_calls: Cell<u32>,
        validate_deprovision_calls: Cell<u32>,
        provision_error: Option<MxcError>,
        validate_provision_error: Option<MxcError>,
    }

    impl StubBackend {
        fn new() -> Self {
            Self {
                provision_calls: Cell::new(0),
                start_calls: Cell::new(0),
                exec_calls: Cell::new(0),
                stop_calls: Cell::new(0),
                deprovision_calls: Cell::new(0),
                validate_provision_calls: Cell::new(0),
                validate_start_calls: Cell::new(0),
                validate_exec_calls: Cell::new(0),
                validate_stop_calls: Cell::new(0),
                validate_deprovision_calls: Cell::new(0),
                provision_error: None,
                validate_provision_error: None,
            }
        }
    }

    impl StatefulSandboxBackend for StubBackend {
        const ID_PREFIX: &'static str = "stubd";
        const BACKEND_KEY: &'static str = "stub_dispatch";
        type ProvisionConfig = ();
        type StartConfig = ();
        type ExecConfig = ();
        type StopConfig = ();
        type DeprovisionConfig = ();
        type ProvisionMetadata = ();
        type StartMetadata = ();
        type StopMetadata = ();
        type DeprovisionMetadata = ();

        fn provision(
            &mut self,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<ProvisionResult<()>, MxcError> {
            self.provision_calls.set(self.provision_calls.get() + 1);
            if let Some(e) = self.provision_error.clone() {
                return Err(e);
            }
            Ok(ProvisionResult {
                sandbox_id: format!("{}:fixed-token", Self::ID_PREFIX),
                metadata: None,
            })
        }
        fn start(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<StartResult<()>, MxcError> {
            self.start_calls.set(self.start_calls.get() + 1);
            Ok(StartResult { metadata: None })
        }
        fn exec(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<ExecHandle, MxcError> {
            self.exec_calls.set(self.exec_calls.get() + 1);
            Err(MxcError::backend_error("stub exec not wired"))
        }
        fn stop(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<StopResult<()>, MxcError> {
            self.stop_calls.set(self.stop_calls.get() + 1);
            Ok(StopResult { metadata: None })
        }
        fn deprovision(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<()>,
        ) -> Result<DeprovisionResult<()>, MxcError> {
            self.deprovision_calls.set(self.deprovision_calls.get() + 1);
            Ok(DeprovisionResult { metadata: None })
        }

        fn validate_provision(
            &self,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_provision_calls
                .set(self.validate_provision_calls.get() + 1);
            if let Some(e) = self.validate_provision_error.clone() {
                return Err(e);
            }
            Ok(())
        }
        fn validate_start(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_start_calls
                .set(self.validate_start_calls.get() + 1);
            Ok(())
        }
        fn validate_exec(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_exec_calls
                .set(self.validate_exec_calls.get() + 1);
            Ok(())
        }
        fn validate_stop(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_stop_calls
                .set(self.validate_stop_calls.get() + 1);
            Ok(())
        }
        fn validate_deprovision(
            &self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            _config: Option<&()>,
        ) -> Result<(), MxcError> {
            self.validate_deprovision_calls
                .set(self.validate_deprovision_calls.get() + 1);
            Ok(())
        }
    }

    /// Backend that exercises typed-config deserialisation via
    /// `ParsedStateAwareRequest::deserialize_config`. The dispatcher's start
    /// phase must extract `experimental.<BACKEND_KEY>.start` into this type
    /// and pass it through to `start()`.
    #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
    struct TypedStartConfig {
        configuration_id: String,
    }

    struct TypedConfigStubBackend {
        captured_start_config: Cell<Option<TypedStartConfig>>,
    }

    impl TypedConfigStubBackend {
        fn new() -> Self {
            Self {
                captured_start_config: Cell::new(None),
            }
        }
    }

    impl StatefulSandboxBackend for TypedConfigStubBackend {
        const ID_PREFIX: &'static str = "typed";
        const BACKEND_KEY: &'static str = "typed_stub";
        type ProvisionConfig = ();
        type StartConfig = TypedStartConfig;
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
            Err(MxcError::backend_error("typed stub exec not wired"))
        }

        fn start(
            &mut self,
            _sandbox_id: &str,
            _request: &ExecutionRequest,
            config: Option<TypedStartConfig>,
        ) -> Result<StartResult<()>, MxcError> {
            self.captured_start_config.set(config);
            Ok(StartResult { metadata: None })
        }
    }

    fn parsed(
        phase: Phase,
        sandbox_id: Option<&str>,
        exp: Option<Value>,
    ) -> ParsedStateAwareRequest {
        ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase,
            containment: Some(ContainmentBackend::IsolationSession),
            sandbox_id: sandbox_id.map(String::from),
            correlation_vector: None,
            experimental_raw: exp,
        }
    }

    fn assert_envelope(outcome: DispatchOutcome) -> Value {
        match outcome {
            DispatchOutcome::Envelope(v) => v,
            DispatchOutcome::ExecCompleted { exit_code } => {
                panic!(
                    "expected envelope, got ExecCompleted {{ exit_code: {} }}",
                    exit_code
                )
            }
        }
    }

    #[test]
    fn dispatch_provision_calls_validate_then_provision() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), false).unwrap(),
        );
        assert_eq!(b.validate_provision_calls.get(), 1);
        assert_eq!(b.provision_calls.get(), 1);
        assert_eq!(env, json!({"result": {"sandboxId": "stubd:fixed-token"}}));
    }

    #[test]
    fn dispatch_provision_dry_run_skips_provision_call_but_runs_validate() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), true).unwrap(),
        );
        assert_eq!(b.validate_provision_calls.get(), 1);
        assert_eq!(b.provision_calls.get(), 0);
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_provision_returns_validate_error_without_calling_provision() {
        let mut b = StubBackend::new();
        b.validate_provision_error = Some(MxcError::policy_validation("nope"));
        let err =
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert_eq!(b.validate_provision_calls.get(), 1);
        assert_eq!(b.provision_calls.get(), 0);
    }

    #[test]
    fn dispatch_provision_propagates_provision_error() {
        let mut b = StubBackend::new();
        b.provision_error = Some(MxcError::backend_error("boom"));
        let err =
            dispatch_state_aware(&mut b, parsed(Phase::Provision, None, None), false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
        assert_eq!(b.provision_calls.get(), 1);
    }

    #[test]
    fn dispatch_start_requires_sandbox_id() {
        let mut b = StubBackend::new();
        let err =
            dispatch_state_aware(&mut b, parsed(Phase::Start, None, None), false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert_eq!(b.start_calls.get(), 0);
    }

    #[test]
    fn dispatch_start_calls_validate_then_start() {
        let mut b = StubBackend::new();
        let env = assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Start, Some("stubd:abc"), None), false)
                .unwrap(),
        );
        assert_eq!(b.validate_start_calls.get(), 1);
        assert_eq!(b.start_calls.get(), 1);
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_exec_validate_common_rejects_empty_command_line() {
        let mut b = StubBackend::new();
        let err = dispatch_state_aware(&mut b, parsed(Phase::Exec, Some("stubd:abc"), None), false)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert_eq!(b.validate_exec_calls.get(), 0);
        assert_eq!(b.exec_calls.get(), 0);
    }

    #[test]
    fn dispatch_exec_dry_run_skips_exec_call() {
        let mut b = StubBackend::new();
        let mut p = parsed(Phase::Exec, Some("stubd:abc"), None);
        p.request.script_code = "echo".into();
        let env = assert_envelope(dispatch_state_aware(&mut b, p, true).unwrap());
        assert_eq!(b.validate_exec_calls.get(), 1);
        assert_eq!(b.exec_calls.get(), 0);
        assert_eq!(env, json!({"result": {}}));
    }

    #[test]
    fn dispatch_stop_routes_correctly() {
        let mut b = StubBackend::new();
        assert_envelope(
            dispatch_state_aware(&mut b, parsed(Phase::Stop, Some("stubd:abc"), None), false)
                .unwrap(),
        );
        assert_eq!(b.validate_stop_calls.get(), 1);
        assert_eq!(b.stop_calls.get(), 1);
    }

    #[test]
    fn dispatch_deprovision_routes_correctly() {
        let mut b = StubBackend::new();
        assert_envelope(
            dispatch_state_aware(
                &mut b,
                parsed(Phase::Deprovision, Some("stubd:abc"), None),
                false,
            )
            .unwrap(),
        );
        assert_eq!(b.validate_deprovision_calls.get(), 1);
        assert_eq!(b.deprovision_calls.get(), 1);
    }

    #[test]
    fn typed_config_stub_receives_typed_start_config() {
        let mut b = TypedConfigStubBackend::new();
        let exp = json!({
            "typed_stub": { "start": {"configuration_id": "small"} }
        });
        let p = parsed(Phase::Start, Some("typed:abc"), Some(exp));
        assert_envelope(dispatch_state_aware(&mut b, p, false).unwrap());
        let captured = b.captured_start_config.into_inner();
        assert_eq!(
            captured,
            Some(TypedStartConfig {
                configuration_id: "small".into()
            })
        );
    }

    #[test]
    fn typed_config_stub_receives_none_when_experimental_block_absent() {
        let mut b = TypedConfigStubBackend::new();
        let p = parsed(Phase::Start, Some("typed:abc"), None);
        assert_envelope(dispatch_state_aware(&mut b, p, false).unwrap());
        assert_eq!(b.captured_start_config.into_inner(), None);
    }

    #[test]
    fn typed_config_stub_surfaces_shape_mismatch_as_malformed_request() {
        let mut b = TypedConfigStubBackend::new();
        // Wrong shape — missing required `configuration_id`.
        let exp = json!({
            "typed_stub": { "start": {"wrong_field": 1} }
        });
        let p = parsed(Phase::Start, Some("typed:abc"), Some(exp));
        let err = dispatch_state_aware(&mut b, p, false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    // ---------- run_state_aware / resolve_backend ----------

    #[test]
    fn run_state_aware_provision_for_recognized_backend_returns_unsupported_phase() {
        // No state-aware impls registered yet — every recognized backend is
        // unsupported. Smoke-test scenario #2 from decision 6.
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Provision,
            containment: Some(ContainmentBackend::Wslc),
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw: None,
        };
        let err = run_state_aware(p, false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::UnsupportedPhase);
    }

    #[test]
    fn run_state_aware_provision_without_containment_is_malformed() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Provision,
            containment: None,
            sandbox_id: None,
            correlation_vector: None,
            experimental_raw: None,
        };
        let err = run_state_aware(p, false).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn resolve_backend_for_iso_prefix_returns_isolation_session() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("iso:wxc-abcd1234".into()),
            correlation_vector: None,
            experimental_raw: None,
        };
        assert_eq!(
            resolve_backend(&p).unwrap(),
            ContainmentBackend::IsolationSession
        );
    }

    #[test]
    fn resolve_backend_for_wsb_prefix_returns_windows_sandbox() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("wsb:deadbeef".into()),
            correlation_vector: None,
            experimental_raw: None,
        };
        assert_eq!(
            resolve_backend(&p).unwrap(),
            ContainmentBackend::WindowsSandbox
        );
    }

    #[test]
    fn resolve_backend_for_unknown_prefix_returns_unsupported_containment() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("unknownxyz:abc".into()),
            correlation_vector: None,
            experimental_raw: None,
        };
        let err = resolve_backend(&p).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
    }

    #[test]
    fn resolve_backend_for_malformed_id_surfaces_malformed_id() {
        let p = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("no-colon".into()),
            correlation_vector: None,
            experimental_raw: None,
        };
        let err = resolve_backend(&p).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }
}
