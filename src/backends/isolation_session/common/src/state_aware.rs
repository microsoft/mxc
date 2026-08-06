// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for `IsolationSessionRunner`. Per-phase
//! methods + validation hooks. Each phase constructs a fresh
//! `IsolationSessionManager` because the OS service may idle-restart
//! between caller invocations.

use std::io::IsTerminal;

use serde::Serialize;

use wxc_common::models::{ExecutionRequest, IsolationSessionProvisionConfig};
use wxc_common::mxc_error::MxcError;
use wxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};

use windows::Win32::Foundation::HANDLE;

use super::error::map_lifecycle_error;
use super::manager::IsolationSessionManager;
use super::policy::{validate_post_provision_policy, validate_provision_policy};
use super::process_options::build_process_options;
use super::sandbox_id::{self, SandboxIdPayload};
use super::IsolationSessionRunner;

/// Provision-phase metadata surfaced to the caller: the OS-assigned agent
/// account name, the agent user's SID, and the shared ephemeral workspace
/// path. All are diagnostic/metadata — the addressing key remains the
/// `sandboxId` tail (the agent user name).
///
/// `pub` is required because the trait associated type slot
/// (`StatefulSandboxBackend::ProvisionMetadata`) reaches public callers via
/// the trait's `provision` method.
#[derive(Debug, Clone, Serialize)]
pub struct IsolationSessionProvisionMetadata {
    #[serde(rename = "agentUserName")]
    pub agent_user_name: String,
    #[serde(rename = "agentUserSid")]
    pub agent_user_sid: String,
    #[serde(rename = "ephemeralWorkspacePath")]
    pub ephemeral_workspace_path: String,
}

/// Parses a state-aware sandbox_id into its decoded payload, returning the
/// `agentUserName` — the opaque, OS-assigned account name minted at provision
/// and the addressing key for every post-provision phase. Format mismatches
/// surface as `MxcError::MalformedId`; see [`super::sandbox_id`] for the
/// format and its rationale.
fn extract_agent_user_name(sandbox_id: &str) -> Result<String, MxcError> {
    Ok(sandbox_id::decode(sandbox_id)?.agent_user_name)
}

impl StatefulSandboxBackend for IsolationSessionRunner {
    const ID_PREFIX: &'static str = sandbox_id::ID_PREFIX;
    const BACKEND_KEY: &'static str = "isolation_session";

    type ProvisionConfig = IsolationSessionProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = IsolationSessionProvisionMetadata;
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        _request: &ExecutionRequest,
        config: Option<IsolationSessionProvisionConfig>,
    ) -> Result<ProvisionResult<IsolationSessionProvisionMetadata>, MxcError> {
        let config = config.unwrap_or_default();
        let app_id = config.app_id;
        // The manager is discarded here — each post-provision phase builds its
        // own from the `sandboxId`. Taking it anyway keeps a single provisioning
        // path with `one_shot`, and proves the service instance that minted the
        // user is live rather than re-activating to find out.
        let (provisioned, _manager) =
            IsolationSessionManager::add_user().map_err(map_lifecycle_error)?;

        // `appId` rides inside the id so later phases recover it without the
        // caller re-supplying it. Nothing consumes it yet; it is carried for a
        // future OS contract. Metadata deliberately does not echo it — the
        // caller already has the value it supplied.
        let sandbox_id = sandbox_id::encode(&SandboxIdPayload::new(
            provisioned.agent_user_name.clone(),
            app_id,
        ))?;

        Ok(ProvisionResult {
            sandbox_id,
            metadata: Some(IsolationSessionProvisionMetadata {
                agent_user_name: provisioned.agent_user_name,
                agent_user_sid: provisioned.agent_user_sid,
                ephemeral_workspace_path: provisioned.ephemeral_workspace_path,
            }),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        let agent_user_name = extract_agent_user_name(sandbox_id)?;
        let manager =
            IsolationSessionManager::new(&agent_user_name).map_err(map_lifecycle_error)?;
        manager.start_session().map_err(map_lifecycle_error)?;
        Ok(StartResult { metadata: None })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let agent_user_name = extract_agent_user_name(sandbox_id)?;
        let manager =
            IsolationSessionManager::new(&agent_user_name).map_err(map_lifecycle_error)?;
        manager.stop_session().map_err(map_lifecycle_error)?;
        Ok(StopResult { metadata: None })
    }

    /// Removes the agent user.
    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let agent_user_name = extract_agent_user_name(sandbox_id)?;
        let manager =
            IsolationSessionManager::new(&agent_user_name).map_err(map_lifecycle_error)?;
        manager
            .deprovision_agent_user()
            .map_err(map_lifecycle_error)?;
        Ok(DeprovisionResult { metadata: None })
    }

    // Filesystem rw/ro/denied paths are rejected at every phase: the backend
    // has no host-folder-sharing primitive. Network policy is honesty-gated —
    // the backend cannot filter or deny the container network, so provision
    // requires the canonical unrestricted-network acknowledgment, and every
    // post-provision phase rejects a supplied network policy (the posture is
    // fixed at provision) while inheriting an absent one. Proxy policy is
    // rejected at every phase. Anything rejected produces a `policy_validation`
    // envelope rather than silent ignore.

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&IsolationSessionProvisionConfig>,
    ) -> Result<(), MxcError> {
        // Structural only — MXC carries `appId` for a future OS consumer and
        // does not judge what a valid application identity looks like.
        if let Some(app_id) = config.and_then(|c| c.app_id.as_deref()) {
            sandbox_id::validate_app_id(app_id)?;
        }
        validate_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        // Decode to reject a malformed id before any OS call.
        extract_agent_user_name(sandbox_id)?;
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    // Every id-consuming phase decodes in its validation hook, so a malformed
    // id is refused uniformly — and, critically, `--dry-run` (which
    // stops after validation) agrees with a real invocation about which ids are
    // acceptable. Validating on only some phases would let a dry run report
    // success for a request the real call then rejects.

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_agent_user_name(sandbox_id)?;
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_agent_user_name(sandbox_id)?;
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_agent_user_name(sandbox_id)?;
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    /// Reuses `IsolationSessionManager::create_process` — the same path the
    /// one-shot runner uses. Output streams to wxc-exec's stdout/stderr via
    /// internal relay threads while the call is in flight; the call returns
    /// once the process has exited and the relays have drained. The
    /// resulting `ExecHandle` carries sentinel pipe handles plus a waiter
    /// closure that yields the already-captured exit code, so the
    /// dispatcher's `relay_exec_to_stdio` is a thin call-through.
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<ExecHandle, MxcError> {
        let agent_user_name = extract_agent_user_name(sandbox_id)?;
        let manager =
            IsolationSessionManager::new(&agent_user_name).map_err(map_lifecycle_error)?;

        let interactive = std::io::stdout().is_terminal();
        let options = build_process_options(request, interactive);

        let exit_code = manager
            .create_process(&options)
            .map_err(map_lifecycle_error)?;

        // The output relay completed inside `create_process`. The dispatcher
        // sees zero pipe handles, skips its own relay setup, and gets the
        // exit code from the waiter closure.
        let null = HANDLE(std::ptr::null_mut());
        Ok(ExecHandle {
            stdout: null,
            stderr: null,
            stdin: null,
            waiter: Box::new(move || Ok(exit_code)),
            terminator: Box::new(|| {}),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainerPolicy, NetworkPolicy};
    use wxc_common::mxc_error::MxcErrorCode;

    // ====== Wire-format constants ======

    // `BACKEND_KEY` names the `experimental.<key>.<phase>` slot the
    // dispatcher reads via `deserialize_config`. A typo here would
    // silently swallow every per-phase config (the field would still
    // deserialize from the containment slot via models.rs's serde
    // rename — only the experimental block would go missing).
    #[test]
    fn backend_key_matches_wire_format() {
        assert_eq!(
            <IsolationSessionRunner as StatefulSandboxBackend>::BACKEND_KEY,
            "isolation_session"
        );
    }

    // `ID_PREFIX` is the `<prefix>:<agentUserName>` tag the dispatcher
    // matches against in `backend_from_prefix`. Indirectly covered by
    // every `extract_agent_user_name_*` test that uses an `"iso:..."`
    // literal; pinned explicitly here so the dependence is visible.
    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <IsolationSessionRunner as StatefulSandboxBackend>::ID_PREFIX,
            "iso"
        );
    }

    // Provision metadata must serialize to exactly the three camelCase wire
    // keys the SDK's `IsolationSessionProvisionMetadata` reads. A missing or
    // misnamed field would silently strip provision data from the result.
    #[test]
    fn provision_metadata_serializes_all_fields() {
        let meta = IsolationSessionProvisionMetadata {
            agent_user_name: "agent-1".to_string(),
            agent_user_sid: "S-1-5-21-1001".to_string(),
            ephemeral_workspace_path: "C:\\ProgramData\\ws\\agent-1".to_string(),
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["agentUserName"], "agent-1");
        assert_eq!(v["agentUserSid"], "S-1-5-21-1001");
        assert_eq!(v["ephemeralWorkspacePath"], "C:\\ProgramData\\ws\\agent-1");
        assert_eq!(
            v.as_object().unwrap().len(),
            3,
            "unexpected fields in provision metadata: {v}"
        );
    }

    // ====== Wire-model / backend config parity ======

    // The generated JSON schema (`schemas/dev/`) and the SDK wire types
    // (`sdk/node/src/generated/wire.ts`) are both emitted from
    // `wxc_common::wire::IsolationSession`, while the phases that actually
    // accept a config are the associated types on the impl above. On the
    // state-aware path the wire model is never constructed — the dispatcher
    // deserializes raw JSON straight into those associated types — so nothing
    // couples the two at compile time. The tests below pin that contract from
    // both directions: the key set the wire model advertises, that the `()`
    // phases reject a payload, and that the phases which do take one still
    // accept the payload the wire model describes.

    #[test]
    fn wire_model_nests_config_only_for_phases_that_take_one() {
        // Field-by-field construction is deliberate: adding a per-phase field
        // to the wire struct breaks this test's compilation, forcing a
        // decision about whether the backend honors it.
        let wire = wxc_common::wire::IsolationSession { provision: None };
        let value = serde_json::to_value(&wire).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["provision"],
            "wire model nests a per-phase config for a phase the backend takes none for"
        );
    }

    #[test]
    fn phases_without_a_config_reject_a_payload() {
        type StartConfig = <IsolationSessionRunner as StatefulSandboxBackend>::StartConfig;
        type StopConfig = <IsolationSessionRunner as StatefulSandboxBackend>::StopConfig;
        type DeprovisionConfig =
            <IsolationSessionRunner as StatefulSandboxBackend>::DeprovisionConfig;
        type ExecConfig = <IsolationSessionRunner as StatefulSandboxBackend>::ExecConfig;

        // These are `()`, which deserializes only from null, so any object in
        // the slot is a hard error at dispatch. `start` belongs to this group:
        // it takes no per-phase config at all.
        let payload = serde_json::json!({ "anything": true });
        assert!(
            serde_json::from_value::<StartConfig>(payload.clone()).is_err(),
            "start accepted a config payload"
        );
        assert!(
            serde_json::from_value::<StopConfig>(payload.clone()).is_err(),
            "stop accepted a config payload"
        );
        assert!(
            serde_json::from_value::<DeprovisionConfig>(payload.clone()).is_err(),
            "deprovision accepted a config payload"
        );
        assert!(
            serde_json::from_value::<ExecConfig>(payload).is_err(),
            "exec accepted a config payload"
        );
    }

    #[test]
    fn phases_with_a_config_accept_the_wire_payload() {
        type ProvisionConfig = <IsolationSessionRunner as StatefulSandboxBackend>::ProvisionConfig;

        // Derive the payload from the wire type instead of a JSON literal: the
        // wire model is only the schema source on this path, so a serde rename
        // on either side would go unnoticed. The config type is
        // `#[serde(default)]` with no `deny_unknown_fields`, so a renamed key
        // does not error — it silently drops the value.
        let provision_phase = wxc_common::wire::IsolationSessionProvisionPhase {
            app_id: Some("Contoso.App_8wekyb3d8bbwe".to_string()),
        };
        let provision: ProvisionConfig =
            serde_json::from_value(serde_json::to_value(&provision_phase).unwrap()).unwrap();
        assert_eq!(
            provision.app_id.as_deref(),
            Some("Contoso.App_8wekyb3d8bbwe"),
            "provision dropped the wire appId (serde rename drift?)"
        );
    }

    fn request_with_filesystem_policy() -> ExecutionRequest {
        ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\workspace".into()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn request_with_canonical_network() -> ExecutionRequest {
        // The one network form the provision phase accepts (see policy.rs):
        // unrestricted outbound + inbound, no host rules, no proxy.
        ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                allow_local_network: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // ====== sandbox_id parsing ======

    /// A structurally valid sandbox id for the phase-routing tests below.
    /// Those tests care about policy validation, not the id, so they need a
    /// well-formed one rather than a literal. The codec's own behaviour is
    /// covered exhaustively in `sandbox_id`.
    fn valid_sandbox_id() -> String {
        sandbox_id::encode(&SandboxIdPayload::new("wxc-abcd1234", None)).unwrap()
    }

    #[test]
    fn extract_agent_user_name_recovers_the_encoded_agent_user_name() {
        let id = sandbox_id::encode(&SandboxIdPayload::new("wxc-abcd1234", None)).unwrap();
        assert_eq!(extract_agent_user_name(&id).unwrap(), "wxc-abcd1234");
    }

    #[test]
    fn extract_agent_user_name_recovers_a_name_containing_a_colon() {
        let id = sandbox_id::encode(&SandboxIdPayload::new("has:a:colon", None)).unwrap();
        assert_eq!(extract_agent_user_name(&id).unwrap(), "has:a:colon");
    }

    #[test]
    fn extract_agent_user_name_rejects_other_prefix() {
        let err = extract_agent_user_name("wsb:abc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_agent_user_name_rejects_missing_colon() {
        let err = extract_agent_user_name("no-colon").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_agent_user_name_rejects_empty_payload() {
        let err = extract_agent_user_name("iso:").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn every_id_consuming_hook_rejects_a_malformed_id() {
        // All four hooks must agree, so `--dry-run` (which stops after
        // validation) cannot report success for an id the real call rejects.
        let runner = IsolationSessionRunner::new();
        let req = request_with_canonical_network();
        let undecodable = "iso:not-a-valid-payload";
        let cases: Vec<(&str, Result<(), MxcError>)> = vec![
            ("start", runner.validate_start(undecodable, &req, None)),
            ("exec", runner.validate_exec(undecodable, &req, None)),
            ("stop", runner.validate_stop(undecodable, &req, None)),
            (
                "deprovision",
                runner.validate_deprovision(undecodable, &req, None),
            ),
        ];
        for (phase, result) in cases {
            let err = result.expect_err(&format!("{phase} must reject an undecodable id"));
            assert_eq!(err.code, MxcErrorCode::MalformedId, "phase {phase}");
        }
    }

    #[test]
    fn every_id_consuming_hook_accepts_a_well_formed_id() {
        let runner = IsolationSessionRunner::new();
        let req = request_with_canonical_network();
        let id = valid_sandbox_id();
        runner.validate_start(&id, &req, None).unwrap();
        runner.validate_exec(&id, &req, None).unwrap();
        runner.validate_stop(&id, &req, None).unwrap();
        runner.validate_deprovision(&id, &req, None).unwrap();
    }

    // ====== validation-hook phase routing ======

    #[test]
    fn validate_provision_hook_rejects_filesystem_policy() {
        let runner = IsolationSessionRunner::new();
        let req = request_with_filesystem_policy();
        let err = runner.validate_provision(&req, None).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_provision_hook_rejects_denied_paths() {
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner.validate_provision(&req, None).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_post_provision_hooks_reject_filesystem_policy() {
        let runner = IsolationSessionRunner::new();
        let req = request_with_filesystem_policy();

        let s = runner
            .validate_start(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(s.code, MxcErrorCode::PolicyValidation);

        let e = runner
            .validate_exec(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(e.code, MxcErrorCode::PolicyValidation);

        let st = runner
            .validate_stop(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(st.code, MxcErrorCode::PolicyValidation);

        let d = runner
            .validate_deprovision(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(d.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_provision_hook_accepts_canonical_network() {
        let runner = IsolationSessionRunner::new();
        let req = request_with_canonical_network();
        runner.validate_provision(&req, None).unwrap();
    }

    #[test]
    fn validate_post_provision_hooks_accept_absent_network() {
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest::default();

        runner
            .validate_start(&valid_sandbox_id(), &req, None)
            .unwrap();
        runner
            .validate_exec(&valid_sandbox_id(), &req, None)
            .unwrap();
        runner
            .validate_stop(&valid_sandbox_id(), &req, None)
            .unwrap();
        runner
            .validate_deprovision(&valid_sandbox_id(), &req, None)
            .unwrap();
    }

    #[test]
    fn validate_post_provision_hooks_reject_specified_network() {
        // A network policy supplied on a post-provision phase is fixed at
        // provision and refused (mapped to policy_validation at the boundary).
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                network_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let s = runner
            .validate_start(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(s.code, MxcErrorCode::PolicyValidation);

        let e = runner
            .validate_exec(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(e.code, MxcErrorCode::PolicyValidation);

        let st = runner
            .validate_stop(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(st.code, MxcErrorCode::PolicyValidation);

        let d = runner
            .validate_deprovision(&valid_sandbox_id(), &req, None)
            .unwrap_err();
        assert_eq!(d.code, MxcErrorCode::PolicyValidation);
    }

    // ====== UI policy is refused on every phase ======

    #[test]
    fn every_validate_hook_rejects_supplied_ui() {
        // The backend has no UI-restriction primitive at any phase, so all five
        // hooks refuse a supplied `ui` rather than accepting and dropping it.
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ..request_with_canonical_network().policy
            },
            ..Default::default()
        };

        let p = runner.validate_provision(&req, None).unwrap_err();
        assert_eq!(p.code, MxcErrorCode::PolicyValidation);
        assert!(p.message.contains("UI policy"), "got {}", p.message);

        for (label, err) in [
            (
                "start",
                runner.validate_start(&valid_sandbox_id(), &req, None),
            ),
            (
                "exec",
                runner.validate_exec(&valid_sandbox_id(), &req, None),
            ),
            (
                "stop",
                runner.validate_stop(&valid_sandbox_id(), &req, None),
            ),
            (
                "deprovision",
                runner.validate_deprovision(&valid_sandbox_id(), &req, None),
            ),
        ] {
            let err = err.unwrap_err();
            assert_eq!(err.code, MxcErrorCode::PolicyValidation, "phase {label}");
            assert!(
                err.message.contains("UI policy"),
                "phase {label}: got {}",
                err.message
            );
        }
    }

    #[test]
    fn validate_hooks_accept_absent_ui() {
        // Guard against over-rejection.
        let runner = IsolationSessionRunner::new();
        runner
            .validate_provision(&request_with_canonical_network(), None)
            .unwrap();
        let req = ExecutionRequest::default();
        runner
            .validate_start(&valid_sandbox_id(), &req, None)
            .unwrap();
        runner
            .validate_exec(&valid_sandbox_id(), &req, None)
            .unwrap();
        runner
            .validate_stop(&valid_sandbox_id(), &req, None)
            .unwrap();
        runner
            .validate_deprovision(&valid_sandbox_id(), &req, None)
            .unwrap();
    }

    // ====== appId validation at the provision hook ======

    fn provision_config_with_app_id(app_id: &str) -> IsolationSessionProvisionConfig {
        IsolationSessionProvisionConfig {
            app_id: Some(app_id.to_string()),
        }
    }

    #[test]
    fn validate_provision_accepts_an_absent_app_id() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionProvisionConfig::default();
        runner
            .validate_provision(&request_with_canonical_network(), Some(&cfg))
            .unwrap();
    }

    #[test]
    fn validate_provision_accepts_a_well_formed_app_id() {
        let runner = IsolationSessionRunner::new();
        let cfg = provision_config_with_app_id("Contoso.App_8wekyb3d8bbwe");
        runner
            .validate_provision(&request_with_canonical_network(), Some(&cfg))
            .unwrap();
    }

    #[test]
    fn validate_provision_accepts_an_empty_app_id() {
        // Empty is a legal, distinct value — MXC must not reject it, because a
        // future OS API may assign it meaning.
        let runner = IsolationSessionRunner::new();
        let cfg = provision_config_with_app_id("");
        runner
            .validate_provision(&request_with_canonical_network(), Some(&cfg))
            .unwrap();
    }

    #[test]
    fn validate_provision_rejects_an_oversized_app_id() {
        let runner = IsolationSessionRunner::new();
        let cfg = provision_config_with_app_id(&"a".repeat(257));
        let err = runner
            .validate_provision(&request_with_canonical_network(), Some(&cfg))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert!(err.message.contains("appId"), "got {}", err.message);
    }

    #[test]
    fn validate_provision_rejects_a_control_character_in_app_id() {
        let runner = IsolationSessionRunner::new();
        let cfg = provision_config_with_app_id("has\u{0}nul");
        let err = runner
            .validate_provision(&request_with_canonical_network(), Some(&cfg))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_provision_checks_app_id_before_touching_the_os() {
        // The hook runs before `provision`, so a bad appId must never reach a
        // lifecycle call. Asserting the policy code (not a backend error) is
        // what pins that ordering.
        let runner = IsolationSessionRunner::new();
        let cfg = provision_config_with_app_id("bad\u{1}");
        let err = runner
            .validate_provision(&request_with_canonical_network(), Some(&cfg))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_accepts_a_well_formed_id() {
        let runner = IsolationSessionRunner::new();
        runner
            .validate_start(&valid_sandbox_id(), &ExecutionRequest::default(), None)
            .unwrap();
    }
}
