// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for `IsolationSessionRunner`. Per-phase
//! methods + validation hooks. Each phase constructs a fresh
//! `IsolationSessionManager` because the OS service may idle-restart
//! between caller invocations.

use std::io::IsTerminal;

use serde::Serialize;

use wxc_common::models::{
    ExecutionRequest, IsolationSessionProvisionConfig, IsolationSessionStartConfig,
    IsolationSessionUser,
};
use wxc_common::mxc_error::MxcError;
use wxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};

use windows::Win32::Foundation::HANDLE;

use super::error::map_lifecycle_error;
use super::manager::IsolationSessionManager;
use super::policy::{
    validate_isolation_session_user, validate_post_provision_policy, validate_provision_policy,
};
use super::process_options::build_process_options;
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

/// Parses the `iso:<agentUserName>` form of a state-aware sandbox_id and
/// returns the inner `agentUserName` segment — the opaque, OS-assigned
/// account name minted at provision. Surfaces format mismatches as
/// `MxcError::MalformedId`.
fn extract_agent_user_name(sandbox_id: &str) -> Result<&str, MxcError> {
    let prefix = <IsolationSessionRunner as StatefulSandboxBackend>::ID_PREFIX;
    match sandbox_id.split_once(':') {
        Some((p, rest)) if p == prefix && !rest.is_empty() => Ok(rest),
        _ => Err(MxcError::malformed_id(format!(
            "expected {}:<agentUserName>, got {:?}",
            prefix, sandbox_id
        ))),
    }
}

/// Normalizes an optional Entra `user` bundle into the exact
/// `(entraAccountName, wamToken)` pair handed to the OS.
///
/// A local agent is signalled to the OS by empty strings, so an absent bundle
/// maps to `("", "")`.
///
/// The UPN is **trimmed**, matching `validate_isolation_session_user`, which
/// trims before its shape check — validating a trimmed value and then
/// transmitting an untrimmed one would let `" alice@contoso.com "` pass
/// validation and reach the OS with its surrounding spaces intact.
///
/// The WAM token is passed **verbatim**: it is an opaque bearer credential and
/// trimming could corrupt it.
fn os_credentials(user: Option<&IsolationSessionUser>) -> (String, &str) {
    match user {
        Some(u) => (u.upn.trim().to_string(), u.wam_token.as_str()),
        None => (String::new(), ""),
    }
}

impl StatefulSandboxBackend for IsolationSessionRunner {
    const ID_PREFIX: &'static str = "iso";
    const BACKEND_KEY: &'static str = "isolation_session";

    type ProvisionConfig = IsolationSessionProvisionConfig;
    /// `experimental.isolation_session.start` carries the Entra WAM token
    /// again for a cloud-agent sandbox; the one-shot surface takes no
    /// backend configuration.
    type StartConfig = IsolationSessionStartConfig;
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
        let user = config.and_then(|c| c.user);
        // Local agent users pass empty strings; Entra agents pass the UPN +
        // WAM token. Either way the OS assigns an opaque agent account name,
        // which becomes the sandboxId tail — start cannot infer Entra-ness
        // from it, so the token is re-supplied at start.
        let (entra_account, wam_token) = os_credentials(user.as_ref());
        let provisioned = IsolationSessionManager::add_user(&entra_account, wam_token)
            .map_err(map_lifecycle_error)?;

        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, provisioned.agent_user_name),
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
        config: Option<IsolationSessionStartConfig>,
    ) -> Result<StartResult<()>, MxcError> {
        let agent_user_name = extract_agent_user_name(sandbox_id)?;
        let manager = IsolationSessionManager::new(agent_user_name).map_err(map_lifecycle_error)?;
        // The sandboxId tail is opaque, so Entra-ness is carried by the
        // start config's user bundle: present → re-supply the WAM token;
        // absent → local session (empty token). The OS validates the token
        // against the agent user it assigned at provision.
        let cfg = config.unwrap_or_default();
        let (_entra_account, wam_token) = os_credentials(cfg.user.as_ref());
        manager
            .start_session(wam_token)
            .map_err(map_lifecycle_error)?;
        Ok(StartResult { metadata: None })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let agent_user_name = extract_agent_user_name(sandbox_id)?;
        let manager = IsolationSessionManager::new(agent_user_name).map_err(map_lifecycle_error)?;
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
        let manager = IsolationSessionManager::new(agent_user_name).map_err(map_lifecycle_error)?;
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
        if let Some(user) = config.and_then(|c| c.user.as_ref()) {
            validate_isolation_session_user(user)?;
        }
        validate_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        config: Option<&IsolationSessionStartConfig>,
    ) -> Result<(), MxcError> {
        // The sandboxId tail is opaque, so start no longer cross-checks it
        // against the user bundle. A user bundle (Entra) is optional at
        // start; when present it must be well-formed. The OS validates the
        // token against the agent user it assigned at provision.
        extract_agent_user_name(sandbox_id)?;
        if let Some(user) = config.and_then(|c| c.user.as_ref()) {
            validate_isolation_session_user(user)?;
        }
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_exec(
        &self,
        _sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_stop(
        &self,
        _sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_deprovision(
        &self,
        _sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
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
        let manager = IsolationSessionManager::new(agent_user_name).map_err(map_lifecycle_error)?;

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
    use wxc_common::models::{ContainerPolicy, IsolationSessionUser, NetworkPolicy};
    use wxc_common::mxc_error::MxcErrorCode;

    fn well_formed_user() -> IsolationSessionUser {
        IsolationSessionUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: "tok".to_string(),
        }
    }

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
        let wire = wxc_common::wire::IsolationSession {
            provision: None,
            start: None,
        };
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
            ["provision", "start"],
            "wire model nests a per-phase config for a phase the backend takes none for"
        );
    }

    #[test]
    fn phases_without_a_config_reject_a_payload() {
        type StopConfig = <IsolationSessionRunner as StatefulSandboxBackend>::StopConfig;
        type DeprovisionConfig =
            <IsolationSessionRunner as StatefulSandboxBackend>::DeprovisionConfig;
        type ExecConfig = <IsolationSessionRunner as StatefulSandboxBackend>::ExecConfig;

        // These are `()`, which deserializes only from null, so any object in
        // the slot is a hard error at dispatch.
        let payload = serde_json::json!({ "user": { "upn": "a@b.com", "wamToken": "t" } });
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
        type StartConfig = <IsolationSessionRunner as StatefulSandboxBackend>::StartConfig;

        // Derive each payload from its own wire type instead of a JSON
        // literal: the wire model is only the schema source on this path, so a
        // serde rename on either side would go unnoticed. Both config types
        // are `#[serde(default)]` with no `deny_unknown_fields`, so a renamed
        // key does not error — it drops the bundle and provisions a local
        // sandbox for a caller who asked for an Entra one. The phases have
        // separate wire types, so both directions are pinned separately.
        let wire_user = || wxc_common::wire::IsolationUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: "tok".to_string(),
        };

        let provision_phase = wxc_common::wire::IsolationSessionProvisionPhase {
            user: Some(wire_user()),
        };
        let provision: ProvisionConfig =
            serde_json::from_value(serde_json::to_value(&provision_phase).unwrap()).unwrap();
        let u = provision
            .user
            .expect("provision dropped the wire user bundle");
        assert_eq!(u.upn, "alice@contoso.com");
        assert_eq!(u.wam_token, "tok");

        let start_phase = wxc_common::wire::IsolationSessionStartPhase {
            user: Some(wire_user()),
        };
        let start: StartConfig =
            serde_json::from_value(serde_json::to_value(&start_phase).unwrap()).unwrap();
        let u = start.user.expect("start dropped the wire user bundle");
        assert_eq!(u.upn, "alice@contoso.com");
        assert_eq!(u.wam_token, "tok");
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

    #[test]
    fn extract_agent_user_name_unwraps_iso_prefix() {
        assert_eq!(
            extract_agent_user_name("iso:wxc-abcd1234").unwrap(),
            "wxc-abcd1234"
        );
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

        let s = runner.validate_start("iso:abc", &req, None).unwrap_err();
        assert_eq!(s.code, MxcErrorCode::PolicyValidation);

        let e = runner.validate_exec("iso:abc", &req, None).unwrap_err();
        assert_eq!(e.code, MxcErrorCode::PolicyValidation);

        let st = runner.validate_stop("iso:abc", &req, None).unwrap_err();
        assert_eq!(st.code, MxcErrorCode::PolicyValidation);

        let d = runner
            .validate_deprovision("iso:abc", &req, None)
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

        runner.validate_start("iso:abc", &req, None).unwrap();
        runner.validate_exec("iso:abc", &req, None).unwrap();
        runner.validate_stop("iso:abc", &req, None).unwrap();
        runner.validate_deprovision("iso:abc", &req, None).unwrap();
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

        let s = runner.validate_start("iso:abc", &req, None).unwrap_err();
        assert_eq!(s.code, MxcErrorCode::PolicyValidation);

        let e = runner.validate_exec("iso:abc", &req, None).unwrap_err();
        assert_eq!(e.code, MxcErrorCode::PolicyValidation);

        let st = runner.validate_stop("iso:abc", &req, None).unwrap_err();
        assert_eq!(st.code, MxcErrorCode::PolicyValidation);

        let d = runner
            .validate_deprovision("iso:abc", &req, None)
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
            ("start", runner.validate_start("iso:abc", &req, None)),
            ("exec", runner.validate_exec("iso:abc", &req, None)),
            ("stop", runner.validate_stop("iso:abc", &req, None)),
            (
                "deprovision",
                runner.validate_deprovision("iso:abc", &req, None),
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
        runner.validate_start("iso:abc", &req, None).unwrap();
        runner.validate_exec("iso:abc", &req, None).unwrap();
        runner.validate_stop("iso:abc", &req, None).unwrap();
        runner.validate_deprovision("iso:abc", &req, None).unwrap();
    }

    // ====== Entra user bundle validation ======

    #[test]
    fn validate_provision_accepts_well_formed_user() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionProvisionConfig {
            user: Some(well_formed_user()),
        };
        runner
            .validate_provision(&request_with_canonical_network(), Some(&cfg))
            .unwrap();
    }

    #[test]
    fn validate_provision_rejects_malformed_user() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionProvisionConfig {
            user: Some(IsolationSessionUser {
                upn: "no-at-sign".to_string(),
                wam_token: "tok".to_string(),
            }),
        };
        let err = runner
            .validate_provision(&ExecutionRequest::default(), Some(&cfg))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_accepts_well_formed_user() {
        // A user bundle is now allowed at start regardless of the opaque
        // sandboxId; it only needs to be well-formed.
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionStartConfig {
            user: Some(well_formed_user()),
        };
        runner
            .validate_start("iso:wxc-abcd1234", &ExecutionRequest::default(), Some(&cfg))
            .unwrap();
    }

    #[test]
    fn validate_start_rejects_malformed_user() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionStartConfig {
            user: Some(IsolationSessionUser {
                upn: "no-at-sign".to_string(),
                wam_token: "tok".to_string(),
            }),
        };
        let err = runner
            .validate_start("iso:wxc-abcd1234", &ExecutionRequest::default(), Some(&cfg))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_local_sandbox_without_user_accepts() {
        let runner = IsolationSessionRunner::new();
        runner
            .validate_start("iso:wxc-abcd1234", &ExecutionRequest::default(), None)
            .unwrap();
    }

    // ====== os_credentials: what actually reaches the OS ======

    #[test]
    fn os_credentials_absent_bundle_is_the_local_agent_pair() {
        let (account, token) = os_credentials(None);
        assert_eq!(account, "");
        assert_eq!(token, "");
    }

    #[test]
    fn os_credentials_trims_the_upn() {
        // validate_isolation_session_user trims before its shape check, so a
        // padded UPN passes validation. Transmitting the untrimmed value would
        // send the OS something the caller was never told was acceptable.
        let user = IsolationSessionUser {
            upn: "  alice@contoso.com\t".to_string(),
            wam_token: "tok".to_string(),
        };
        let (account, _) = os_credentials(Some(&user));
        assert_eq!(account, "alice@contoso.com");
    }

    #[test]
    fn os_credentials_passes_the_wam_token_verbatim() {
        // The token is an opaque bearer credential; trimming could corrupt it.
        let user = IsolationSessionUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: "  tok-with-edges  ".to_string(),
        };
        let (_, token) = os_credentials(Some(&user));
        assert_eq!(token, "  tok-with-edges  ");
    }

    #[test]
    fn os_credentials_leaves_an_interior_space_in_the_upn_alone() {
        // Only the edges are trimmed — the value is otherwise verbatim.
        let user = IsolationSessionUser {
            upn: " a b@contoso.com ".to_string(),
            wam_token: "tok".to_string(),
        };
        let (account, _) = os_credentials(Some(&user));
        assert_eq!(account, "a b@contoso.com");
    }
}
