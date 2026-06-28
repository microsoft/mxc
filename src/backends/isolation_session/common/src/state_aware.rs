// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for `IsolationSessionRunner`. Per-phase
//! methods + validation hooks. Each phase constructs a fresh
//! `IsolationSessionManager` because the OS service may idle-restart
//! between caller invocations.

use std::io::IsTerminal;

use serde::Serialize;

use wxc_common::models::{
    ExecutionRequest, IsolationSessionConfig, IsolationSessionProvisionConfig,
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

/// Provision-phase metadata. Carries the OS-assigned agent account name
/// for diagnostics; the SID is omitted (can be added when a caller needs it).
///
/// `pub` is required because the trait associated type slot
/// (`StatefulSandboxBackend::ProvisionMetadata`) reaches public callers via
/// the trait's `provision` method.
#[derive(Debug, Clone, Serialize)]
pub struct IsolationSessionProvisionMetadata {
    #[serde(rename = "agentUserName")]
    pub agent_user_name: String,
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

impl StatefulSandboxBackend for IsolationSessionRunner {
    const ID_PREFIX: &'static str = "iso";
    const BACKEND_KEY: &'static str = "isolation_session";

    type ProvisionConfig = IsolationSessionProvisionConfig;
    /// `experimental.isolation_session.start` mirrors the one-shot
    /// `experimental.isolation_session` shape — same `IsolationSessionConfig`
    /// type, same wire keys.
    type StartConfig = IsolationSessionConfig;
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
        let (entra_account, wam_token) = match &user {
            Some(u) => (u.upn.as_str(), u.wam_token.as_str()),
            None => ("", ""),
        };
        let agent_user_name = IsolationSessionManager::add_user(entra_account, wam_token)
            .map_err(map_lifecycle_error)?;

        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, agent_user_name),
            metadata: Some(IsolationSessionProvisionMetadata { agent_user_name }),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        config: Option<IsolationSessionConfig>,
    ) -> Result<StartResult<()>, MxcError> {
        let agent_user_name = extract_agent_user_name(sandbox_id)?;
        let manager = IsolationSessionManager::new(agent_user_name).map_err(map_lifecycle_error)?;
        // The sandboxId tail is opaque, so Entra-ness is carried by the
        // start config's user bundle: present → re-supply the WAM token;
        // absent → local session (empty token). The OS validates the token
        // against the agent user it assigned at provision.
        let cfg = config.unwrap_or_default();
        let wam_token = cfg
            .user
            .as_ref()
            .map(|u| u.wam_token.as_str())
            .unwrap_or("");
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

    // Filesystem rw/ro/denied paths, network, and proxy policy are rejected
    // at every phase: the backend has no host-folder-sharing, network, or
    // proxy primitive. Anything rejected produces a `policy_validation`
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
        config: Option<&IsolationSessionConfig>,
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
    use wxc_common::models::{ContainerPolicy, IsolationSessionUser};
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

    fn request_with_filesystem_policy() -> ExecutionRequest {
        ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\workspace".into()],
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
    fn validate_phase_hooks_accept_clean_request() {
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest::default();

        runner.validate_provision(&req, None).unwrap();
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
            .validate_provision(&ExecutionRequest::default(), Some(&cfg))
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
        let cfg = IsolationSessionConfig {
            user: Some(well_formed_user()),
        };
        runner
            .validate_start("iso:wxc-abcd1234", &ExecutionRequest::default(), Some(&cfg))
            .unwrap();
    }

    #[test]
    fn validate_start_rejects_malformed_user() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionConfig {
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
}
