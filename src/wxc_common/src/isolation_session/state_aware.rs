// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for `IsolationSessionRunner`. Per-phase
//! methods + validation hooks. Each phase constructs a fresh
//! `IsolationSessionManager` because the OS service may idle-restart
//! between caller invocations.

use std::io::IsTerminal;

use serde::Serialize;

use crate::id::mint_random_token;
use crate::models::{CodexRequest, IsolationSessionConfig, IsolationSessionProvisionConfig};
use crate::mxc_error::MxcError;
use crate::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};

use windows::Win32::Foundation::HANDLE;

use super::error::map_lifecycle_error;
use super::manager::IsolationSessionManager;
use super::policy::{
    validate_isolation_session_user, validate_post_provision_policy, validate_provision_policy,
};
use super::process_options::{build_process_options, compute_redirect_flags};
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

/// Parses the `iso:<provisionId>` form of a state-aware sandbox_id and
/// returns the inner `provisionId` segment. Surfaces format mismatches as
/// `MxcError::MalformedId`.
fn extract_provision_id(sandbox_id: &str) -> Result<&str, MxcError> {
    let prefix = <IsolationSessionRunner as StatefulSandboxBackend>::ID_PREFIX;
    match sandbox_id.split_once(':') {
        Some((p, rest)) if p == prefix && !rest.is_empty() => Ok(rest),
        _ => Err(MxcError::malformed_id(format!(
            "expected {}:<provisionId>, got {:?}",
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
        request: &CodexRequest,
        config: Option<IsolationSessionProvisionConfig>,
    ) -> Result<ProvisionResult<IsolationSessionProvisionMetadata>, MxcError> {
        let user = config.and_then(|c| c.user);
        // For Entra sandboxes the UPN IS the OS-layer provisionId; encoding
        // it as the sandboxId tail keeps subsequent phases stateless.
        let provision_id = match &user {
            Some(u) => u.upn.clone(),
            None => format!("wxc-{}", mint_random_token()),
        };
        let manager = IsolationSessionManager::new(&provision_id).map_err(map_lifecycle_error)?;
        manager.register_client().map_err(map_lifecycle_error)?;

        let provision_result = match &user {
            Some(u) => manager.provision_agent_user_v2(&u.wam_token),
            None => manager.provision_agent_user(),
        };
        let agent_user_name = match provision_result {
            Ok(name) => name,
            Err(e) => {
                // provision_agent_user can fail after the OS-side provision
                // succeeded, leaving an Indefinite-lifetime agent user.
                // Defensive cleanup mirrors the one-shot path; no-ops on
                // absent state.
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return Err(map_lifecycle_error(e));
            }
        };

        // Apply filesystem policy (rw + ro paths) before returning. A
        // failure here leaves the agent user provisioned but no folders
        // accessible to it; tear it down so the caller does not see a
        // half-provisioned sandboxId.
        if let Err(e) = manager.share_folders(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
            None,
        ) {
            let _ = manager.deprovision_agent_user();
            let _ = manager.unregister_client();
            return Err(map_lifecycle_error(e));
        }

        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, provision_id),
            metadata: Some(IsolationSessionProvisionMetadata { agent_user_name }),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &CodexRequest,
        config: Option<IsolationSessionConfig>,
    ) -> Result<StartResult<()>, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;
        // Config absent → Composable (the one-shot default). The OS API
        // does not call back into MXC after start; a return here means the
        // session is ready to host process launches.
        let cfg = config.unwrap_or_default();
        let configuration_id = cfg.configuration_id;
        let start_result = match cfg.user {
            Some(u) => manager.start_session_v2(configuration_id, &u.wam_token),
            None => manager.start_session(configuration_id),
        };
        start_result.map_err(map_lifecycle_error)?;
        Ok(StartResult { metadata: None })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &CodexRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;
        manager.stop_session().map_err(map_lifecycle_error)?;
        Ok(StopResult { metadata: None })
    }

    /// Removes the agent user. The `unregister_client` step is currently a
    /// no-op so concurrent MXC isolation-session sandboxes coexist on the
    /// shared regid; deprovisioning one does not tear down another.
    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &CodexRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;
        manager
            .deprovision_agent_user()
            .map_err(map_lifecycle_error)?;
        manager.unregister_client().map_err(map_lifecycle_error)?;
        Ok(DeprovisionResult { metadata: None })
    }

    // Filesystem rw/ro paths are honoured at provision (applied via
    // `share_folders`) and rejected at every later phase, because the grant
    // lifecycle is bound to the agent user. `denied_paths`, network, and
    // proxy policy are rejected at every phase: the backend has no
    // equivalent primitive. Anything rejected produces a
    // `policy_validation` envelope rather than silent ignore.

    fn validate_provision(
        &self,
        request: &CodexRequest,
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
        request: &CodexRequest,
        config: Option<&IsolationSessionConfig>,
    ) -> Result<(), MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let is_entra = provision_id.contains('@');
        let user = config.and_then(|c| c.user.as_ref());
        match (is_entra, user) {
            (true, None) => {
                return Err(MxcError::malformed_request(
                    "Entra sandbox requires user at start",
                ));
            }
            (false, Some(_)) => {
                return Err(MxcError::malformed_request(
                    "user is not allowed for local sandbox",
                ));
            }
            (true, Some(u)) => {
                validate_isolation_session_user(u)?;
                if !u.upn.eq_ignore_ascii_case(provision_id) {
                    return Err(MxcError::malformed_request(
                        "user.upn does not match sandboxId",
                    ));
                }
            }
            (false, None) => {}
        }
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_exec(
        &self,
        _sandbox_id: &str,
        request: &CodexRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_stop(
        &self,
        _sandbox_id: &str,
        request: &CodexRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_post_provision_policy(request).map_err(map_lifecycle_error)
    }

    fn validate_deprovision(
        &self,
        _sandbox_id: &str,
        request: &CodexRequest,
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
        request: &CodexRequest,
        _config: Option<()>,
    ) -> Result<ExecHandle, MxcError> {
        let provision_id = extract_provision_id(sandbox_id)?;
        let manager = IsolationSessionManager::new(provision_id).map_err(map_lifecycle_error)?;

        let mut options = build_process_options(request);
        let interactive = std::io::stdout().is_terminal();
        options.interactive = interactive;
        options.redirect_flags = compute_redirect_flags(interactive);

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
    use crate::models::{ContainerPolicy, IsolationSessionUser};
    use crate::mxc_error::MxcErrorCode;

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

    // `ID_PREFIX` is the `<prefix>:<provisionId>` tag the dispatcher
    // matches against in `backend_from_prefix`. Indirectly covered by
    // every `extract_provision_id_*` test that uses an `"iso:..."`
    // literal; pinned explicitly here so the dependence is visible.
    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <IsolationSessionRunner as StatefulSandboxBackend>::ID_PREFIX,
            "iso"
        );
    }

    fn request_with_filesystem_policy() -> CodexRequest {
        CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\workspace".into()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // ====== sandbox_id parsing ======

    #[test]
    fn extract_provision_id_unwraps_iso_prefix() {
        assert_eq!(
            extract_provision_id("iso:wxc-abcd1234").unwrap(),
            "wxc-abcd1234"
        );
    }

    #[test]
    fn extract_provision_id_rejects_other_prefix() {
        let err = extract_provision_id("wsb:abc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_provision_id_rejects_missing_colon() {
        let err = extract_provision_id("no-colon").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_provision_id_rejects_empty_payload() {
        let err = extract_provision_id("iso:").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    // ====== validation-hook phase routing ======

    #[test]
    fn validate_provision_hook_accepts_filesystem_policy() {
        let runner = IsolationSessionRunner::new();
        let req = request_with_filesystem_policy();
        runner.validate_provision(&req, None).unwrap();
    }

    #[test]
    fn validate_provision_hook_rejects_denied_paths() {
        let runner = IsolationSessionRunner::new();
        let req = CodexRequest {
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
        let req = CodexRequest::default();

        runner.validate_provision(&req, None).unwrap();
        runner.validate_start("iso:abc", &req, None).unwrap();
        runner.validate_exec("iso:abc", &req, None).unwrap();
        runner.validate_stop("iso:abc", &req, None).unwrap();
        runner.validate_deprovision("iso:abc", &req, None).unwrap();
    }

    // ====== Entra user bundle + sandbox-id consistency matrix ======

    #[test]
    fn validate_provision_accepts_well_formed_user() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionProvisionConfig {
            user: Some(well_formed_user()),
        };
        runner
            .validate_provision(&CodexRequest::default(), Some(&cfg))
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
            .validate_provision(&CodexRequest::default(), Some(&cfg))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_entra_sandbox_with_matching_user_accepts() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionConfig {
            user: Some(well_formed_user()),
            ..Default::default()
        };
        runner
            .validate_start(
                "iso:alice@contoso.com",
                &CodexRequest::default(),
                Some(&cfg),
            )
            .unwrap();
    }

    #[test]
    fn validate_start_entra_sandbox_without_user_is_malformed() {
        let runner = IsolationSessionRunner::new();
        let err = runner
            .validate_start("iso:alice@contoso.com", &CodexRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message.contains("Entra sandbox requires user"),
            "got {}",
            err.message
        );
    }

    #[test]
    fn validate_start_local_sandbox_with_user_is_malformed() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionConfig {
            user: Some(well_formed_user()),
            ..Default::default()
        };
        let err = runner
            .validate_start("iso:wxc-abcd1234", &CodexRequest::default(), Some(&cfg))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message.contains("not allowed for local sandbox"),
            "got {}",
            err.message
        );
    }

    #[test]
    fn validate_start_local_sandbox_without_user_accepts() {
        let runner = IsolationSessionRunner::new();
        runner
            .validate_start("iso:wxc-abcd1234", &CodexRequest::default(), None)
            .unwrap();
    }

    #[test]
    fn validate_start_entra_user_upn_mismatch_is_malformed() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionConfig {
            user: Some(IsolationSessionUser {
                upn: "bob@contoso.com".to_string(),
                wam_token: "tok".to_string(),
            }),
            ..Default::default()
        };
        let err = runner
            .validate_start(
                "iso:alice@contoso.com",
                &CodexRequest::default(),
                Some(&cfg),
            )
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(
            err.message.contains("does not match sandboxId"),
            "got {}",
            err.message
        );
    }

    #[test]
    fn validate_start_entra_user_upn_match_is_case_insensitive() {
        let runner = IsolationSessionRunner::new();
        let cfg = IsolationSessionConfig {
            user: Some(IsolationSessionUser {
                upn: "Alice@Contoso.COM".to_string(),
                wam_token: "tok".to_string(),
            }),
            ..Default::default()
        };
        runner
            .validate_start(
                "iso:alice@contoso.com",
                &CodexRequest::default(),
                Some(&cfg),
            )
            .unwrap();
    }
}
