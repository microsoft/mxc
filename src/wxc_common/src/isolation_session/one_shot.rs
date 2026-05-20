// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `ScriptRunner` impl for `IsolationSessionRunner`. Runs the full
//! register → provision → share → start → exec → stop → deprovision
//! lifecycle in a single process.

use std::fmt::Write;
use std::io::IsTerminal;

use crate::id::mint_random_token;
use crate::logger::Logger;
use crate::models::{CodexRequest, IsolationSessionConfigurationId, ScriptResponse};
use crate::script_runner::ScriptRunner;

use super::manager::IsolationSessionManager;
use super::policy::validate_provision_policy;
use super::process_options::{build_process_options, compute_redirect_flags};
use super::IsolationSessionRunner;

impl ScriptRunner for IsolationSessionRunner {
    fn validate_runner(&self, request: &CodexRequest) -> Result<(), ScriptResponse> {
        // One-shot runs the full provision → start → exec → stop →
        // deprovision lifecycle in a single process, so provision-phase
        // semantics apply to the whole call.
        if let Some(cfg) = request.experimental.isolation_session.as_ref() {
            if cfg.user.is_some() {
                return Err(ScriptResponse::error(
                    "user is not supported in one-shot mode; use the state-aware lifecycle",
                ));
            }
        }
        validate_provision_policy(request).map_err(ScriptResponse::from)
    }

    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        let mut options = build_process_options(request);

        // Detect at runtime whether wxc-exec's stdout is a TTY. This flips
        // the backend into ConPTY mode (`InteractiveConsole = true`) and
        // adjusts the redirect flags (no separate stderr in ConPTY mode —
        // the OS API merges it into stdout). The check sees the handle
        // wxc-exec was given by its immediate parent: ConPTY when launched
        // by node-pty (`spawnSandbox`), pipe when launched by
        // `child_process.spawn` (`spawnSandboxFromConfig({usePty: false})`),
        // console when launched directly from a shell.
        let interactive = std::io::stdout().is_terminal();
        options.interactive = interactive;
        options.redirect_flags = compute_redirect_flags(interactive);

        let _ = writeln!(
            logger,
            "Isolation Session: process={}",
            options.process_path
        );
        let _ = writeln!(logger, "Isolation Session: arguments={}", options.arguments);
        let _ = writeln!(logger, "Isolation Session: interactive={}", interactive);

        let session_cfg = request.experimental.isolation_session.as_ref();
        let config_id: IsolationSessionConfigurationId = session_cfg
            .map(|cfg| cfg.configuration_id)
            .unwrap_or_default();

        // Mint a per-invocation provisionId so concurrent MXC
        // isolation-session processes do not collide on agent identity.
        let provision_id = format!("wxc-{}", mint_random_token());
        let manager = match IsolationSessionManager::new(&provision_id) {
            Ok(m) => m,
            Err(e) => return e.into(),
        };

        if let Err(e) = manager.register_client() {
            return e.into();
        }

        match manager.provision_agent_user() {
            Ok(agent_name) => {
                let _ = writeln!(logger, "Isolation Session: agent user = {}", agent_name);
            }
            Err(e) => {
                // provision_agent_user may return Err *after* a successful
                // OS-side provision (e.g., the AgentUserName fetch fails on
                // a non-error result). Defensively deprovision so an
                // Indefinite-lifetime agent user does not leak.
                // No-ops on absent state.
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return e.into();
            }
        }

        if let Err(e) = manager.share_folders(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
            Some(logger),
        ) {
            let _ = manager.deprovision_agent_user();
            let _ = manager.unregister_client();
            return e.into();
        }

        if let Err(e) = manager.start_session(config_id) {
            // Provision succeeded; start did not. Clean up. stop_session
            // is a no-op on an unstarted session.
            let _ = manager.stop_session();
            let _ = manager.deprovision_agent_user();
            let _ = manager.unregister_client();
            return e.into();
        }

        let exit_code = match manager.create_process(&options) {
            Ok(code) => code,
            Err(e) => {
                let _ = manager.stop_session();
                let _ = manager.deprovision_agent_user();
                let _ = manager.unregister_client();
                return e.into();
            }
        };

        if let Err(e) = manager.stop_session() {
            let _ = writeln!(logger, "Warning: stop_session failed: {}", e);
        }
        if let Err(e) = manager.deprovision_agent_user() {
            let _ = writeln!(logger, "Warning: deprovision_agent_user failed: {}", e);
        }
        if let Err(e) = manager.unregister_client() {
            let _ = writeln!(logger, "Warning: unregister_client failed: {}", e);
        }

        // Output already streamed live to wxc-exec's stdio via relay
        // threads in `create_process` — captured fields intentionally
        // empty (same pattern as AppContainer).
        ScriptResponse {
            exit_code,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ExperimentalConfig, IsolationSessionConfig, IsolationSessionUser};

    fn well_formed_user() -> IsolationSessionUser {
        IsolationSessionUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: "tok".to_string(),
        }
    }

    #[test]
    fn validate_runner_one_shot_rejects_user() {
        let runner = IsolationSessionRunner::new();
        let req = CodexRequest {
            experimental: ExperimentalConfig {
                isolation_session: Some(IsolationSessionConfig {
                    user: Some(well_formed_user()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let resp = runner.validate_runner(&req).unwrap_err();
        assert!(
            resp.error_message
                .contains("user is not supported in one-shot mode"),
            "got {}",
            resp.error_message
        );
    }

    #[test]
    fn validate_runner_one_shot_accepts_no_user() {
        let runner = IsolationSessionRunner::new();
        let req = CodexRequest {
            experimental: ExperimentalConfig {
                isolation_session: Some(IsolationSessionConfig::default()),
                ..Default::default()
            },
            ..Default::default()
        };
        runner.validate_runner(&req).unwrap();
    }
}
