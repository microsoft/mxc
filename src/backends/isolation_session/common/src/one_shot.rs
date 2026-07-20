// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `ScriptRunner` impl for `IsolationSessionRunner`. Runs the full
//! provision → start → exec → stop → deprovision lifecycle in a single
//! process.

use std::fmt::Write;
use std::io::IsTerminal;

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;

use super::manager::IsolationSessionManager;
use super::policy::validate_provision_policy;
use super::process_options::build_process_options;
use super::IsolationSessionRunner;

impl ScriptRunner for IsolationSessionRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
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

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        // Detect at runtime whether wxc-exec's stdout is a TTY. This flips
        // the backend into ConPTY mode (`InteractiveConsole = true`) and
        // adjusts the redirect flags (no separate stderr in ConPTY mode —
        // the OS API merges it into stdout). The check sees the handle
        // wxc-exec was given by its immediate parent: ConPTY when launched
        // by node-pty (`spawnSandbox`), pipe when launched by
        // `child_process.spawn` (`spawnSandboxFromConfig({usePty: false})`),
        // console when launched directly from a shell.
        let interactive = std::io::stdout().is_terminal();
        let options = build_process_options(request, interactive);

        let _ = writeln!(
            logger,
            "Isolation Session: process={}",
            options.process_path
        );
        let _ = writeln!(logger, "Isolation Session: arguments={}", options.arguments);
        let _ = writeln!(logger, "Isolation Session: interactive={}", interactive);

        // One-shot runs are local agent users only (state-aware handles
        // Entra). An explicit appId from config is passed verbatim; when
        // absent, the manager auto-detects the invoking (parent) process's
        // PFN, if the process is packaged. Provision returns the OS-assigned
        // account name; the manager is then pegged to it for the rest of the
        // lifecycle.
        let app_id = request
            .experimental
            .isolation_session
            .as_ref()
            .and_then(|c| c.app_id.clone())
            .unwrap_or_default();
        let agent_user_name = match IsolationSessionManager::add_user(app_id.as_str(), "", "") {
            Ok(provisioned) => {
                let _ = writeln!(
                    logger,
                    "Isolation Session: agent user = {}",
                    provisioned.agent_user_name
                );
                provisioned.agent_user_name
            }
            Err(e) => return e.into(),
        };

        let manager = match IsolationSessionManager::new(&agent_user_name) {
            Ok(m) => m,
            Err(e) => return e.into(),
        };

        if let Err(e) = manager.start_session("") {
            // Provision succeeded; start did not. Clean up. stop_session
            // is a no-op on an unstarted session.
            let _ = manager.stop_session();
            let _ = manager.deprovision_agent_user();
            return e.into();
        }

        let exit_code = match manager.create_process(&options) {
            Ok(code) => code,
            Err(e) => {
                let _ = manager.stop_session();
                let _ = manager.deprovision_agent_user();
                return e.into();
            }
        };

        if let Err(e) = manager.stop_session() {
            let _ = writeln!(logger, "Warning: stop_session failed: {}", e);
        }
        if let Err(e) = manager.deprovision_agent_user() {
            let _ = writeln!(logger, "Warning: deprovision_agent_user failed: {}", e);
        }

        // Output already streamed live to wxc-exec's stdio via relay
        // threads in `create_process` — captured fields intentionally
        // empty (same pattern as AppContainer).
        ScriptResponse {
            exit_code,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ExperimentalConfig, IsolationSessionConfig, IsolationSessionUser};

    fn well_formed_user() -> IsolationSessionUser {
        IsolationSessionUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: "tok".to_string(),
        }
    }

    #[test]
    fn validate_runner_one_shot_rejects_user() {
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest {
            experimental: ExperimentalConfig {
                isolation_session: Some(IsolationSessionConfig {
                    user: Some(well_formed_user()),
                    app_id: None,
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
        let req = ExecutionRequest {
            experimental: ExperimentalConfig {
                isolation_session: Some(IsolationSessionConfig::default()),
                ..Default::default()
            },
            ..Default::default()
        };
        runner.validate_runner(&req).unwrap();
    }
}
