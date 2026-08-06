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

/// Refuses the `lifecycle` settings the backend cannot honor.
///
/// Value-based rather than presence-based (unlike `ui`), because the defaults
/// genuinely match the behavior: the in-proc API exposes no session-lifetime
/// knob, so one-shot always stops the session and removes the agent user before
/// returning — exactly what `destroyOnExit: true` asks for. Only the values the
/// backend cannot deliver are refused:
///
/// * `destroyOnExit: false` asks the session to outlive the call. It cannot.
/// * `preservePolicy: true` asks for filesystem/network policy to be retained
///   past the run. This backend installs no persistent filesystem or network
///   enforcement — filesystem policy is refused outright, and the accepted
///   network policy is an acknowledgment of an unrestricted posture rather than
///   anything applied — so there is nothing to retain.
fn reject_unsupported_lifecycle(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if !request.lifecycle.destroy_on_exit {
        return Err(ScriptResponse::error(
            "lifecycle.destroyOnExit=false is not supported by the isolation session backend; \
             the session is always stopped and the agent user removed before the call returns",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(ScriptResponse::error(
            "lifecycle.preservePolicy=true is not supported by the isolation session backend; \
             it installs no persistent filesystem or network enforcement, so there is none \
             to preserve",
        ));
    }
    Ok(())
}

impl ScriptRunner for IsolationSessionRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        // One-shot runs the full provision → start → exec → stop →
        // deprovision lifecycle in a single process, so provision-phase
        // semantics apply to the whole call. The one-shot surface takes no
        // backend configuration, so there is nothing backend-specific to
        // validate here — only the cross-cutting stable-surface policy.
        reject_unsupported_lifecycle(request)?;
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

        // Provision returns the OS-assigned account name plus a manager
        // already pegged to it. Taking the manager from `add_user` is what
        // keeps a freshly-minted agent user from being stranded: a separate
        // `new()` would activate the service a second time, and a failure
        // there would leave an account that can no longer be removed.
        let manager = match IsolationSessionManager::add_user() {
            Ok((provisioned, manager)) => {
                let _ = writeln!(
                    logger,
                    "Isolation Session: agent user = {}",
                    provisioned.agent_user_name
                );
                manager
            }
            Err(e) => return e.into(),
        };

        if let Err(e) = manager.start_session() {
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
    use wxc_common::models::{ContainerPolicy, LifecycleConfig, NetworkPolicy};

    #[test]
    fn validate_runner_one_shot_rejects_default_network() {
        // No user, but the default (absent → `Block`) network is not the
        // canonical unrestricted-network acknowledgment, so one-shot provision
        // refuses it (one-shot runs the full lifecycle, so provision rules
        // apply).
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest::default();
        let resp = runner.validate_runner(&req).unwrap_err();
        assert!(
            resp.error_message.contains("network"),
            "got {}",
            resp.error_message
        );
    }

    // ====== lifecycle (value-based: defaults match actual behavior) ======

    fn canonical_request() -> ExecutionRequest {
        ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                allow_local_network: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn validate_runner_one_shot_rejects_destroy_on_exit_false() {
        // The in-proc API has no session-lifetime knob; one-shot always tears
        // the session down, so this asks for something the backend cannot do.
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest {
            lifecycle: LifecycleConfig {
                destroy_on_exit: false,
                preserve_policy: false,
            },
            ..canonical_request()
        };
        let resp = runner.validate_runner(&req).unwrap_err();
        assert!(
            resp.error_message.contains("lifecycle.destroyOnExit=false"),
            "got {}",
            resp.error_message
        );
    }

    #[test]
    fn validate_runner_one_shot_rejects_preserve_policy_true() {
        let runner = IsolationSessionRunner::new();
        let req = ExecutionRequest {
            lifecycle: LifecycleConfig {
                destroy_on_exit: true,
                preserve_policy: true,
            },
            ..canonical_request()
        };
        let resp = runner.validate_runner(&req).unwrap_err();
        assert!(
            resp.error_message.contains("lifecycle.preservePolicy=true"),
            "got {}",
            resp.error_message
        );
    }

    #[test]
    fn validate_runner_one_shot_accepts_default_lifecycle() {
        // `destroyOnExit: true` (the default) is exactly what the backend does,
        // so it must not be refused — the gate is value-based for this reason.
        let runner = IsolationSessionRunner::new();
        runner.validate_runner(&canonical_request()).unwrap();
    }

    #[test]
    fn validate_runner_one_shot_rejects_supplied_ui() {
        let runner = IsolationSessionRunner::new();
        let mut req = canonical_request();
        req.policy.ui_specified = true;
        let resp = runner.validate_runner(&req).unwrap_err();
        assert!(
            resp.error_message.contains("UI policy is not supported"),
            "got {}",
            resp.error_message
        );
    }
}
