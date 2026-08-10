// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-creation options for the IsolationSession backend: MXC-internal
//! `ProcessOptions` built from an `ExecutionRequest`, then translated to the
//! WinRT `IsoSessionProcessOptions` consumed by `RunProcessWithOptionsAsync`.

use wxc_common::models::ExecutionRequest;

use isolation_session_bindings::bindings::IsoSessionProcessOptions;
use windows_core::HSTRING;

use super::error::{op, regfree_not_fused, transport_err, IsolationSessionError};

const REDIRECT_STDIN: u32 = 0x1;
const REDIRECT_STDOUT: u32 = 0x2;
const REDIRECT_STDERR: u32 = 0x4;

/// Canonical redirect-flags bitfield for the agent process I/O.
///
/// Stdin and stdout are always redirected. Stderr is redirected ONLY in
/// non-interactive mode: in ConPTY mode the OS API merges stderr into
/// stdout and does not populate the stderr handle, so asking for it would
/// produce a handle of 0.
fn compute_redirect_flags(interactive: bool) -> u32 {
    let mut flags = REDIRECT_STDIN | REDIRECT_STDOUT;
    if !interactive {
        flags |= REDIRECT_STDERR;
    }
    flags
}

/// Process creation options decoupled from `ExecutionRequest` and from the
/// WinRT types — small struct so the builder is unit-testable without a
/// live `IsoSessionOps` activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcessOptions {
    pub process_path: String,
    pub arguments: String,
    /// Execution timeout in milliseconds. 0 = no timeout.
    pub timeout_ms: u32,
    /// Empty = default working directory.
    pub working_directory: String,
    pub env_vars: Vec<(String, String)>,
    pub redirect_flags: u32,
    /// `true` asks the OS API to set up a ConPTY in the isolation session.
    /// Caller (the runner) sets this from `std::io::stdout().is_terminal()`.
    pub interactive: bool,
}

/// Builds `ProcessOptions` from an `ExecutionRequest`. `interactive` flips the
/// backend into ConPTY mode (`InteractiveConsole = true`) and adjusts
/// `redirect_flags` accordingly (no separate stderr stream in ConPTY mode).
///
/// The command line is wrapped with `cmd.exe /c` so shell features (pipes,
/// redirections, chained commands) work — same pattern as the LXC backend's
/// `/bin/sh -c`.
pub(super) fn build_process_options(
    request: &ExecutionRequest,
    interactive: bool,
) -> ProcessOptions {
    let env_vars: Vec<(String, String)> = request
        .env
        .iter()
        .filter_map(|entry| {
            let mut parts = entry.splitn(2, '=');
            let name = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").to_string();
            if name.is_empty() {
                None
            } else {
                Some((name, value))
            }
        })
        .collect();

    // Resolve cmd.exe off `%SystemDrive%` rather than hardcoding `C:`.
    // Fallback `C:` covers the unlikely case of an absent env var.
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let process_path = format!(r"{}\Windows\System32\cmd.exe", system_drive);

    ProcessOptions {
        process_path,
        arguments: format!("/c {}", request.script_code),
        timeout_ms: request.script_timeout,
        working_directory: request.working_directory.clone(),
        env_vars,
        redirect_flags: compute_redirect_flags(interactive),
        interactive,
    }
}

/// How much longer than the caller's deadline the **service-side** timer is
/// armed for on the streaming path.
///
/// The service arms its timer when the process is created and kills the process
/// with an ordinary exit code (the host suite pins this as exit code 1). Our own
/// `WaitForExit` starts later and, with an equal duration, therefore always
/// loses the race — so a genuine timeout arrives looking exactly like a normal
/// exit and cannot be reported as one.
///
/// Giving the service timer a margin lets the local deadline fire first, so a
/// timeout is observed as the wait sentinel plus a still-running process. The
/// service timer stays armed as a watchdog for the case this process dies
/// before it can enforce anything.
///
/// **This is a margin, not a guarantee.** It orders the two timers only while
/// the gap between arming the service timer and entering our own wait — a few
/// COM calls and a thread spawn — stays under the margin; a host stall longer
/// than that could still let the service win. No timeout *signal* is available
/// to key off instead: the process interface exposes lifetime and console
/// members (`ExitCode`, `WaitForExit`, `Terminate`, `CloseStandardInput`,
/// `SendCtrlClose`, the stdio handles, `ResizeConsole`) and nothing that
/// distinguishes a service-enforced kill from an ordinary exit. Five seconds is
/// chosen to dwarf that startup gap rather than to bound the OS.
pub(super) const SERVICE_TIMEOUT_GRACE_MS: u32 = 5_000;

/// Relaxes the service-side timer so the caller's deadline is enforced locally.
///
/// Only for the streaming path, which has somewhere to report a timeout. The
/// run-to-completion path keeps the service timer exactly as it was: it has no
/// timeout channel, and its observable behaviour (exit code 1 on an OS-side
/// timeout) is pinned by the host suite.
///
/// Two deadlines are left alone rather than shifted:
///
/// - **Zero** means INFINITE. There is no deadline to move behind, and adding a
///   grace would invent one the caller never asked for.
/// - **A deadline too large to move** (within `SERVICE_TIMEOUT_GRACE_MS` of
///   `u32::MAX`) disarms the service timer instead. Saturating would silently
///   shrink the margin to nothing and re-equalize the timers, restoring the
///   exact misclassification this exists to prevent. At that magnitude — over
///   forty-nine days — a watchdog is meaningless anyway, so the local deadline
///   becomes the only one.
pub(super) fn with_service_timeout_grace(mut options: ProcessOptions) -> ProcessOptions {
    const NO_SERVICE_TIMEOUT: u32 = 0;
    if options.timeout_ms == 0 {
        return options;
    }
    options.timeout_ms = match options.timeout_ms.checked_add(SERVICE_TIMEOUT_GRACE_MS) {
        Some(armed) => armed,
        None => NO_SERVICE_TIMEOUT,
    };
    options
}

/// Translates the MXC-internal `ProcessOptions` into a fresh
/// `IsoSessionProcessOptions` ready for `RunProcessWithOptionsAsync`.
pub(super) fn build_iso_process_options(
    options: &ProcessOptions,
) -> Result<IsoSessionProcessOptions, IsolationSessionError> {
    let proc_options =
        match super::regfree::activate_via_private_clsid::<IsoSessionProcessOptions>() {
            Some(result) => {
                result.map_err(|e| transport_err(op::OPTIONS_NEW, "activation failed", &e))?
            }
            // No inbox fallback: the fused private-CLSID activator is absent.
            None => return Err(regfree_not_fused(op::OPTIONS_NEW)),
        };

    proc_options
        .SetTimeoutMilliseconds(options.timeout_ms)
        .map_err(|e| transport_err(op::OPTIONS_TIMEOUT, "set failed", &e))?;

    if !options.working_directory.is_empty() {
        proc_options
            .SetWorkingDirectory(&HSTRING::from(&options.working_directory))
            .map_err(|e| transport_err(op::OPTIONS_WORKING_DIR, "set failed", &e))?;
    }

    proc_options
        .SetInteractiveConsole(options.interactive)
        .map_err(|e| transport_err(op::OPTIONS_INTERACTIVE, "set failed", &e))?;

    proc_options
        .SetRedirectStandardInput(options.redirect_flags & REDIRECT_STDIN != 0)
        .map_err(|e| transport_err(op::OPTIONS_REDIRECT_STDIN, "set failed", &e))?;
    proc_options
        .SetRedirectStandardOutput(options.redirect_flags & REDIRECT_STDOUT != 0)
        .map_err(|e| transport_err(op::OPTIONS_REDIRECT_STDOUT, "set failed", &e))?;
    proc_options
        .SetRedirectStandardError(options.redirect_flags & REDIRECT_STDERR != 0)
        .map_err(|e| transport_err(op::OPTIONS_REDIRECT_STDERR, "set failed", &e))?;

    if !options.env_vars.is_empty() {
        let env = proc_options
            .Environment()
            .map_err(|e| transport_err(op::OPTIONS_ENVIRONMENT, "get failed", &e))?;
        for (name, value) in &options.env_vars {
            // The variable name rides in the message, never in `operation` —
            // that field stays low-cardinality for telemetry grouping.
            env.Insert(&HSTRING::from(name), &HSTRING::from(value))
                .map_err(|e| {
                    transport_err(
                        op::OPTIONS_ENVIRONMENT,
                        &format!("insert {name} failed"),
                        &e,
                    )
                })?;
        }
    }

    Ok(proc_options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_wraps_command_with_cmd_exe() {
        let request = ExecutionRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        // Host-relative — drive comes from %SYSTEMDRIVE% (typically `C:`),
        // so assert the trailing path shape rather than the full literal.
        assert!(
            opts.process_path.ends_with(r"\Windows\System32\cmd.exe"),
            "unexpected process_path: {}",
            opts.process_path
        );
        assert_eq!(opts.arguments, "/c echo hello");
    }

    #[test]
    fn options_maps_timeout() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            script_timeout: 30000,
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        assert_eq!(opts.timeout_ms, 30000);
    }

    /// The service-side timer must not be able to fire before the caller's own
    /// deadline on the streaming path.
    ///
    /// The regression this pins: both timers were armed with the same duration,
    /// but the service arms its own at process creation while our wait starts
    /// later, so the service always won the race. A genuine timeout then
    /// arrived looking like an ordinary exit — the host suite pins the
    /// OS-side timeout as exit code 1 — so it could not be reported as a
    /// timeout at all, and the streaming path's timeout reporting never fired.
    #[test]
    fn the_service_timer_is_armed_behind_the_local_deadline() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            script_timeout: 30000,
            ..Default::default()
        };
        let local = build_process_options(&request, false);
        let relaxed = with_service_timeout_grace(local);
        assert!(
            relaxed.timeout_ms > 30000,
            "the service timer must outlast the caller's deadline, got {}",
            relaxed.timeout_ms
        );
    }

    /// INFINITE stays INFINITE: there is no deadline to move behind, and
    /// giving it a grace would invent a deadline the caller never asked for.
    #[test]
    fn an_infinite_timeout_is_not_given_a_service_grace() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            script_timeout: 0,
            ..Default::default()
        };
        let relaxed = with_service_timeout_grace(build_process_options(&request, false));
        assert_eq!(relaxed.timeout_ms, 0);
    }

    /// A deadline too large to move disarms the service timer rather than
    /// silently re-equalizing the two.
    ///
    /// The regression this pins: saturating arithmetic clamps at `u32::MAX`, so
    /// a deadline within the grace of the maximum would come back with a margin
    /// shrunk to nothing — the timers equal again, and a genuine timeout once
    /// more indistinguishable from an ordinary exit. `timeout` is an
    /// unconstrained `u32` on the wire, so this is reachable input.
    #[test]
    fn a_deadline_too_large_to_move_disarms_the_service_timer() {
        for script_timeout in [
            u32::MAX,
            u32::MAX - 1,
            u32::MAX - SERVICE_TIMEOUT_GRACE_MS + 1,
        ] {
            let request = ExecutionRequest {
                script_code: "echo hi".to_string(),
                script_timeout,
                ..Default::default()
            };
            let relaxed = with_service_timeout_grace(build_process_options(&request, false));
            assert_eq!(
                relaxed.timeout_ms, 0,
                "a deadline of {script_timeout} must disarm the service timer rather than \
                 arm it equal to the caller's deadline"
            );
        }
    }

    /// The largest deadline that can still be moved keeps a full margin.
    #[test]
    fn the_largest_movable_deadline_keeps_its_full_margin() {
        let script_timeout = u32::MAX - SERVICE_TIMEOUT_GRACE_MS;
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            script_timeout,
            ..Default::default()
        };
        let relaxed = with_service_timeout_grace(build_process_options(&request, false));
        assert_eq!(relaxed.timeout_ms, u32::MAX);
        assert!(relaxed.timeout_ms > script_timeout);
    }

    #[test]
    fn options_maps_working_directory() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            working_directory: r"C:\Windows".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        assert_eq!(opts.working_directory, r"C:\Windows");
    }

    #[test]
    fn options_parses_env_vars() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            env: vec!["FOO=bar".to_string(), "PATH=C:\\bin;C:\\tools".to_string()],
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        assert_eq!(opts.env_vars.len(), 2);
        assert_eq!(opts.env_vars[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(
            opts.env_vars[1],
            ("PATH".to_string(), r"C:\bin;C:\tools".to_string())
        );
    }

    #[test]
    fn options_skips_malformed_env_vars() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            env: vec![
                "GOOD=value".to_string(),
                "=no_name".to_string(),
                "ALSO_GOOD=".to_string(),
            ],
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        assert_eq!(opts.env_vars.len(), 2);
        assert_eq!(opts.env_vars[0].0, "GOOD");
        assert_eq!(opts.env_vars[1], ("ALSO_GOOD".to_string(), String::new()));
    }

    #[test]
    fn options_non_interactive_redirects_all_three_streams() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        assert!(!opts.interactive);
        assert_eq!(
            opts.redirect_flags,
            REDIRECT_STDIN | REDIRECT_STDOUT | REDIRECT_STDERR
        );
    }

    #[test]
    fn options_interactive_redirects_stdin_stdout_only() {
        let request = ExecutionRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request, true);
        assert!(opts.interactive);
        assert_eq!(opts.redirect_flags, REDIRECT_STDIN | REDIRECT_STDOUT);
        assert_eq!(
            opts.redirect_flags & REDIRECT_STDERR,
            0,
            "interactive (ConPTY) mode merges stderr into stdout"
        );
    }

    #[test]
    fn compute_redirect_flags_interactive_omits_stderr() {
        let flags = compute_redirect_flags(true);
        assert!(
            flags & REDIRECT_STDIN != 0,
            "stdin should be redirected even in interactive mode"
        );
        assert!(flags & REDIRECT_STDOUT != 0, "stdout should be redirected");
        assert!(
            flags & REDIRECT_STDERR == 0,
            "stderr should NOT be redirected in interactive (ConPTY) mode \
             — the OS API does not populate ErrorHandle"
        );
    }

    #[test]
    fn compute_redirect_flags_noninteractive_includes_stderr() {
        let flags = compute_redirect_flags(false);
        assert!(flags & REDIRECT_STDIN != 0, "stdin should be redirected");
        assert!(flags & REDIRECT_STDOUT != 0, "stdout should be redirected");
        assert!(
            flags & REDIRECT_STDERR != 0,
            "stderr should be redirected in non-interactive (plain pipes) mode"
        );
    }
}
