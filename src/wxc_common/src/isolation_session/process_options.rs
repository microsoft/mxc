// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Process-creation options for the IsolationSession backend: MXC-internal
//! `ProcessOptions` built from a `CodexRequest`, then translated to the
//! WinRT `IsoSessionProcessOptions` consumed by `RunProcessWithOptionsAsync`.

use crate::models::CodexRequest;

use isolation_session_bindings::bindings::IsoSessionProcessOptions;
use windows_core::HSTRING;

use super::error::{lifecycle_err, IsolationSessionError};

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

/// Process creation options decoupled from `CodexRequest` and from the
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

/// Builds `ProcessOptions` from a `CodexRequest`. `interactive` flips the
/// backend into ConPTY mode (`InteractiveConsole = true`) and adjusts
/// `redirect_flags` accordingly (no separate stderr stream in ConPTY mode).
///
/// The command line is wrapped with `cmd.exe /c` so shell features (pipes,
/// redirections, chained commands) work — same pattern as the LXC backend's
/// `/bin/sh -c`.
pub(super) fn build_process_options(request: &CodexRequest, interactive: bool) -> ProcessOptions {
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

/// Translates the MXC-internal `ProcessOptions` into a fresh
/// `IsoSessionProcessOptions` ready for `RunProcessWithOptionsAsync`.
pub(super) fn build_iso_process_options(
    options: &ProcessOptions,
) -> Result<IsoSessionProcessOptions, IsolationSessionError> {
    let proc_options = IsoSessionProcessOptions::new()
        .map_err(|e| lifecycle_err(format!("IsoSessionProcessOptions::new failed: {}", e)))?;

    proc_options
        .SetTimeoutMilliseconds(options.timeout_ms)
        .map_err(|e| lifecycle_err(format!("SetTimeoutMilliseconds: {}", e)))?;

    if !options.working_directory.is_empty() {
        proc_options
            .SetWorkingDirectory(&HSTRING::from(&options.working_directory))
            .map_err(|e| lifecycle_err(format!("SetWorkingDirectory: {}", e)))?;
    }

    proc_options
        .SetInteractiveConsole(options.interactive)
        .map_err(|e| lifecycle_err(format!("SetInteractiveConsole: {}", e)))?;

    proc_options
        .SetRedirectStandardInput(options.redirect_flags & REDIRECT_STDIN != 0)
        .map_err(|e| lifecycle_err(format!("SetRedirectStandardInput: {}", e)))?;
    proc_options
        .SetRedirectStandardOutput(options.redirect_flags & REDIRECT_STDOUT != 0)
        .map_err(|e| lifecycle_err(format!("SetRedirectStandardOutput: {}", e)))?;
    proc_options
        .SetRedirectStandardError(options.redirect_flags & REDIRECT_STDERR != 0)
        .map_err(|e| lifecycle_err(format!("SetRedirectStandardError: {}", e)))?;

    if !options.env_vars.is_empty() {
        let env = proc_options
            .Environment()
            .map_err(|e| lifecycle_err(format!("get Environment IMap: {}", e)))?;
        for (name, value) in &options.env_vars {
            env.Insert(&HSTRING::from(name), &HSTRING::from(value))
                .map_err(|e| lifecycle_err(format!("Environment.Insert({}): {}", name, e)))?;
        }
    }

    Ok(proc_options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_wraps_command_with_cmd_exe() {
        let request = CodexRequest {
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
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            script_timeout: 30000,
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        assert_eq!(opts.timeout_ms, 30000);
    }

    #[test]
    fn options_maps_working_directory() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            working_directory: r"C:\Windows".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request, false);
        assert_eq!(opts.working_directory, r"C:\Windows");
    }

    #[test]
    fn options_parses_env_vars() {
        let request = CodexRequest {
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
        let request = CodexRequest {
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
        let request = CodexRequest {
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
        let request = CodexRequest {
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
