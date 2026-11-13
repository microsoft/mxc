// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::Write;
use std::process::{Command, Stdio};

use mxc_sdk::v1::dev::{self, SpawnWithExtendedJsonOptions};
use mxc_sdk::v1::{
    spawn_with_extended_options, ContainerRequest, MxcProcess, SpawnStdio,
    SpawnWithExtendedOptions, WaitResult,
};

const HOST_ENV: &str = "MXC_INHERITED_STDIO_HOST";
const EXIT_CODE: i32 = 7;
const INPUT: &str = "INHERITED_STDIN_LINE";
const VARIANTS: [&str; 3] = ["typed", "1.0.0", "1.1.0-alpha"];

/// `command(marker, exit_code)` must read one line from stdin, print
/// `{marker}_OUT:{line}` to stdout and `{marker}_ERR` to stderr, then exit.
pub fn assert_uses_caller_stdio(
    test_name: &str,
    typed_request: impl FnOnce(String) -> ContainerRequest,
    command: impl Fn(&str, i32) -> String,
) {
    if let Ok(variant) = std::env::var(HOST_ENV) {
        run_host(&variant, typed_request, command);
        return;
    }

    assert_default_pipes(typed_request(command("PIPES", EXIT_CODE)));

    for variant in VARIANTS {
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                test_name,
                "--include-ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HOST_ENV, variant)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start inherited-stdio host");
        let line_ending = if cfg!(windows) { "\r\n" } else { "\n" };
        child
            .stdin
            .take()
            .expect("host stdin")
            .write_all(format!("{INPUT}{line_ending}").as_bytes())
            .expect("write host stdin");
        let output = child.wait_with_output().expect("wait for host");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{variant} host failed with {}:\n{stdout}\n{stderr}",
            output.status
        );
        let marker = marker(variant);
        assert!(
            stdout.contains(&format!("{marker}_OUT:{INPUT}")),
            "{variant}: stdin did not reach the workload, or its stdout did not reach the caller:\n{stdout}\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("{marker}_ERR")),
            "{variant}: the workload's stderr did not reach the caller:\n{stdout}\n{stderr}"
        );
    }
}

fn run_host(
    variant: &str,
    typed_request: impl FnOnce(String) -> ContainerRequest,
    command: impl Fn(&str, i32) -> String,
) {
    #[cfg(unix)]
    mark_stdio_close_on_exec();
    let command_line = command(&marker(variant), EXIT_CODE);
    let process = if variant == "typed" {
        let mut options = SpawnWithExtendedOptions::default();
        options.stdio = SpawnStdio::Inherit;
        spawn_with_extended_options(typed_request(command_line), options)
            .expect("spawn with inherited stdio")
    } else {
        let json = serde_json::json!({
            "version": variant,
            "containment": "process",
            "process": { "commandLine": command_line, "timeout": 30000 },
        })
        .to_string();
        let mut options = SpawnWithExtendedJsonOptions::default();
        options.stdio = SpawnStdio::Inherit;
        dev::spawn_with_extended_options_json(&json, options)
            .expect("spawn exact JSON with inherited stdio")
    };
    assert_inherited_exit(process);
}

fn assert_default_pipes(request: ContainerRequest) {
    let mut process = spawn_with_extended_options(request, SpawnWithExtendedOptions::default())
        .expect("spawn with default extended options");
    let line_ending = if cfg!(windows) { "\r\n" } else { "\n" };
    let mut stdin = process.take_stdin().expect("pipes mode provides stdin");
    stdin
        .write_all(format!("{INPUT}{line_ending}").as_bytes())
        .expect("write stdin");
    drop(stdin);
    let output = process.wait_with_output().expect("wait with output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.outcome,
        WaitResult::Exited(EXIT_CODE),
        "{stdout}\n{stderr}"
    );
    assert!(stdout.contains(&format!("PIPES_OUT:{INPUT}")), "{stdout}");
    assert!(stderr.contains("PIPES_ERR"), "{stderr}");
}

fn assert_inherited_exit(mut process: MxcProcess) {
    assert!(process.take_stdin().is_none());
    assert!(process.take_stdout().is_none());
    assert!(process.take_stderr().is_none());
    assert_eq!(process.wait().expect("wait"), WaitResult::Exited(EXIT_CODE));
}

fn marker(variant: &str) -> String {
    format!("INHERITED_STDIO_{}", variant.replace(['.', '-'], "_"))
}

// Node marks its stdio close-on-exec; doing the same makes this host as strict.
#[cfg(unix)]
fn mark_stdio_close_on_exec() {
    for fd in 0..=2 {
        // SAFETY: fcntl only reads and sets descriptor flags on this process's stdio.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            assert!(flags >= 0, "read flags of fd {fd}");
            assert!(libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) >= 0);
        }
    }
}
