// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bubblewrap (Linux) executor **characterization** tests.
//!
//! These lock in the run-to-completion behavior of the `lxc-exec` Bubblewrap
//! path. They assert what the code does **today**.
//!
//! Bubblewrap `--clearenv`s unconditionally, so the env contract pinned here is
//! deliberate rather than incidental. The harness captures via `.output()` and
//! so cannot provide a real PTY; the stdin/`SIGTTIN` behavior that needs one is
//! tracked separately.
//!
//! They run in the existing Linux CI job (`cargo test`) **only when `bwrap` is
//! installed** — `has_bwrap()` skips them cleanly otherwise. Each test also
//! skips if `lxc-exec` has not been built.
#![cfg(target_os = "linux")]

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};
use wxc_e2e_tests::{
    has_bwrap, has_platform_exec, run_platform_config_value,
    run_platform_config_value_within_duration,
};

const SCHEMA_VERSION: &str = "0.9.0-alpha";
const AF_VSOCK: libc::c_int = 40;
const UNASSIGNED_FAMILY: libc::c_int = 255;
const IO_URING_PARAMS_SIZE: usize = 120;

/// The schema that introduced the default environment block and start-directory
/// normalization, so cases asserting either must name it explicitly.
const SCHEMA_VERSION_0_9: &str = "0.9.0-alpha";

/// Whether the Bubblewrap characterization prerequisites are present.
fn ready() -> bool {
    has_platform_exec() && has_bwrap()
}

/// Build a one-shot config that omits `containment` so the binary selects its
/// OS-native backend (Bubblewrap on Linux).
fn config(label: &str, command_line: &str) -> serde_json::Value {
    config_at(SCHEMA_VERSION, label, command_line)
}

/// [`config`] against an explicit schema version.
fn config_at(version: &str, label: &str, command_line: &str) -> serde_json::Value {
    json!({
        "version": version,
        "containerId": format!("char-bwrap-{label}"),
        "process": { "commandLine": command_line }
    })
}

/// A private directory on the host, used as a policy grant or as the launching
/// process's own working directory.
fn unique_tempdir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mxc-char-bwrap-{tag}-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn bubblewrap_propagates_exit_code() {
    if !ready() {
        return;
    }
    let result =
        run_platform_config_value("bwrap exit code", &config("exit-code", "exit 7"), &[], None);
    assert_eq!(
        result.code,
        Some(7),
        "expected exit 7, got {:?}\n--- stderr ---\n{}",
        result.code,
        result.stderr
    );
}

#[test]
fn bubblewrap_streams_stdout() {
    if !ready() {
        return;
    }
    let result = run_platform_config_value(
        "bwrap stdout",
        &config("stdout", "echo CHAR_BWRAP_STDOUT_71c4d"),
        &[],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result.combined_output().contains("CHAR_BWRAP_STDOUT_71c4d"),
        "stdout missing sentinel:\n{}",
        result.combined_output()
    );
}

/// CHARACTERIZES CURRENT BEHAVIOR.
///
/// Bubblewrap runs with `--clearenv`, so the sandboxed child does *not* inherit
/// the launcher's environment even when `process.env` is empty. The refactor
/// should preserve this; if it ever turns RED the env model has drifted.
#[test]
fn bubblewrap_clears_host_env_by_default() {
    if !ready() {
        return;
    }
    let marker = "CHAR_BWRAP_SHOULD_NOT_APPEAR_8a02f";
    let result = run_platform_config_value(
        "bwrap env clear",
        &config("env-clear", "printf 'MARKER=[%s]\\n' \"$MXC_CHAR_MARKER\""),
        &[("MXC_CHAR_MARKER", marker)],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    let out = result.combined_output();
    assert!(
        out.contains("MARKER=[]"),
        "expected cleared env (MARKER=[]); current Bubblewrap --clearenv behavior. Output:\n{out}"
    );
    assert!(
        !out.contains(marker),
        "host env marker leaked into the sandbox. Output:\n{out}"
    );
}

/// Locks in that an explicitly requested `process.env` reaches the child.
#[test]
fn bubblewrap_applies_requested_env() {
    if !ready() {
        return;
    }
    let mut cfg = config("env-set", "printf 'SET=[%s]\\n' \"$MXC_CHAR_SET\"");
    cfg["process"]["env"] = json!(["MXC_CHAR_SET=from_config_c93b"]);
    let result = run_platform_config_value("bwrap env set", &cfg, &[], None);
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result.combined_output().contains("SET=[from_config_c93b]"),
        "expected requested env var to reach the child. Output:\n{}",
        result.combined_output()
    );
}

/// Locks in that a filesystem grant is **not** a working directory.
///
/// Seatbelt and ProcessContainer both resolve an empty `process.cwd` to the
/// first read-write policy path. Bubblewrap deliberately does not: it emits
/// `--chdir` only for `process.cwd`, because a granted directory is somewhere
/// the child was permitted to go, not somewhere it was asked to start. The
/// divergence is easy to "fix" into conformity by mistake, so it is pinned
/// end-to-end here and not only in `bwrap_command.rs`.
#[test]
fn bubblewrap_does_not_adopt_a_policy_grant_as_the_working_directory() {
    if !ready() {
        return;
    }
    let grant = fs::canonicalize(unique_tempdir("cwd-grant")).expect("canonicalize grant");
    let mut cfg = config("cwd-grant", "pwd -P");
    cfg["filesystem"] = json!({ "readwritePaths": [grant.to_string_lossy()] });
    let result = run_platform_config_value("bwrap cwd grant", &cfg, &[], None);
    let landed = result.stdout.trim().to_string();
    let _ = fs::remove_dir_all(&grant);

    assert_eq!(
        result.code,
        Some(0),
        "run failed:\n{}",
        result.combined_output()
    );
    assert_ne!(
        landed,
        grant.to_string_lossy(),
        "a read-write grant must not become the child's working directory"
    );
}

/// Locks in that from schema 0.9 a relative `process.cwd` is anchored to the
/// sandbox root rather than resolving against whatever directory `bwrap`
/// carried into the namespace.
///
/// `tmp` is the probe because the backend always mounts a `--tmpfs /tmp`, so
/// `/tmp` is guaranteed to exist inside the sandbox while the launching
/// process's own directory is not. Anchoring is what keeps `HOME` and
/// `--chdir` naming the same directory, so both are asserted together.
#[test]
fn bubblewrap_anchors_a_relative_process_cwd_from_0_9() {
    if !ready() {
        return;
    }
    // Launched from a directory that is *not* the filesystem root, so an
    // unanchored `tmp` could not coincidentally resolve to `/tmp`.
    let launch = fs::canonicalize(unique_tempdir("cwd-relative")).expect("canonicalize launch");
    let mut cfg = config_at(
        SCHEMA_VERSION_0_9,
        "cwd-relative",
        "printf 'PWD=[%s] HOME=[%s]\\n' \"$(pwd -P)\" \"$HOME\"",
    );
    cfg["process"]["cwd"] = json!("tmp");
    let result = run_platform_config_value("bwrap cwd relative", &cfg, &[], Some(launch.as_path()));
    let _ = fs::remove_dir_all(&launch);

    let out = result.combined_output();
    assert_eq!(result.code, Some(0), "run failed:\n{out}");
    assert!(
        out.contains("PWD=[/tmp]"),
        "a relative process.cwd should anchor to the sandbox root. Output:\n{out}"
    );
    assert!(
        out.contains("HOME=[/tmp]"),
        "HOME must name the directory the child actually started in. Output:\n{out}"
    );
}

/// Locks in that a command which does not exist fails the run instead of
/// reporting success or hanging.
///
/// The sandbox is torn down on the same path as a normal exit, so a shell that
/// never execs anything must still release the run. Termination is therefore
/// the property under test, and it is enforced by the harness deadline rather
/// than by an elapsed-time assertion: a run that never returns could not be
/// measured by one.
#[test]
fn bubblewrap_reports_a_missing_command() {
    if !ready() {
        return;
    }
    const DEADLINE: Duration = Duration::from_secs(30);

    let cfg = config("missing-command", "mxc-char-definitely-not-a-real-binary");
    let result = run_platform_config_value_within_duration(
        "bwrap missing command",
        &cfg,
        &[],
        None,
        DEADLINE,
    )
    .unwrap_or_else(|| {
        panic!("a missing command should fail promptly; it was still running after {DEADLINE:?}")
    });

    assert_ne!(
        result.code,
        Some(0),
        "a missing command should fail the run. Output:\n{}",
        result.combined_output()
    );
}

/// Locks in that an explicit `process.cwd` is honored (Bubblewrap emits
/// `--chdir` for a non-empty working directory). `/` always exists inside the
/// sandbox, so it is a stable target.
#[test]
fn bubblewrap_honors_explicit_process_cwd() {
    if !ready() {
        return;
    }
    let mut cfg = config("cwd-explicit", "pwd -P");
    cfg["process"]["cwd"] = json!("/");
    let result = run_platform_config_value("bwrap cwd explicit", &cfg, &[], None);
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert_eq!(
        result.stdout.trim(),
        "/",
        "expected child cwd to honor explicit process.cwd=/"
    );
}

/// Characterizes that a `process.timeout` shorter than the workload is
/// enforced, and that it takes a backgrounded descendant down with it.
///
/// The descendant is the load-bearing case: `bwrap` forks, so pid 1 of the
/// sandbox namespace is not the process the executor spawned. Killing that
/// handle tears the sandbox down only because `--die-with-parent` is set —
/// without it the descendant outlives the timeout, keeps writing to the
/// inherited stdout, and runs on after teardown has dropped its network
/// enforcement.
#[test]
fn bubblewrap_timeout_is_enforced() {
    if !ready() {
        return;
    }
    // Named so the assertion messages below cannot drift from the values they
    // describe when these are tuned.
    const TIMEOUT_MS: u64 = 1500;
    const DESCENDANT_SLEEP_SECS: u64 = 8;
    // Comfortably above the timeout and comfortably below the descendant's
    // lifetime, so a pass means teardown did not wait the descendant out.
    const MAX_ELAPSED: Duration = Duration::from_secs(6);

    let mut cfg = config(
        "timeout",
        &format!("echo CHAR_BEFORE; (/bin/sleep {DESCENDANT_SLEEP_SECS}; echo CHAR_AFTER) & wait"),
    );
    cfg["process"]["timeout"] = json!(TIMEOUT_MS);
    let started = Instant::now();
    let result = run_platform_config_value("bwrap timeout", &cfg, &[], None);
    let elapsed = started.elapsed();
    let out = result.combined_output();
    assert!(
        out.contains("CHAR_BEFORE"),
        "expected pre-timeout output. Output:\n{out}"
    );
    assert_ne!(
        result.code,
        Some(0),
        "a timed-out run should exit non-zero. Output:\n{out}"
    );
    assert!(
        !out.contains("CHAR_AFTER"),
        "the descendant outlived the timeout and wrote post-timeout output. \
         Output:\n{out}"
    );
    assert!(
        elapsed < MAX_ELAPSED,
        "a {TIMEOUT_MS}ms timeout should not wait out the {DESCENDANT_SLEEP_SECS}s \
         descendant; took {elapsed:?}"
    );
}

#[test]
fn bubblewrap_allows_common_socket_families() {
    if !ready() {
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        println!("SKIPPED: python3 is required for the Bubblewrap socket-family seccomp test");
        return;
    }

    let command = r#"python3 -c 'import socket
for family in (socket.AF_UNIX, socket.AF_INET):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.close()
print("ALLOWED_FAMILIES_OK")'"#;
    let result = run_platform_config_value(
        "bwrap allowed socket families",
        &config("allowed-socket-families", command),
        &[],
        None,
    );
    let output = result.combined_output();
    assert_eq!(
        result.code,
        Some(0),
        "allowed socket family creation failed:\n{output}"
    );
    assert!(
        output.contains("ALLOWED_FAMILIES_OK"),
        "allowed socket family probe did not finish:\n{output}"
    );
}

#[test]
fn bubblewrap_denies_unlisted_families_with_eperm() {
    if !ready() {
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        println!("SKIPPED: python3 is required for the Bubblewrap socket-family seccomp test");
        return;
    }

    // SAFETY: The call passes constant Linux socket arguments and checks the
    // returned descriptor.
    let control = unsafe { libc::socket(UNASSIGNED_FAMILY, libc::SOCK_STREAM, 0) };
    let control_errno = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default();
    if control >= 0 {
        // SAFETY: The descriptor was returned by the successful socket call above.
        unsafe { libc::close(control) };
    }
    assert!(
        control < 0 && control_errno != libc::EPERM,
        "unfiltered socket({UNASSIGNED_FAMILY}) must fail with something other than EPERM \
         so EPERM inside the sandbox proves the filter; got fd {control}, errno {control_errno}"
    );

    let command = format!(
        r#"python3 -c 'import errno, socket, sys
results = []
for name, create in (("SOCKET", socket.socket), ("SOCKETPAIR", socket.socketpair)):
    try:
        created = create({UNASSIGNED_FAMILY}, socket.SOCK_STREAM)
    except OSError as error:
        print(f"{{name}}_ERRNO={{error.errno}}")
        results.append(error.errno == errno.EPERM)
    else:
        print(f"{{name}}_ALLOWED")
        results.append(False)
sys.exit(0 if all(results) else 2)'"#
    );
    let result = run_platform_config_value(
        "bwrap unlisted family seccomp",
        &config("unlisted-family-seccomp", &command),
        &[],
        None,
    );
    let output = result.combined_output();
    assert_eq!(
        result.code,
        Some(0),
        "unlisted family was not denied with EPERM:\n{output}"
    );
    for call in ["SOCKET", "SOCKETPAIR"] {
        assert!(
            output.contains(&format!("{call}_ERRNO={}", libc::EPERM)),
            "expected exact EPERM from {call}:\n{output}"
        );
    }
}

#[test]
fn bubblewrap_denies_vsock_with_eperm() {
    if !ready() {
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        println!("SKIPPED: python3 is required for the Bubblewrap VSOCK seccomp test");
        return;
    }

    // SAFETY: The call passes constant Linux socket arguments and checks the
    // returned descriptor.
    let control = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if control < 0 {
        println!(
            "SKIPPED: unfiltered AF_VSOCK control failed with errno {}; the host cannot prove the filter caused EPERM",
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default()
        );
        return;
    }

    // SAFETY: The descriptor was returned by the successful socket call above.
    unsafe { libc::close(control) };

    let command = r#"python3 -c 'import errno, socket, sys
try:
    socket.socket(40, socket.SOCK_STREAM)
except OSError as error:
    print(f"AF_VSOCK_ERRNO={error.errno}")
    sys.exit(0 if error.errno == errno.EPERM else 2)
else:
    print("AF_VSOCK_ALLOWED")
    sys.exit(3)'"#;
    let result = run_platform_config_value(
        "bwrap vsock seccomp",
        &config("vsock-seccomp", command),
        &[],
        None,
    );
    let output = result.combined_output();
    assert_eq!(result.code, Some(0), "VSOCK filter failed:\n{output}");
    assert!(
        output.contains("AF_VSOCK_ERRNO=1"),
        "expected exact EPERM from AF_VSOCK:\n{output}"
    );
}

#[test]
fn bubblewrap_denies_io_uring_with_enosys() {
    if !ready() {
        return;
    }
    if Command::new("python3").arg("--version").output().is_err() {
        println!("SKIPPED: python3 is required for the Bubblewrap io_uring seccomp test");
        return;
    }

    let mut params = [0_u8; IO_URING_PARAMS_SIZE];
    // SAFETY: `params` is a zeroed buffer the size of `struct io_uring_params`,
    // and the returned descriptor is checked before use.
    let control =
        unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, params.as_mut_ptr()) } as libc::c_int;
    if control < 0 {
        println!(
            "SKIPPED: unfiltered io_uring_setup control failed with errno {}; the host cannot prove the filter caused ENOSYS",
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default()
        );
        return;
    }

    // SAFETY: The descriptor was returned by the successful io_uring_setup call above.
    unsafe { libc::close(control) };

    let command = format!(
        r#"python3 -c 'import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
params = ctypes.create_string_buffer({IO_URING_PARAMS_SIZE})
ring = libc.syscall({}, 1, params)
if ring >= 0:
    os.close(ring)
    print("IO_URING_ALLOWED")
    sys.exit(3)
error = ctypes.get_errno()
print(f"IO_URING_ERRNO={{error}}")
sys.exit(0 if error == errno.ENOSYS else 2)'"#,
        libc::SYS_io_uring_setup
    );
    let result = run_platform_config_value(
        "bwrap io_uring seccomp",
        &config("io-uring-seccomp", &command),
        &[],
        None,
    );
    let output = result.combined_output();
    assert_eq!(result.code, Some(0), "io_uring filter failed:\n{output}");
    assert!(
        output.contains(&format!("IO_URING_ERRNO={}", libc::ENOSYS)),
        "expected exact ENOSYS from io_uring_setup:\n{output}"
    );
}
