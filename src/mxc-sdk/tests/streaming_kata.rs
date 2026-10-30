// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kata backend tests: streaming create-and-run execution, filesystem and
//! network policy, timeouts, the container lifecycle, and cleanup, on every
//! hypervisor the host is set up for.
//!
//! Linux-gated. The rejection tests need no Kata install and always run. The
//! live tests boot real microVMs, so they need root, `/dev/kvm`, a Kata
//! `runtime-rs` install, and a root filesystem; they skip when one is missing,
//! unless `MXC_KATA_TESTS_REQUIRE_EXECUTION` turns a skip into a failure.
//!
//! Environment:
//!
//! - `MXC_KATA_ROOT`: Kata install prefix (or `containerd-shim-kata-v2` on `PATH`).
//! - `MXC_KATA_TEST_ROOTFS`: directory holding a root filesystem with `sh`.
//! - `MXC_KATA_TEST_ROOTFS_IMAGE`: an ext4 image of the same root filesystem,
//!   required for Firecracker.
//! - `MXC_KATA_TEST_HYPERVISORS`: comma-separated subset of
//!   `qemu,clh,dragonball,firecracker`. Defaults to all four.
//! - `MXC_KATA_CONFIG_<HYPERVISOR>`: a Kata configuration file to use instead of
//!   the shipped one.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mxc_sdk::__ffi::{execute_lifecycle_json, run_lifecycle_json, spawn_container_json};
use mxc_sdk::v1::{Error, ErrorCode, WaitResult};
use serde_json::{json, Value};

/// A boot plus a teardown on a loaded host.
const LIVE_TIMEOUT: Duration = Duration::from_secs(180);

/// One live sandbox at a time: each owns a VM and the host's KVM.
fn exclusive() -> MutexGuard<'static, ()> {
    static LIVE_SANDBOX: Mutex<()> = Mutex::new(());
    LIVE_SANDBOX.lock().unwrap_or_else(|e| e.into_inner())
}

/// Reports a skip, or fails when this lane was provisioned to execute the suite.
fn not_ready(reason: &str) -> bool {
    if std::env::var("MXC_KATA_TESTS_REQUIRE_EXECUTION").is_ok_and(|value| value != "0") {
        panic!("strict mode: {reason}");
    }
    println!("SKIPPED: {reason}");
    false
}

fn hypervisors() -> Vec<String> {
    std::env::var("MXC_KATA_TEST_HYPERVISORS")
        .unwrap_or_else(|_| "qemu,clh,dragonball,firecracker".to_string())
        .split(',')
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

/// What a live test needs from the host for one hypervisor.
struct Live {
    hypervisor: String,
    /// The rootfs the request names: a directory, or an image for Firecracker.
    rootfs: PathBuf,
    state_dir: PathBuf,
}

fn shim_is_installed() -> bool {
    if let Some(root) = std::env::var_os("MXC_KATA_ROOT") {
        let root = PathBuf::from(root);
        return root
            .join("runtime-rs/bin/containerd-shim-kata-v2")
            .is_file()
            || root.join("bin/containerd-shim-kata-v2").is_file();
    }
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| dir.join("containerd-shim-kata-v2").is_file())
    })
}

/// Whether this host can boot a sandbox on `hypervisor`, and where.
fn live(hypervisor: &str) -> Option<Live> {
    // SAFETY: `geteuid` has no preconditions and no side effects.
    if unsafe { libc::geteuid() } != 0 {
        not_ready("the Kata backend needs root");
        return None;
    }
    if !Path::new("/dev/kvm").exists() {
        not_ready("/dev/kvm is missing; the Kata backend needs hardware virtualization");
        return None;
    }
    if !shim_is_installed() {
        not_ready("containerd-shim-kata-v2 was not found; set MXC_KATA_ROOT");
        return None;
    }
    let variable = if hypervisor == "firecracker" {
        "MXC_KATA_TEST_ROOTFS_IMAGE"
    } else {
        "MXC_KATA_TEST_ROOTFS"
    };
    let Some(rootfs) = std::env::var_os(variable).map(PathBuf::from) else {
        not_ready(&format!("{variable} is not set"));
        return None;
    };
    if !rootfs.exists() {
        not_ready(&format!(
            "{variable} names {}, which does not exist",
            rootfs.display()
        ));
        return None;
    }
    // Each test run keeps its sandboxes apart, so the leak audit sees only its own.
    let state_dir = PathBuf::from(format!("/run/mxc-kata-test-{}", std::process::id()));
    // SAFETY: tests that reach here hold `exclusive()`, so no other test thread
    // is reading or writing the environment.
    unsafe { std::env::set_var("MXC_KATA_STATE_DIR", &state_dir) };
    Some(Live {
        hypervisor: hypervisor.to_string(),
        rootfs,
        state_dir,
    })
}

fn kata_section(live: &Live) -> Value {
    json!({"rootfs": live.rootfs, "hypervisor": live.hypervisor})
}

fn one_shot(live: &Live, command: &str, extra: Value) -> String {
    let mut request = json!({
        "version": "1.1.0-alpha",
        "containment": "kata",
        "kata": kata_section(live),
        "process": {"commandLine": command},
    });
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        if key == "process" {
            for (inner_key, inner_value) in value.as_object().cloned().unwrap_or_default() {
                request["process"][inner_key] = inner_value;
            }
        } else {
            request[key] = value;
        }
    }
    request.to_string()
}

/// Runs a request to completion and returns its exit code, stdout, and stderr.
fn run(request: &str) -> (WaitResult, String, String) {
    let process = spawn_container_json(request, true)
        .unwrap_or_else(|e| panic!("the request was refused: {e:?}"));
    let result = process
        .wait_with_output()
        .unwrap_or_else(|e| panic!("waiting for the sandbox failed: {e}"));
    assert!(
        result.warnings.is_empty(),
        "cleanup reported: {:?}",
        result.warnings
    );
    (
        result.outcome,
        String::from_utf8_lossy(&result.stdout).into_owned(),
        String::from_utf8_lossy(&result.stderr).into_owned(),
    )
}

fn host_kernel() -> String {
    String::from_utf8_lossy(
        &std::process::Command::new("uname")
            .arg("-r")
            .output()
            .expect("uname runs")
            .stdout,
    )
    .trim()
    .to_string()
}

/// The command lines of the live processes that belong to Kata sandboxes: the
/// shim and the hypervisor.
fn sandbox_processes() -> Vec<String> {
    let mut running = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let path = entry.path();
        let Ok(cmdline) = std::fs::read(path.join("cmdline")) else {
            continue;
        };
        let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
        if !cmdline.contains("mxc-kata-") || cmdline.contains("streaming_kata") {
            continue;
        }
        let zombie = std::fs::read_to_string(path.join("stat")).is_ok_and(|stat| {
            stat.rsplit(')')
                .next()
                .is_some_and(|rest| rest.trim_start().starts_with('Z'))
        });
        if !zombie {
            running.push(cmdline);
        }
    }
    running
}

/// Fails when the sandbox left a VM, a mount, a namespace, a loop device, or a
/// directory behind. Every terminal path owes this.
fn assert_nothing_left(live: &Live) {
    let state = live.state_dir.display().to_string();

    let leftovers: Vec<_> = std::fs::read_dir(&live.state_dir)
        .map(|entries| entries.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "sandbox directories left in {state}: {leftovers:?}"
    );

    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let stale: Vec<_> = mountinfo
        .lines()
        .filter(|line| line.contains(&state) || line.contains("/mxc-kata-"))
        .collect();
    assert!(stale.is_empty(), "mounts left behind: {stale:?}");

    let running = sandbox_processes();
    assert!(running.is_empty(), "processes left running: {running:?}");

    let loops: Vec<_> = std::fs::read_dir("/sys/block")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("loop"))
        .filter_map(|e| std::fs::read_to_string(e.path().join("loop/backing_file")).ok())
        .filter(|backing| backing.contains(&state))
        .collect();
    assert!(loops.is_empty(), "loop devices left attached: {loops:?}");
}

// --- Requests the backend must refuse before it creates anything ---------------

fn refuse(request: Value, experimental: bool) -> Error {
    match spawn_container_json(&request.to_string(), experimental) {
        Ok(_) => panic!("the request must be refused: {request}"),
        Err(error) => error,
    }
}

#[test]
fn kata_refuses_what_it_cannot_enforce_before_creating_anything() {
    let dir = tempfile::tempdir().unwrap();
    let rootfs_dir = dir.path().join("rootfs");
    std::fs::create_dir(&rootfs_dir).unwrap();
    let base = |extra: Value| {
        let mut request = json!({
            "version": "1.1.0-alpha",
            "containment": "kata",
            "kata": {"rootfs": rootfs_dir, "hypervisor": "qemu"},
            "process": {"commandLine": "true"},
        });
        for (key, value) in extra.as_object().cloned().unwrap_or_default() {
            request[key] = value;
        }
        request
    };

    // Experimental backends need the caller's opt-in on the streaming path too.
    let error = refuse(base(json!({})), false);
    assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error:?}");
    assert!(error.message.contains("experimental"), "{error:?}");

    let cases = [
        (
            json!({"network": {"egress": {"default": "allow"}}}),
            "network.egress.default",
        ),
        (
            json!({"network": {"ingress": {"default": "allow"}}}),
            "network.ingress.default",
        ),
        (
            json!({"network": {"egress": {"default": "deny", "allow": [
                {"to": [{"cidr": "10.0.0.0/8"}], "ports": [{"protocol": "tcp", "port": 443}]}]}}}),
            "rules",
        ),
        (json!({"ui": {"disable": true}}), "ui policy"),
        (
            json!({"lifecycle": {"destroyOnExit": false}}),
            "destroyOnExit",
        ),
        (
            json!({"kata": {"rootfs": "/nonexistent/mxc/rootfs"}}),
            "/nonexistent/mxc/rootfs",
        ),
        (
            json!({"kata": {"rootfs": rootfs_dir, "hypervisor": "firecracker"}}),
            "ext4 image",
        ),
        (
            json!({"filesystem": {"readwritePaths": [dir.path()]},
                   "kata": {"rootfs": rootfs_dir, "hypervisor": "firecracker"}}),
            "no shared filesystem",
        ),
        (
            json!({"filesystem": {"readwritePaths": ["/nonexistent/mxc/grant"]}}),
            "does not exist",
        ),
    ];
    for (extra, expected) in cases {
        let error = refuse(base(extra.clone()), true);
        assert_eq!(
            error.code,
            ErrorCode::PolicyValidation,
            "{extra}: {error:?}"
        );
        assert!(error.message.contains(expected), "{extra}: {error:?}");
    }

    let error = refuse(
        json!({"version": "1.1.0-alpha", "containment": "kata",
               "process": {"commandLine": "true"}}),
        true,
    );
    assert_eq!(error.code, ErrorCode::PolicyValidation, "{error:?}");
    assert!(error.message.contains("kata section"), "{error:?}");

    // Nothing was provisioned for any of them.
    assert!(
        !Path::new("/run/mxc-kata").exists()
            || std::fs::read_dir("/run/mxc-kata").map_or(true, |mut e| e.next().is_none()),
        "a refused request left a sandbox directory"
    );
}

#[test]
fn kata_lifecycle_refuses_unknown_and_malformed_sandboxes() {
    let stale = run_lifecycle_json(
        r#"{"version":"1.1.0-alpha","phase":"stop","sandboxId":"kata:0a1b2c3d"}"#,
        false,
        true,
    )
    .expect_err("an unknown sandbox cannot be stopped");
    assert_eq!(stale.code, ErrorCode::StaleId, "{stale:?}");

    let malformed = run_lifecycle_json(
        r#"{"version":"1.1.0-alpha","phase":"stop","sandboxId":"kata:../../etc"}"#,
        false,
        true,
    )
    .expect_err("a path is not a sandbox id");
    assert_eq!(malformed.code, ErrorCode::MalformedId, "{malformed:?}");

    let not_opted_in = run_lifecycle_json(
        r#"{"version":"1.1.0-alpha","phase":"stop","sandboxId":"kata:0a1b2c3d"}"#,
        false,
        false,
    )
    .expect_err("experimental backends need the opt-in");
    assert_eq!(
        not_opted_in.code,
        ErrorCode::BackendUnavailable,
        "{not_opted_in:?}"
    );
}

// --- Create-and-run execution on each hypervisor --------------------------------

#[test]
fn kata_streams_stdio_runs_in_the_guest_kernel_and_has_no_network() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: streaming, guest kernel, network");

        let request = one_shot(
            &live,
            "uname -r; echo err-line >&2; read line; echo \"stdin=$line\"; \
             ls /sys/class/net; cat /proc/net/route; exit 7",
            json!({}),
        );
        let mut process = spawn_container_json(&request, true).expect("the sandbox starts");
        let mut stdin = process.take_stdin().expect("stdin is available");
        let mut stdout = process.take_stdout().expect("stdout is available");
        let mut stderr = process.take_stderr().expect("stderr is available");
        let out = std::thread::spawn(move || {
            let mut text = String::new();
            stdout.read_to_string(&mut text).unwrap();
            text
        });
        let err = std::thread::spawn(move || {
            let mut text = String::new();
            stderr.read_to_string(&mut text).unwrap();
            text
        });
        stdin.write_all(b"hello\n").unwrap();
        drop(stdin);
        let started = Instant::now();
        let outcome = process.wait().expect("the process is waited for");
        assert!(started.elapsed() < LIVE_TIMEOUT);
        let out = out.join().unwrap();
        let err = err.join().unwrap();

        assert_eq!(
            outcome,
            WaitResult::Exited(7),
            "{hypervisor}: {out:?} {err:?}"
        );
        let mut lines = out.lines();
        let guest_kernel = lines.next().unwrap_or_default();
        assert!(
            !guest_kernel.is_empty(),
            "{hypervisor}: no kernel in {out:?}"
        );
        assert_ne!(
            guest_kernel,
            host_kernel(),
            "{hypervisor}: the workload printed the host kernel, so it did not run in a VM"
        );
        assert_eq!(err.trim(), "err-line", "{hypervisor}");
        assert_eq!(lines.next(), Some("stdin=hello"), "{hypervisor}: {out:?}");
        // Deny-all: loopback is the only interface and the route table is empty.
        assert_eq!(lines.next(), Some("lo"), "{hypervisor}: {out:?}");
        let routes: Vec<_> = lines.collect();
        assert_eq!(
            routes.len(),
            1,
            "{hypervisor}: unexpected routes {routes:?}"
        );
        assert!(routes[0].starts_with("Iface"), "{hypervisor}: {routes:?}");

        assert_nothing_left(&live);
    }
}

#[test]
fn kata_input_a_workload_never_reads_cannot_outlive_it() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: unread input");

        let request = one_shot(&live, "sleep 3; exit 3", json!({}));
        let mut process = spawn_container_json(&request, true).expect("the sandbox starts");
        let mut stdin = process.take_stdin().expect("stdin is available");
        let (done, written) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(stdin.write_all(&vec![0u8; 32 << 20]));
        });
        let outcome = process.wait().expect("the wait is answered");
        assert_eq!(outcome, WaitResult::Exited(3), "{hypervisor}");
        let result = written
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or_else(|_| panic!("{hypervisor}: the write outlived the process"));
        assert!(result.is_err(), "{hypervisor}: unread input was accepted");
        drop(process);
        assert_nothing_left(&live);
    }
}

#[test]
fn kata_accepts_an_explicit_deny_all_network_policy() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: explicit deny-all network");
        let request = one_shot(
            &live,
            "ls /sys/class/net",
            json!({"network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "deny", "hostLoopback": "deny"}}}),
        );
        let (outcome, out, err) = run(&request);
        assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}: {err}");
        assert_eq!(out.trim(), "lo", "{hypervisor}");
        assert_nothing_left(&live);
    }
}

#[test]
fn kata_enforces_filesystem_policy() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: filesystem policy");

        if hypervisor == "firecracker" {
            // No shared filesystem: only the guest's own files can be denied.
            let request = one_shot(
                &live,
                "echo passwd-bytes=$(cat /etc/passwd | wc -c); ls /bin | head -n 1 | wc -l",
                json!({"filesystem": {"deniedPaths": ["/etc/passwd"]}}),
            );
            let (outcome, out, err) = run(&request);
            assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}: {err}");
            let mut lines = out.lines();
            assert_eq!(
                lines.next(),
                Some("passwd-bytes=0"),
                "{hypervisor}: {out:?}"
            );
            assert_eq!(
                lines.next().map(str::trim),
                Some("1"),
                "{hypervisor}: {out:?}"
            );
            assert_nothing_left(&live);
            continue;
        }

        let host = tempfile::tempdir_in("/tmp").unwrap();
        let base = host.path().canonicalize().unwrap();
        for dir in ["ro", "rw", "rw/private"] {
            std::fs::create_dir_all(base.join(dir)).unwrap();
        }
        std::fs::write(base.join("ro/readable.txt"), "from-host\n").unwrap();
        std::fs::write(base.join("rw/private/secret.txt"), "classified\n").unwrap();
        std::fs::write(base.join("rw/token.txt"), "classified\n").unwrap();
        let b = base.display();
        let request = one_shot(
            &live,
            &format!(
                "cat {b}/ro/readable.txt; \
                 (echo changed > {b}/ro/readable.txt) 2>/dev/null && echo ro-write=allowed \
                   || echo ro-write=denied; \
                 echo from-guest > {b}/rw/created.txt && echo rw-write=allowed; \
                 echo private-entries=$(ls {b}/rw/private | wc -l); \
                 echo token-bytes=$(cat {b}/rw/token.txt | wc -c)"
            ),
            json!({"filesystem": {
                "readonlyPaths": [format!("{b}/ro")],
                "readwritePaths": [format!("{b}/rw")],
                "deniedPaths": [format!("{b}/rw/private"), format!("{b}/rw/token.txt")]}}),
        );
        let (outcome, out, err) = run(&request);
        assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}: {err}");
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(
            lines,
            [
                "from-host",
                "ro-write=denied",
                "rw-write=allowed",
                "private-entries=0",
                "token-bytes=0"
            ],
            "{hypervisor}: {err}"
        );
        // The host agrees: the read-only file is untouched, the read-write
        // grant took the write, and the denied files were never changed.
        assert_eq!(
            std::fs::read_to_string(base.join("ro/readable.txt")).unwrap(),
            "from-host\n"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("rw/created.txt")).unwrap(),
            "from-guest\n"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("rw/token.txt")).unwrap(),
            "classified\n"
        );
        assert_nothing_left(&live);
    }
}

#[test]
fn kata_kills_a_workload_that_outlives_its_timeout() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: timeout");
        let request = one_shot(
            &live,
            "echo started; sleep 600",
            json!({"process": {"timeout": 3000}}),
        );
        let mut process = spawn_container_json(&request, true).expect("the sandbox starts");
        let mut stdout = process.take_stdout().expect("stdout");
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            stdout.read_to_string(&mut text).unwrap();
            text
        });
        let began = Instant::now();
        let outcome = process.wait().expect("the wait is answered");
        assert_eq!(outcome, WaitResult::TimedOut, "{hypervisor}");
        assert!(
            began.elapsed() < Duration::from_secs(60),
            "{hypervisor}: the timeout took {:?}",
            began.elapsed()
        );
        assert_eq!(reader.join().unwrap().trim(), "started", "{hypervisor}");
        drop(process);
        assert_nothing_left(&live);
    }
}

#[test]
fn kata_kill_and_drop_release_the_sandbox() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: kill and drop");

        let mut killed = spawn_container_json(&one_shot(&live, "sleep 600", json!({})), true)
            .expect("the sandbox starts");
        killed.kill().expect("the process is killed");
        let outcome = killed.wait().expect("the wait is answered");
        assert_eq!(
            outcome,
            WaitResult::Exited(137),
            "{hypervisor}: SIGKILL reports 128 + 9"
        );
        drop(killed);
        assert_nothing_left(&live);

        // A handle dropped with its workload still running owes the same cleanup.
        let abandoned = spawn_container_json(&one_shot(&live, "sleep 600", json!({})), true)
            .expect("the sandbox starts");
        drop(abandoned);
        assert_nothing_left(&live);
    }
}

#[test]
fn kata_reports_a_shim_failure_and_leaves_nothing_behind() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: shim failure");

        // A configuration the shim cannot load makes its create call fail
        // after the shim and the sandbox's resources exist.
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("bogus.toml");
        std::fs::write(&bogus, "this is not a Kata configuration\n").unwrap();
        let variable = format!("MXC_KATA_CONFIG_{}", hypervisor.to_uppercase());
        let saved = std::env::var_os(&variable);
        // SAFETY: tests that reach here hold `exclusive()`, so no other test
        // thread is reading or writing the environment.
        unsafe { std::env::set_var(&variable, &bogus) };
        let started = Instant::now();
        let result = spawn_container_json(&one_shot(&live, "true", json!({})), true);
        // SAFETY: as above.
        unsafe {
            match saved {
                Some(value) => std::env::set_var(&variable, value),
                None => std::env::remove_var(&variable),
            }
        }

        let error = result
            .err()
            .expect("the shim must refuse the configuration");
        assert_eq!(
            error.code,
            ErrorCode::BackendError,
            "{hypervisor}: {error:?}"
        );
        assert!(
            error.message.contains("could not create"),
            "{hypervisor}: {error:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{hypervisor}: the failure took {:?}",
            started.elapsed()
        );
        assert_nothing_left(&live);
    }
}

// --- A request that dies without cleaning up -------------------------------------

/// Runs a sandbox and waits to be killed. Only the test below starts it, in a
/// child process, because killing the test's own process would end the run.
#[test]
#[ignore = "helper process for kata_reclaims_a_sandbox_left_by_a_killed_request"]
fn kata_orphan_holder() {
    let hypervisor = std::env::var("MXC_KATA_ORPHAN_HYPERVISOR").expect("set by the parent test");
    let state_dir = std::env::var("MXC_KATA_ORPHAN_STATE_DIR").expect("set by the parent test");
    let Some(mut live) = live(&hypervisor) else {
        return;
    };
    live.state_dir = PathBuf::from(&state_dir);
    // SAFETY: this helper process runs a single test thread.
    unsafe { std::env::set_var("MXC_KATA_STATE_DIR", &state_dir) };
    let _process = spawn_container_json(&one_shot(&live, "echo up; sleep 600", json!({})), true)
        .expect("the sandbox starts");
    println!("orphan-ready");
    std::thread::sleep(Duration::from_secs(3600));
}

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn kata_reclaims_a_sandbox_left_by_a_killed_request() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: orphan reclaim");

        let mut child = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "kata_orphan_holder", "--ignored", "--nocapture"])
                .env("MXC_KATA_ORPHAN_HYPERVISOR", &hypervisor)
                .env("MXC_KATA_ORPHAN_STATE_DIR", &live.state_dir)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("the helper starts"),
        );
        let stdout = child.0.stdout.take().unwrap();
        let ready = std::thread::spawn(move || {
            BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
                .any(|line| line.contains("orphan-ready"))
        });
        let started = Instant::now();
        while !ready.is_finished() {
            assert!(
                started.elapsed() < LIVE_TIMEOUT,
                "{hypervisor}: the helper never became ready"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(
            ready.join().unwrap(),
            "{hypervisor}: the helper exited early"
        );

        // SIGKILL: the helper cannot clean up, so its VM keeps running.
        drop(child);
        assert!(
            !sandbox_processes().is_empty(),
            "{hypervisor}: the killed request's VM should still be running"
        );

        // The next request reclaims it before creating its own.
        let (outcome, _, err) = run(&one_shot(&live, "true", json!({})));
        assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}: {err}");
        assert_nothing_left(&live);
    }
}

// --- The container lifecycle ----------------------------------------------------

fn lifecycle(request: Value) -> Result<Value, Error> {
    run_lifecycle_json(&request.to_string(), false, true)
        .map(|text| serde_json::from_str(&text).expect("the envelope is JSON"))
}

fn exec_in(sandbox_id: &str, command: &str, timeout_ms: Option<u32>) -> (WaitResult, String) {
    let mut process = json!({"commandLine": command});
    if let Some(timeout) = timeout_ms {
        process["timeout"] = json!(timeout);
    }
    let request = json!({"version": "1.1.0-alpha", "phase": "exec",
                         "sandboxId": sandbox_id, "process": process});
    let mut handle = execute_lifecycle_json(&request.to_string(), true)
        .unwrap_or_else(|e| panic!("exec was refused: {e:?}"));
    let mut stdout = handle.take_stdout().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).unwrap();
        text
    });
    let outcome = handle.wait().expect("exec is waited for");
    let out = reader.join().unwrap();
    (outcome, out)
}

/// Runs `command` with `input` on its standard input, handed over as native
/// stdio, and returns how it ended and what it wrote.
fn exec_with_native_input(sandbox_id: &str, command: &str, input: &str) -> (WaitResult, String) {
    let request = json!({"version": "1.1.0-alpha", "phase": "exec",
                         "sandboxId": sandbox_id, "process": {"commandLine": command}});
    let mut handle = execute_lifecycle_json(&request.to_string(), true)
        .unwrap_or_else(|e| panic!("exec was refused: {e:?}"));
    let stdio = handle
        .take_native_stdio()
        .expect("native stdio is taken")
        .expect("native stdio is available");
    let mut stdin = std::fs::File::from(stdio.stdin.expect("stdin"));
    let mut stdout = std::fs::File::from(stdio.stdout.expect("stdout"));
    let reader = std::thread::spawn(move || {
        // Native stdout is non-blocking, so a read may find nothing yet.
        let (mut text, mut chunk) = (Vec::new(), [0u8; 4096]);
        let deadline = Instant::now() + LIVE_TIMEOUT;
        while Instant::now() < deadline {
            match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => text.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("reading the output: {e}"),
            }
        }
        String::from_utf8_lossy(&text).into_owned()
    });
    stdin.write_all(input.as_bytes()).expect("input is written");
    drop(stdin);
    let outcome = handle.wait().expect("exec is waited for");
    (outcome, reader.join().unwrap())
}

/// Releases a sandbox when a test fails part way, so one failure does not
/// strand a VM and fail every test after it.
struct ReleaseOnDrop(String);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        for phase in ["stop", "deprovision"] {
            let _ =
                lifecycle(json!({"version": "1.1.0-alpha", "phase": phase, "sandboxId": self.0}));
        }
    }
}

#[test]
fn kata_runs_the_container_lifecycle_and_keeps_the_writable_layer_across_a_restart() {
    for hypervisor in hypervisors() {
        let _guard = exclusive();
        let Some(live) = live(&hypervisor) else {
            continue;
        };
        println!("== {hypervisor}: lifecycle");

        let provisioned = lifecycle(json!({
            "version": "1.1.0-alpha", "phase": "provision", "containment": "kata",
            "kata": kata_section(&live),
            "network": {"egress": {"default": "deny"}},
        }))
        .expect("provision succeeds");
        let sandbox_id = provisioned["result"]["sandboxId"]
            .as_str()
            .unwrap_or_else(|| panic!("no sandboxId in {provisioned}"))
            .to_string();
        assert!(sandbox_id.starts_with("kata:"), "{sandbox_id}");
        let _release = ReleaseOnDrop(sandbox_id.clone());

        // Provisioned means resources are held but no VM runs.
        let error = execute_lifecycle_json(
            &json!({"version": "1.1.0-alpha", "phase": "exec", "sandboxId": sandbox_id,
                    "process": {"commandLine": "true"}})
            .to_string(),
            true,
        )
        .err()
        .expect("exec needs a started sandbox");
        assert_eq!(error.code, ErrorCode::NotStarted, "{error:?}");

        lifecycle(json!({"version": "1.1.0-alpha", "phase": "start", "sandboxId": sandbox_id}))
            .expect("start succeeds");
        let again =
            lifecycle(json!({"version": "1.1.0-alpha", "phase": "start", "sandboxId": sandbox_id}))
                .expect_err("a running sandbox cannot be started");
        assert_eq!(again.code, ErrorCode::AlreadyStarted, "{again:?}");

        let (outcome, out) = exec_in(
            &sandbox_id,
            "uname -r; echo kept > /root/marker; ls /sys/class/net",
            None,
        );
        assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}: {out:?}");
        let mut lines = out.lines();
        assert_ne!(
            lines.next().unwrap_or_default(),
            host_kernel(),
            "{hypervisor}"
        );
        assert_eq!(lines.next(), Some("lo"), "{hypervisor}");

        // Input handed over as native stdio reaches the process, and ends only
        // when the caller closes it.
        let (outcome, out) = exec_with_native_input(&sandbox_id, "cat", "from-caller");
        assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}: {out:?}");
        assert_eq!(out, "from-caller", "{hypervisor}");

        // Processes in one sandbox share its state; a timeout ends only its own.
        let (outcome, _) = exec_in(&sandbox_id, "sleep 600", Some(2000));
        assert_eq!(outcome, WaitResult::TimedOut, "{hypervisor}");
        let (outcome, out) = exec_in(&sandbox_id, "cat /root/marker", None);
        assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}");
        assert_eq!(out.trim(), "kept", "{hypervisor}");

        lifecycle(json!({"version": "1.1.0-alpha", "phase": "stop", "sandboxId": sandbox_id}))
            .expect("stop succeeds");
        let stopped =
            lifecycle(json!({"version": "1.1.0-alpha", "phase": "stop", "sandboxId": sandbox_id}))
                .expect_err("a stopped sandbox cannot be stopped again");
        assert_eq!(stopped.code, ErrorCode::AlreadyStopped, "{stopped:?}");

        // A provisioned sandbox keeps its writable layer, so a restart sees it.
        lifecycle(json!({"version": "1.1.0-alpha", "phase": "start", "sandboxId": sandbox_id}))
            .expect("restart succeeds");
        let (outcome, out) = exec_in(&sandbox_id, "cat /root/marker", None);
        assert_eq!(outcome, WaitResult::Exited(0), "{hypervisor}");
        assert_eq!(
            out.trim(),
            "kept",
            "{hypervisor}: the layer was lost across a restart"
        );

        // A running sandbox must be stopped before it is released.
        let running = lifecycle(
            json!({"version": "1.1.0-alpha", "phase": "deprovision", "sandboxId": sandbox_id}),
        )
        .expect_err("a running sandbox cannot be deprovisioned");
        assert_eq!(running.code, ErrorCode::AlreadyStarted, "{running:?}");

        lifecycle(json!({"version": "1.1.0-alpha", "phase": "stop", "sandboxId": sandbox_id}))
            .expect("stop succeeds");
        lifecycle(json!({"version": "1.1.0-alpha", "phase": "deprovision",
                         "sandboxId": sandbox_id}))
        .expect("deprovision succeeds");
        let gone =
            lifecycle(json!({"version": "1.1.0-alpha", "phase": "start", "sandboxId": sandbox_id}))
                .expect_err("a deprovisioned sandbox is gone");
        assert_eq!(gone.code, ErrorCode::StaleId, "{gone:?}");

        assert_nothing_left(&live);
    }
}

#[test]
fn kata_lifecycle_enforces_policy_fixed_at_provision() {
    let _guard = exclusive();
    let Some(live) = live(hypervisors().first().map(String::as_str).unwrap_or("qemu")) else {
        return;
    };
    // The hypervisor is irrelevant to a request refused before a VM exists.
    let refused = lifecycle(json!({
        "version": "1.1.0-alpha", "phase": "provision", "containment": "kata",
        "kata": kata_section(&live),
        "network": {"egress": {"default": "allow"}},
    }))
    .expect_err("allow-all egress cannot be enforced");
    assert_eq!(refused.code, ErrorCode::PolicyValidation, "{refused:?}");
    assert_nothing_left(&live);
}
