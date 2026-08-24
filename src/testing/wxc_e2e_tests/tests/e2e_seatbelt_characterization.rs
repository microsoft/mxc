// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Seatbelt (macOS) executor **characterization** tests.
//!
//! These pin the run-to-completion behavior of the `mxc-exec-mac` executor
//! under the unified `SandboxBackend`/`Runner` design, exercised end-to-end.
//!
//! Two of them — `clears_host_env_when_process_env_empty` and
//! `runs_in_first_readwrite_path_when_process_cwd_empty` — assert behaviors the
//! unification deliberately changed from the pre-refactor executor: Seatbelt now
//! unconditionally `env_clear()`s and resolves an empty working directory to a
//! policy path. If they turn RED, the env/cwd model has drifted.
//!
//! They run in the existing macOS CI job (`cargo test --target
//! aarch64-apple-darwin`) with no extra infrastructure: `sandbox-exec` needs no
//! elevation. Each test skips cleanly if `mxc-exec-mac` has not been built.
#![cfg(target_os = "macos")]

use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::json;
use wxc_e2e_tests::{has_platform_exec, run_platform_config_value};

const SCHEMA_VERSION: &str = "0.7.0-alpha";

/// Build a one-shot config that omits `containment` so the binary selects its
/// OS-native backend (Seatbelt on macOS). `cwd`/`env`/`timeout` are optional.
fn config(label: &str, command_line: &str) -> serde_json::Value {
    json!({
        "version": SCHEMA_VERSION,
        "containerId": format!("char-seatbelt-{label}"),
        "process": { "commandLine": command_line }
    })
}

/// Create a unique temporary directory for cwd characterization.
fn unique_tempdir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mxc-char-{tag}-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn seatbelt_propagates_exit_code() {
    if !has_platform_exec() {
        return;
    }
    let result = run_platform_config_value(
        "seatbelt exit code",
        &config("exit-code", "exit 7"),
        &[],
        None,
    );
    assert_eq!(
        result.code,
        Some(7),
        "expected exit 7, got {:?}\n--- stderr ---\n{}",
        result.code,
        result.stderr
    );
}

#[test]
fn seatbelt_streams_stdout() {
    if !has_platform_exec() {
        return;
    }
    let result = run_platform_config_value(
        "seatbelt stdout",
        &config("stdout", "echo CHAR_SEATBELT_STDOUT_9f31a"),
        &[],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result
            .combined_output()
            .contains("CHAR_SEATBELT_STDOUT_9f31a"),
        "stdout missing sentinel:\n{}",
        result.combined_output()
    );
}

/// CHARACTERIZES CURRENT BEHAVIOR (regression guard).
///
/// With an empty `process.env`, the Seatbelt exec path starts the child from a
/// *cleared* environment (`env_clear()` plus a default `PATH`), so the
/// launcher's environment — which may hold cloud creds / API tokens — never
/// leaks into untrusted sandboxed code. This matches Bubblewrap's `--clearenv`
/// model (see `bubblewrap_clears_host_env_by_default`); if it ever turns RED the
/// env model has drifted.
#[test]
fn seatbelt_clears_host_env_when_process_env_empty() {
    if !has_platform_exec() {
        return;
    }
    let marker = "CHAR_SEATBELT_ENV_CLEAR_4b7c2";
    let result = run_platform_config_value(
        "seatbelt env clear",
        &config("env-clear", "printf 'MARKER=[%s]\\n' \"$MXC_CHAR_MARKER\""),
        &[("MXC_CHAR_MARKER", marker)],
        None,
    );
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    let out = result.combined_output();
    assert!(
        out.contains("MARKER=[]"),
        "expected a cleared env (MARKER=[]); the child must not inherit the \
         launcher's environment when process.env is empty. Output:\n{out}"
    );
    assert!(
        !out.contains(marker),
        "host env marker leaked into the sandbox. Output:\n{out}"
    );
}

/// Locks in that an explicitly requested `process.env` is honored (and, by
/// implication, that the env is scrubbed to exactly the request when set).
#[test]
fn seatbelt_applies_requested_env() {
    if !has_platform_exec() {
        return;
    }
    let mut cfg = config("env-set", "printf 'SET=[%s]\\n' \"$MXC_CHAR_SET\"");
    cfg["process"]["env"] = json!(["MXC_CHAR_SET=from_config_e21a"]);
    let result = run_platform_config_value("seatbelt env set", &cfg, &[], None);
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result.combined_output().contains("SET=[from_config_e21a]"),
        "expected requested env var to reach the child. Output:\n{}",
        result.combined_output()
    );
}

/// A configured `network.proxy` injects `HTTP_PROXY` / `HTTPS_PROXY` into the
/// sandboxed child (the cooperative env-var proxy model, matching Bubblewrap).
/// Uses the external `url` variant so no bundled proxy or `--allow-testing-features`
/// flag is required — this characterizes the env-injection wiring end-to-end.
#[test]
fn seatbelt_injects_proxy_env_from_network_proxy() {
    if !has_platform_exec() {
        return;
    }
    let mut cfg = config(
        "proxy-env",
        "printf 'P=[%s] S=[%s]\\n' \"$HTTP_PROXY\" \"$HTTPS_PROXY\"",
    );
    cfg["network"] = json!({
        "defaultPolicy": "block",
        "proxy": { "url": "http://127.0.0.1:8080" }
    });
    let result = run_platform_config_value("seatbelt proxy env", &cfg, &[], None);
    assert_eq!(result.code, Some(0), "stderr: {}", result.stderr);
    assert!(
        result
            .combined_output()
            .contains("P=[http://127.0.0.1:8080] S=[http://127.0.0.1:8080]"),
        "expected proxy env vars injected into the child. Output:\n{}",
        result.combined_output()
    );
}

/// CHARACTERIZES CURRENT BEHAVIOR (regression guard).
///
/// With an empty `process.cwd`, the Seatbelt exec path no longer inherits the
/// launcher's working directory (which the deny-by-default profile may forbid,
/// making the child's `getcwd()` fail and leak a "getcwd: Operation not
/// permitted" line). Instead it resolves the cwd to the first readwrite policy
/// path — a directory the profile is guaranteed to allow. `write_dir` is listed
/// first, so the relative-path probe lands there, not in the launcher cwd.
///
/// We observe the cwd by having the child create a file via a relative path
/// (a shell redirection) and checking which directory it lands in — this
/// avoids `pwd`/`realpath`, which the default Seatbelt profile denies for
/// arbitrary temp paths. `launch_dir` is a second writable policy path that is
/// *not* the resolved cwd, so the probe must not land there.
#[test]
fn seatbelt_runs_in_first_readwrite_path_when_process_cwd_empty() {
    if !has_platform_exec() {
        return;
    }
    let write_dir = fs::canonicalize(unique_tempdir("cwd-write")).expect("canonicalize");
    let launch_dir = fs::canonicalize(unique_tempdir("cwd-launch")).expect("canonicalize");
    let probe = "char_cwd_default_probe.txt";
    let mut cfg = config("cwd-default", &format!("echo CHAR_OK > {probe}"));
    cfg["filesystem"] = json!({
        "readwritePaths": [write_dir.to_string_lossy(), launch_dir.to_string_lossy()]
    });
    let result = run_platform_config_value("seatbelt cwd default", &cfg, &[], Some(&launch_dir));
    let in_launch = launch_dir.join(probe).exists();
    let in_write = write_dir.join(probe).exists();
    let _ = fs::remove_dir_all(&launch_dir);
    let _ = fs::remove_dir_all(&write_dir);
    assert_eq!(
        result.code,
        Some(0),
        "run failed:\n{}",
        result.combined_output()
    );
    assert!(
        in_write && !in_launch,
        "expected the probe in the first readwrite policy path {} (resolved cwd \
         with empty process.cwd); in_write={in_write} in_launch={in_launch}\n{}",
        write_dir.display(),
        result.combined_output()
    );
}

/// Locks in that an explicit `process.cwd` is honored.
#[test]
fn seatbelt_honors_explicit_process_cwd() {
    if !has_platform_exec() {
        return;
    }
    let dir = fs::canonicalize(unique_tempdir("cwd-explicit")).expect("canonicalize");
    let probe = "char_cwd_explicit_probe.txt";
    let mut cfg = config("cwd-explicit", &format!("echo CHAR_OK > {probe}"));
    cfg["process"]["cwd"] = json!(dir.to_string_lossy());
    cfg["filesystem"] = json!({ "readwritePaths": [dir.to_string_lossy()] });
    let result = run_platform_config_value("seatbelt cwd explicit", &cfg, &[], None);
    let exists = dir.join(probe).exists();
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        result.code,
        Some(0),
        "run failed:\n{}",
        result.combined_output()
    );
    assert!(
        exists,
        "expected the probe file in the explicit process.cwd {}\n{}",
        dir.display(),
        result.combined_output()
    );
}

/// Characterizes that a `process.timeout` shorter than the workload kills the
/// child mid-run: the pre-timeout marker is emitted, the post-timeout marker is
/// not, and the process exits non-zero well before the workload would finish.
#[test]
fn seatbelt_timeout_kills_before_completion() {
    if !has_platform_exec() {
        return;
    }
    let mut cfg = config("timeout", "echo CHAR_BEFORE; /bin/sleep 5; echo CHAR_AFTER");
    cfg["process"]["timeout"] = json!(1500);
    let result = run_platform_config_value("seatbelt timeout", &cfg, &[], None);
    let out = result.combined_output();
    assert!(
        out.contains("CHAR_BEFORE"),
        "expected pre-timeout output. Output:\n{out}"
    );
    assert!(
        !out.contains("CHAR_AFTER"),
        "workload should have been killed before completing. Output:\n{out}"
    );
    assert_ne!(result.code, Some(0), "timed-out run should not exit 0");
    assert!(
        result.wall_time_ms < 4500,
        "timeout should fire well before the 5s workload; took {}ms",
        result.wall_time_ms
    );
}

/// End-to-end guard for the macOS root-symlink resolution in
/// `seatbelt_common::profile_builder` (`resolve_macos_root_symlinks`).
///
/// On macOS `/var` is a symlink to `/private/var`, and Seatbelt matches
/// `subpath` filters against the **resolved** path, so a grant emitted as
/// `(subpath "/var/folders/…")` matches nothing at all. The ordinary spelling
/// of `$TMPDIR` (`_CS_DARWIN_USER_TEMP_DIR`) *is* `/var/folders/<a>/<b>/T/`,
/// so without that resolution a caller passing `$TMPDIR` straight through
/// gets a grant that silently never matches — the profile loads fine and the
/// access is still denied.
///
/// The resolution itself is unit-tested in the builder; this test exists
/// because those unit tests assert on the *generated profile text* and so
/// cannot show that the kernel actually honors it. It covers the two things
/// only a real sandbox launch can: that the profile still **loads** with the
/// rewritten rules, and that a write under the un-resolved path genuinely
/// **succeeds**.
///
/// It deliberately does **not** canonicalize the path. Every other filesystem
/// test in this file calls `fs::canonicalize` first, which resolves the
/// symlink itself — so none of them would notice this class of bug.
#[test]
fn seatbelt_honors_uncanonicalized_var_readwrite_path() {
    if !has_platform_exec() {
        return;
    }
    // `env::temp_dir()` returns the host's real per-user `$TMPDIR`, so this
    // needs no machine-specific container id — but only exercises the
    // regression when it is genuinely the un-resolved `/var` spelling.
    let temp_root = std::env::temp_dir();
    if !temp_root.starts_with("/var") {
        return;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = temp_root.join(format!("mxc-char-uncanon-{nanos}"));
    fs::create_dir_all(&dir).expect("create temp dir");

    let probe = "char_uncanon_probe.txt";
    let mut cfg = config("uncanon", &format!("echo CHAR_OK > {probe}"));
    cfg["process"]["cwd"] = json!(dir.to_string_lossy());
    cfg["filesystem"] = json!({ "readwritePaths": [dir.to_string_lossy()] });

    let result = run_platform_config_value("seatbelt uncanonicalized rw path", &cfg, &[], None);
    let exists = dir.join(probe).exists();
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        result.code,
        Some(0),
        "sandbox run failed for the un-resolved /var spelling of {} \
         (the profile must both load and grant the path):\n{}",
        dir.display(),
        result.combined_output()
    );
    assert!(
        exists,
        "expected the probe file under the un-resolved /var path {}; the grant \
         was emitted but never matched\n{}",
        dir.display(),
        result.combined_output()
    );
}

// ---------------------------------------------------------------------------
// Egress enforcement
//
// The tests above prove `HTTP_PROXY` is *injected*. These prove egress is
// actually *restricted* — a profile that emitted no rules at all would pass
// the env-injection test.
//
// Each case pairs a destination that must be reachable (a loopback endpoint,
// which the runtime proxy needs) with one that must not (a raw IP). Both the
// 0.8 directional shape and its legacy 0.7 twin are covered, since a test that
// only proves the new denial can't tell "correctly enforced" from "denies
// everyone".
//
// Raw IP, never a hostname: a blocked DNS lookup fails the same way a blocked
// connection does, so a hostname probe can't tell enforcement from a name
// resolution artifact. Each denial is gated on the same probe succeeding under
// an allow policy, so a runner with no outbound access skips instead of
// reporting a denial it never actually observed.
// ---------------------------------------------------------------------------

/// A destination that is reachable from a GitHub-hosted runner and is not
/// loopback, so a deny policy must block it.
const DENY_TARGET: &str = "1.1.1.1";
const DENY_TARGET_PORT: u16 = 443;

/// Loopback TCP listener standing in for the runtime proxy endpoint. It only
/// needs to accept a connection — Seatbelt filters at the socket layer, so
/// reachability is the whole of what the profile controls.
struct LoopbackEndpoint {
    port: u16,
    stop: Arc<AtomicBool>,
}

impl LoopbackEndpoint {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback endpoint");
        let port = listener.local_addr().expect("endpoint addr").port();
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                    }
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        Self { port, stop }
    }
}

impl Drop for LoopbackEndpoint {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Probe both destinations and print a marker for each outcome. Absolute paths
/// because the Seatbelt exec path clears the child's environment.
fn egress_probe(loopback_port: u16) -> String {
    format!(
        "if /usr/bin/nc -z -w 3 127.0.0.1 {loopback_port}; \
         then echo LOOPBACK_REACHABLE; else echo LOOPBACK_BLOCKED; fi; \
         if /usr/bin/nc -z -w 5 {DENY_TARGET} {DENY_TARGET_PORT}; \
         then echo DIRECT_REACHABLE; else echo DIRECT_BLOCKED; fi"
    )
}

/// Directional (0.8) config. `deny` needs the loopback runtime proxy, which is
/// the only egress Seatbelt permits under a deny default.
///
/// The allow variant states `ingress` explicitly: an omitted `hostLoopback` is
/// `deny`, which would close the loopback endpoint this probe uses as its
/// control. Seatbelt requires `hostLoopback` to equal `default`.
fn directional_config(label: &str, port: u16, default: &str) -> serde_json::Value {
    let mut cfg = json!({
        "version": "0.8.0-alpha",
        "containerId": format!("char-seatbelt-{label}"),
        "process": { "commandLine": egress_probe(port) },
        "network": { "egress": { "default": default } }
    });
    if default == "deny" {
        cfg["runtimeConfig"] = json!({ "networkProxy": format!("http://127.0.0.1:{port}") });
    } else {
        cfg["network"]["ingress"] = json!({ "default": "allow", "hostLoopback": "allow" });
    }
    cfg
}

/// Directional config pinning `network.ingress.hostLoopback` while egress stays
/// open, so the only thing under test is the host-loopback posture.
fn host_loopback_config(label: &str, port: u16, action: &str) -> serde_json::Value {
    json!({
        "version": "0.8.0-alpha",
        "containerId": format!("char-seatbelt-{label}"),
        "process": { "commandLine": egress_probe(port) },
        "network": {
            "egress": { "default": "allow" },
            "ingress": { "default": action, "hostLoopback": action }
        }
    })
}

/// Legacy (0.7) twin of [`directional_config`].
fn legacy_config(label: &str, port: u16, default_policy: &str) -> serde_json::Value {
    let mut cfg = config(label, &egress_probe(port));
    cfg["network"] = if default_policy == "block" {
        json!({
            "defaultPolicy": "block",
            "proxy": { "url": format!("http://127.0.0.1:{port}") }
        })
    } else {
        json!({ "defaultPolicy": "allow" })
    };
    cfg
}

/// Run the allow-policy twin and report whether the deny target was actually
/// reachable. When it isn't, the runner has no outbound access and a later
/// `DIRECT_BLOCKED` would be evidence of nothing.
fn deny_target_reachable_when_allowed(label: &str, cfg: &serde_json::Value) -> bool {
    let result = run_platform_config_value(label, cfg, &[], None);
    let output = result.combined_output();

    assert_eq!(
        result.code,
        Some(0),
        "{label} should run under an allow policy. Output:\n{output}"
    );
    assert!(
        output.contains("LOOPBACK_REACHABLE"),
        "{label}: loopback must be reachable under an allow policy. Output:\n{output}"
    );

    if output.contains("DIRECT_REACHABLE") {
        return true;
    }
    println!(
        "SKIPPED: {DENY_TARGET}:{DENY_TARGET_PORT} is unreachable from an allow-policy sandbox \
         on this host, so a denial would not be evidence of enforcement"
    );
    false
}

/// Assert the deny twin blocks the raw IP while keeping the proxy endpoint up.
fn assert_denies_direct_egress(label: &str, cfg: &serde_json::Value) {
    let result = run_platform_config_value(label, cfg, &[], None);
    let output = result.combined_output();

    assert_eq!(
        result.code,
        Some(0),
        "{label} should run to completion. Output:\n{output}"
    );
    assert!(
        output.contains("DIRECT_BLOCKED"),
        "{label}: direct egress to {DENY_TARGET}:{DENY_TARGET_PORT} must be blocked — it is \
         reachable under the allow twin, so this is enforcement, not an unreachable host. \
         Output:\n{output}"
    );
    assert!(
        output.contains("LOOPBACK_REACHABLE"),
        "{label}: the loopback proxy endpoint must stay reachable, otherwise the policy denies \
         everything and the proxy could never be used. Output:\n{output}"
    );
}

/// Schema 0.8 `network.egress.default: "deny"` restricts egress to the loopback
/// runtime proxy. This is the enforcement half of
/// `tests/examples/30_mac_network_schema_v2.json`, which CI cannot run because
/// it expects an externally supplied proxy.
#[test]
fn seatbelt_directional_deny_blocks_direct_egress() {
    if !has_platform_exec() {
        return;
    }
    let endpoint = LoopbackEndpoint::start();

    let allow = directional_config("dir-allow", endpoint.port, "allow");
    if !deny_target_reachable_when_allowed("seatbelt 0.8 egress allow", &allow) {
        return;
    }

    let deny = directional_config("dir-deny", endpoint.port, "deny");
    assert_denies_direct_egress("seatbelt 0.8 egress deny", &deny);
}

/// The legacy twin: 0.8 must not have changed what `defaultPolicy` callers get.
#[test]
fn seatbelt_legacy_block_blocks_direct_egress() {
    if !has_platform_exec() {
        return;
    }
    let endpoint = LoopbackEndpoint::start();

    let allow = legacy_config("legacy-allow", endpoint.port, "allow");
    if !deny_target_reachable_when_allowed("seatbelt 0.7 defaultPolicy allow", &allow) {
        return;
    }

    let block = legacy_config("legacy-block", endpoint.port, "block");
    assert_denies_direct_egress("seatbelt 0.7 defaultPolicy block", &block);
}

/// `network.ingress.hostLoopback: "deny"` must close the host's own loopback
/// even though egress is otherwise wide open.
///
/// Unlike the egress tests above, this one needs no reachable external host —
/// its control is a loopback listener this process owns — so it proves
/// enforcement on every macOS host instead of skipping on an offline one.
#[test]
fn seatbelt_host_loopback_deny_blocks_host_loopback() {
    if !has_platform_exec() {
        return;
    }
    let endpoint = LoopbackEndpoint::start();

    // Control: same policy but hostLoopback=allow, proving the endpoint is up
    // and that a denial below comes from the policy, not a dead listener.
    let allow = host_loopback_config("hl-allow", endpoint.port, "allow");
    let allow_result = run_platform_config_value("seatbelt hostLoopback allow", &allow, &[], None);
    let allow_output = allow_result.combined_output();
    assert_eq!(
        allow_result.code,
        Some(0),
        "hostLoopback=allow should run to completion. Output:\n{allow_output}"
    );
    assert!(
        allow_output.contains("LOOPBACK_REACHABLE"),
        "hostLoopback=allow must leave host loopback reachable. Output:\n{allow_output}"
    );

    let deny = host_loopback_config("hl-deny", endpoint.port, "deny");
    let deny_result = run_platform_config_value("seatbelt hostLoopback deny", &deny, &[], None);
    let deny_output = deny_result.combined_output();
    assert_eq!(
        deny_result.code,
        Some(0),
        "hostLoopback=deny should run to completion. Output:\n{deny_output}"
    );
    assert!(
        deny_output.contains("LOOPBACK_BLOCKED"),
        "hostLoopback=deny must block host loopback — it is reachable under the allow twin \
         above, so this is enforcement, not a dead listener. Output:\n{deny_output}"
    );
}
