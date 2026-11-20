// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_os = "linux")]

#[path = "support/wxc_e2e_tests.rs"]
mod wxc_e2e_tests;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wxc_e2e_tests::{has_lxc_host, has_platform_exec, run_platform_config_value};

/// Whether the LXC capability prerequisites are present.
fn ready() -> bool {
    has_platform_exec() && has_lxc_host()
}

#[test]
fn invalid_identity_mapping_configurations_are_rejected() {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    if !ready() {
        return;
    }

    for (case, mapping, succeeds, expected) in [
        (
            "shifted",
            "lxc.idmap = u 0 100000 65536\n\
             lxc.idmap = g 0 100000 65536",
            true,
            &[] as &[&str],
        ),
        (
            "host-root",
            "lxc.idmap = u 0 100000 65536\n\
             lxc.idmap = g 0 0 1\n\
             lxc.idmap = g 1 100001 65535",
            false,
            &["/gid_map:", "maps to outside ID 0"],
        ),
        (
            "host-root-user",
            "lxc.idmap = u 0 100000 1\n\
             lxc.idmap = u 1 0 1\n\
             lxc.idmap = u 2 100002 65534\n\
             lxc.idmap = g 0 100000 65536",
            false,
            &["/uid_map:", "maps to outside ID 0"],
        ),
        (
            "garbled",
            "lxc.idmap = g garbled",
            false,
            &[
                "Failed to parse id mappings",
                "Failed to parse config file",
                "lxc.idmap = g garbled",
            ],
        ),
    ] {
        let name = format!("lxc-idmap-{case}-{}", std::process::id());
        let outcome = std::panic::catch_unwind(|| {
            Command::new("lxc-create")
                .args([
                    "-n", &name, "-t", "download", "--", "-d", "alpine", "-r", "3.23", "-a",
                    "amd64",
                ])
                .status()
                .expect("create identity-map fixture");
            let definition = format!("/var/lib/lxc/{name}/config");
            let original = fs::read_to_string(&definition).expect("read identity-map fixture");
            let config = json!({
                "version": "0.9.0-alpha",
                "containerId": name,
                "containment": "lxc",
                "process": { "commandLine": "touch /mxc-idmap-workload-ran" },
                "lifecycle": { "destroyOnExit": false },
                "lxc": { "distribution": "alpine", "release": "3.23" }
            });
            let result = std::panic::catch_unwind(|| {
                let config_without_mappings = original
                    .lines()
                    .filter(|line| line.split('=').next().map(str::trim) != Some("lxc.idmap"))
                    .collect::<Vec<_>>()
                    .join("\n");
                fs::write(
                    &definition,
                    format!("{config_without_mappings}\n{mapping}\n"),
                )
                .expect("configure identity mapping");
                run_platform_config_value(case, &config, &[], None)
            });
            fs::write(&definition, original).expect("restore fixture definition for cleanup");
            let result = result.expect("run identity-map workload");
            let output = result.combined_output();
            assert!(
                result.code.is_some_and(|code| (code == 0) == succeeds),
                "{case} mapping: expected success={succeeds}, exit={:?}\n{output}",
                result.code
            );
            for message in expected {
                assert!(
                    output.contains(message),
                    "{case} mapping: missing diagnostic {message:?}\n{output}"
                );
            }

            let workload_ran = Path::new(&format!(
                "/var/lib/lxc/{name}/rootfs/mxc-idmap-workload-ran"
            ))
            .try_exists()
            .expect("observe identity-map workload marker");
            assert_eq!(
                workload_ran, succeeds,
                "{case} mapping: unexpected workload execution\n{output}"
            );

            let state = Command::new("lxc-info")
                .args(["-n", &name, "-s", "-H"])
                .output()
                .expect("observe retained identity-map container state");
            if !succeeds {
                assert!(
                    state.status.success(),
                    "{case} mapping: failed to read retained container state: {state:?}\n{output}"
                );
                assert_eq!(
                    String::from_utf8_lossy(&state.stdout).trim(),
                    "STOPPED",
                    "{case} mapping: rejected container is not stopped: {state:?}\n{output}"
                );
            }
        });
        let _ = Command::new("lxc-destroy")
            .args(["-n", &name, "-f"])
            .output();
        outcome.expect("identity-map fixture failed");
    }
}

#[test]
fn cancelling_startup_preserves_a_stopped_container() {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::{gettid, Pid};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::time::{Duration, Instant};
    use wxc_e2e_tests::run_platform_config_value_within_duration;

    if !ready() {
        return;
    }

    let fixture = tempfile::tempdir_in(".").expect("create startup fixture");
    let directory = fixture.path().canonicalize().expect("startup fixture path");
    let name = format!("lxc-cancel-startup-{}", std::process::id());
    let entered = directory.join("entered");
    let release = directory.join("release");
    let outcome = std::panic::catch_unwind(|| {
        let created = Command::new("lxc-create")
            .args([
                "-n", &name, "-t", "download", "--", "-d", "alpine", "-r", "3.23", "-a", "amd64",
            ])
            .output()
            .expect("create existing container");
        if !created.status.success() {
            panic!("container fixture creation failed: {created:?}");
        }
        let hook = directory.join("startup.sh");

        // Keep startup blocked until fixture cleanup.
        fs::write(
            &hook,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$PPID\" > '{}'\nwhile [ ! -e '{}' ]; do sleep 0.01; done\n",
                entered.display(),
                release.display()
            ),
        )
        .expect("write startup hook");
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))
            .expect("make hook executable");
        let definition = format!("/var/lib/lxc/{name}/config");
        let mut contents = fs::read_to_string(&definition).expect("read existing definition");
        contents.push_str(&format!(
            "\nlxc.tty.dir = lxc\nlxc.tty.max = 1\nlxc.hook.start-host = {}\n",
            hook.display()
        ));
        fs::write(&definition, contents).expect("install startup gate");
        let children = format!("/proc/self/task/{}/children", gettid());
        let canceller = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let monitor_pid = loop {
                if let Some(pid) = fs::read_to_string(&entered)
                    .ok()
                    .and_then(|pid| pid.trim().parse::<i32>().ok())
                {
                    break pid;
                }
                if Instant::now() >= deadline {
                    panic!("container did not reach the startup hook");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let pid = fs::read_to_string(children)
                .expect("read executor child PID")
                .trim()
                .parse::<i32>()
                .expect("one executor child");
            kill(Pid::from_raw(pid), Signal::SIGTERM).expect("cancel executor during startup");
            monitor_pid
        });
        let config = json!({
            "version": "0.9.0-alpha",
            "containerId": name,
            "containment": "lxc",
            "process": { "commandLine": "sleep 60" },
            "lifecycle": { "destroyOnExit": false },
            "lxc": { "distribution": "alpine", "release": "3.23" },
            "network": { "egress": { "default": "allow" } }
        });
        let result = run_platform_config_value_within_duration(
            "cancel persistent LXC startup",
            &config,
            &[],
            None,
            Duration::from_secs(40),
        );
        let monitor_pid = canceller.join().expect("startup cancellation thread");
        let monitor_reaped = !std::path::Path::new(&format!("/proc/{monitor_pid}"))
            .try_exists()
            .expect("observe startup monitor after cancellation");
        let state = Command::new("/usr/bin/timeout")
            .args(["--kill-after=1", "5", "lxc-info", "-n", &name, "-sH"])
            .output()
            .expect("read container state after cancellation");
        (result, state, monitor_reaped)
    });
    let _ = fs::write(directory.join("release"), "");
    let _ = Command::new("lxc-stop").args(["-n", &name, "-k"]).output();
    let _ = Command::new("lxc-destroy")
        .args(["-n", &name, "-f"])
        .output();
    let (result, state, monitor_reaped) = outcome.expect("startup cancellation fixture failed");

    assert!(
        result.is_some()
            && monitor_reaped
            && state.status.success()
            && String::from_utf8_lossy(&state.stdout).trim() == "STOPPED",
        "cancelling startup must reap the startup monitor and preserve a stopped container; \
         monitor_reaped={monitor_reaped}, state={state:?}, executor={result:?}"
    );
}

#[test]
fn failed_startup_waits_for_cleanup_after_one_minute() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if !ready() {
        return;
    }

    for (case, hook_body) in [
        ("immediate", "exit 1"),
        ("hung", "while [ ! -e \"$release\" ]; do sleep 0.01; done"),
    ] {
        let fixture = tempfile::tempdir_in(".").expect("create startup timeout fixture");
        let directory = fixture.path().canonicalize().expect("startup fixture path");
        let name = format!("lxc-timeout-startup-{case}-{}", std::process::id());
        let entered = directory.join("entered");
        let cleanup_entered = directory.join("cleanup-entered");
        let cleanup_finished = directory.join("cleanup-finished");
        let release = directory.join("release");
        let outcome = std::panic::catch_unwind(|| {
            let created = Command::new("lxc-create")
                .args([
                    "-n", &name, "-t", "download", "--", "-d", "alpine", "-r", "3.23", "-a",
                    "amd64",
                ])
                .output()
                .expect("create existing container");
            if !created.status.success() {
                panic!("container fixture creation failed: {created:?}");
            }
            let hook = directory.join("startup.sh");
            fs::write(
                &hook,
                format!(
                    "#!/bin/sh\ntouch '{}'\nrelease='{}'\n{hook_body}\n",
                    entered.display(),
                    release.display()
                ),
            )
            .expect("write startup hook");
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))
                .expect("make hook executable");
            let definition = format!("/var/lib/lxc/{name}/config");
            let mut contents = fs::read_to_string(&definition).expect("read existing definition");
            contents.push_str(&format!("\nlxc.hook.start-host = {}\n", hook.display()));
            fs::write(&definition, contents).expect("install startup gate");
            let destroy = directory.join("lxc-destroy");
            let original_path = std::env::var("PATH").expect("host command path");

            // Hold destruction past the startup deadline, then remove the container.
            fs::write(
                &destroy,
                format!(
                    "#!/bin/sh\ntouch '{}'\nwhile [ ! -e '{}' ]; do sleep 0.01; done\n\
                     PATH='{}' lxc-destroy \"$@\" && touch '{}'\n",
                    cleanup_entered.display(),
                    release.display(),
                    original_path,
                    cleanup_finished.display()
                ),
            )
            .expect("write delayed destruction tool");
            fs::set_permissions(&destroy, fs::Permissions::from_mode(0o700))
                .expect("make destruction tool executable");
            let path = format!("{}:{original_path}", directory.display());
            let config = json!({
                "version": "0.9.0-alpha",
                "containerId": name,
                "containment": "lxc",
                "process": { "commandLine": "echo WORKLOAD_RAN" },
                "lifecycle": { "destroyOnExit": true },
                "lxc": { "distribution": "alpine", "release": "3.23" },
                "network": { "egress": { "default": "allow" } }
            });
            let output_path = directory.join("executor-output");
            let output = fs::File::create(&output_path).expect("create executor output");
            let started = Instant::now();
            let mut executor =
                Command::new(wxc_e2e_tests::find_platform_exec().expect("find lxc-exec"))
                    .arg("--config-base64")
                    .arg(STANDARD.encode(config.to_string()))
                    .env("PATH", &path)
                    .stdin(Stdio::null())
                    .stdout(output.try_clone().expect("capture executor stdout"))
                    .stderr(output)
                    .spawn()
                    .expect("run LXC startup with delayed cleanup");
            while !cleanup_entered.exists()
                && started.elapsed() < Duration::from_secs(75)
                && executor.try_wait().expect("poll executor status").is_none()
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            let cleanup_started = cleanup_entered.exists();
            std::thread::sleep(Duration::from_secs(65));
            let running_during_cleanup = executor
                .try_wait()
                .expect("observe executor during cleanup")
                .is_none();
            fs::write(&release, "").expect("release delayed cleanup");
            let mut exited_before_cleanup = false;
            let executor_status = loop {
                if let Some(status) = executor.try_wait().expect("poll executor status") {
                    if cleanup_finished.exists() {
                        break Some(status);
                    }
                    exited_before_cleanup = true;
                }
                if started.elapsed() >= Duration::from_secs(200) {
                    let _ = executor.kill();
                    let _ = executor.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(25));
            };
            let output = fs::read_to_string(output_path).expect("read executor output");
            (
                executor_status,
                entered.exists(),
                cleanup_started,
                running_during_cleanup,
                exited_before_cleanup,
                !std::path::Path::new(&definition).exists(),
                output,
            )
        });
        let _ = fs::write(release, "");
        let _ = Command::new("lxc-stop").args(["-n", &name, "-k"]).output();
        let _ = Command::new("lxc-destroy")
            .args(["-n", &name, "-f"])
            .output();
        let (
            executor_status,
            hook_entered,
            cleanup_started,
            running_during_cleanup,
            exited_before_cleanup,
            container_destroyed,
            output,
        ) = outcome.expect("startup cleanup fixture failed");

        assert!(
            hook_entered
                && cleanup_started
                && running_during_cleanup
                && !exited_before_cleanup
                && executor_status.is_some_and(|status| !status.success())
                && container_destroyed
                && !output.contains("WORKLOAD_RAN"),
            "failed startup must wait for cleanup past one minute without running the workload; \
             case={case}, hook_entered={hook_entered}, cleanup_started={cleanup_started}, \
             running_during_cleanup={running_during_cleanup}, \
             exited_before_cleanup={exited_before_cleanup}, \
             container_destroyed={container_destroyed}, executor={executor_status:?}\n{output}"
        );
    }
}

#[test]
fn successful_startup_does_not_time_out_the_workload() {
    use std::process::Command;
    use std::time::Duration;
    use wxc_e2e_tests::run_platform_config_value_within_duration;

    if !ready() {
        return;
    }

    let name = format!("lxc-successful-startup-{}", std::process::id());
    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": name,
        "containment": "lxc",
        "process": { "commandLine": "sh -c 'sleep 65 && echo WORKLOAD_FINISHED'" },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "alpine", "release": "3.23" }
    });
    let result = run_platform_config_value_within_duration(
        "LXC successful startup with a long-running workload",
        &config,
        &[],
        None,
        Duration::from_secs(120),
    );
    let _ = Command::new("/usr/bin/timeout")
        .args(["--kill-after=1", "5", "lxc-stop", "-n", &name, "-k"])
        .output();
    let _ = Command::new("/usr/bin/timeout")
        .args(["--kill-after=1", "5", "lxc-destroy", "-n", &name, "-f"])
        .output();

    assert!(
        result.as_ref().is_some_and(|result| {
            result.code == Some(0) && result.combined_output().contains("WORKLOAD_FINISHED")
        }),
        "successful startup must not time out a workload lasting longer than one minute; \
         executor={result:?}"
    );
}

#[test]
fn unavailable_ipv6_firewall_refuses_network_startup() {
    use std::os::unix::fs::PermissionsExt;

    if !ready() {
        return;
    }

    if !std::path::Path::new("/proc/net/if_inet6").exists() {
        println!("SKIP: IPv6 is disabled; startup refusal with active IPv6 was not tested.");
        return;
    }

    let tools = tempfile::tempdir_in(".").expect("create firewall tool directory");
    let firewall = tools.path().join("ip6tables");
    std::fs::write(
        &firewall,
        "#!/bin/sh\necho IPV6_FIREWALL_UNAVAILABLE >&2\nexit 1\n",
    )
    .expect("write unavailable IPv6 firewall");
    std::fs::set_permissions(&firewall, std::fs::Permissions::from_mode(0o700))
        .expect("make firewall tool executable");
    let path = format!(
        "{}:{}",
        tools
            .path()
            .canonicalize()
            .expect("firewall tool path")
            .display(),
        std::env::var("PATH").expect("host command path")
    );
    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-ipv6-firewall-unavailable",
        "containment": "lxc",
        "process": { "commandLine": "echo WORKLOAD_RAN" },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "alpine", "release": "3.23" },
        "network": { "egress": { "default": "allow" } }
    });

    let result = run_platform_config_value(
        "unavailable IPv6 firewall",
        &config,
        &[("PATH", &path)],
        None,
    );

    assert!(
        result.code != Some(0)
            && !result.combined_output().contains("WORKLOAD_RAN")
            && result
                .combined_output()
                .contains("Cannot start a networked container without a working IPv6 firewall",),
        "network startup did not reject the unavailable IPv6 firewall\n{}",
        result.combined_output()
    );
}

#[tokio::test]
async fn workload_cannot_allow_a_denied_address() {
    if !ready() {
        return;
    }

    let listener = tokio::net::TcpListener::bind("10.0.3.1:0")
        .await
        .expect("bind local HTTP server");
    let address = listener.local_addr().expect("local HTTP address");
    let port = address.port();
    let mut server = tokio::task::JoinSet::new();
    server.spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept local HTTP request");
            let mut request = [0; 1024];
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut request))
                .await
                .expect("local HTTP request timed out")
                .expect("read local HTTP request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nLOCAL_HTTP",
                )
                .await
                .expect("send local HTTP response");
        }
    });

    let http_request = format!(
        r#"
with contextlib.closing(http.client.HTTPConnection("10.0.3.1", {port}, timeout=5)) as client:
    try:
        client.request("GET", "/")
        body = client.getresponse().read()
    except (PermissionError, TimeoutError) as error:
        if not expect_denial:
            raise
        print("HTTP_BLOCKED", repr(error))
    else:
        if expect_denial:
            raise RuntimeError("received an HTTP response from the denied address")
        assert body == b"LOCAL_HTTP", body
"#
    );

    let mut config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-denied-address-override",
        "containment": "lxc",
        "process": {
            "commandLine": format!(r#"python3 -c '
import contextlib, http.client, subprocess

expect_denial = False
subprocess.run(["apt-get", "update", "-qq"], check=True)
subprocess.run(["apt-get", "install", "-y", "-qq", "--no-install-recommends", "iptables"], check=True)
{http_request}'"#)
        },
        "lifecycle": { "destroyOnExit": false },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": { "egress": { "default": "allow" } }
    });

    let control_config = config.clone();
    let control = tokio::task::spawn_blocking(move || {
        run_platform_config_value("lxc denied address control", &control_config, &[], None)
    })
    .await
    .expect("allowed HTTP probe panicked");

    config["lifecycle"]["destroyOnExit"] = json!(true);
    config["network"]["egress"]["deny"] = json!([{ "to": [{ "cidr": "10.0.3.1/32" }] }]);
    config["process"]["commandLine"] = json!(format!(
        r#"python3 -c '
import contextlib, http.client, subprocess

expect_denial = True
for firewall in ("iptables-nft", "iptables-legacy"):
    subprocess.run([firewall, "--version"], check=True)

    # Prepend an allow rule for the denied destination.
    subprocess.run([firewall, "-I", "OUTPUT", "1", "-d", "10.0.3.1/32", "-j", "ACCEPT"], check=False)
{http_request}'"#
    ));

    let denied = tokio::task::spawn_blocking(move || {
        run_platform_config_value("lxc denied address override", &config, &[], None)
    })
    .await
    .expect("denied HTTP probe panicked");

    let mut connection = tokio::net::TcpStream::connect(address)
        .await
        .expect("local HTTP server stopped after denied request");
    connection
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("request local HTTP server after denied request");
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connection.read_to_string(&mut response),
    )
    .await
    .expect("local HTTP server timed out after denied request")
    .expect("read local HTTP response after denied request");
    server.shutdown().await;

    assert!(
        control.code == Some(0) && denied.code == Some(0) && response.ends_with("LOCAL_HTTP"),
        "expected the local HTTP control to reply and the denied address to stay unreachable after \
         firewall allow attempts\n--- control ({:?}) ---\n{}\n--- denied ({:?}) ---\n{}",
        control.code,
        control.combined_output(),
        denied.code,
        denied.combined_output()
    );
}

#[test]
fn workload_can_still_ping() {
    if !ready() {
        return;
    }

    // A packaged CAP_NET_RAW+ep ping cannot exec after the bounding-set drop.
    // Use a copy without file capabilities to exercise unprivileged ICMP.
    let command = "install -m 0755 \"$(command -v ping)\" /tmp/mxc-ping \
                   && /tmp/mxc-ping -c 1 127.0.0.1";

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-ping-allowed",
        "containment": "lxc",
        "process": { "commandLine": command },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{ "to": [{ "cidr": "198.51.100.2/32" }] }]
            }
        }
    });

    let result = run_platform_config_value("lxc ping allowed", &config, &[], None);

    assert_eq!(
        result.code,
        Some(0),
        "the workload could not ping after the capability drop\n{}",
        result.combined_output()
    );
}

#[test]
fn workload_cannot_open_a_raw_or_packet_socket() {
    if !ready() {
        return;
    }

    let probe = format!(
        "python3 -c '{}'",
        include_str!("support/raw_socket_probe.py")
    );

    // Use Ubuntu for python3.
    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-raw-socket-refusal",
        "containment": "lxc",
        "process": { "commandLine": probe },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{ "to": [{ "cidr": "198.51.100.2/32" }] }]
            }
        }
    });

    let result = run_platform_config_value("lxc raw socket refusal", &config, &[], None);
    let output = result.combined_output();

    assert!(
        output.contains("raw EPERM") && output.contains("packet EPERM"),
        "the workload opened a raw or packet socket the capability drop must refuse\n{output}"
    );
}

#[test]
fn workload_cannot_send_a_raw_packet() {
    if !ready() {
        return;
    }

    let probe = r#"python3 -c '
import errno, socket

# ICMP Echo request with its checksum.
echo_request = bytes.fromhex("0800f7ff00000000")
try:
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as raw:
        print("raw OPENED")
        print("raw SENT", raw.sendto(echo_request, ("127.0.0.1", 0)))
except OSError as error:
    print("raw", errno.errorcode[error.errno])
'"#;

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-raw-socket-send",
        "containment": "lxc",
        "process": { "commandLine": probe },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{ "to": [{ "cidr": "127.0.0.1/32" }] }]
            }
        }
    });

    let result = run_platform_config_value("lxc raw socket send", &config, &[], None);
    let output = result.combined_output();

    assert!(
        output.contains("raw EPERM"),
        "expected raw-packet creation or sending to be refused with EPERM\n{output}"
    );
}

#[test]
fn workload_cannot_write_host_core_pattern() {
    if !ready() {
        return;
    }

    let probe = r#"sh -c '
mount -o remount,bind,rw /proc/sys || exit 2
core_pattern=$(cat /proc/sys/kernel/core_pattern) || exit 2
! (printf "%s\n" "$core_pattern" > /proc/sys/kernel/core_pattern)
'"#;
    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-core-pattern-write",
        "containment": "lxc",
        "process": { "commandLine": probe },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": { "egress": { "default": "allow" } }
    });

    let result = run_platform_config_value("lxc core pattern write", &config, &[], None);

    assert_eq!(
        result.code,
        Some(0),
        "expected the core_pattern write to be refused after remounting /proc/sys read-write\n{}",
        result.combined_output()
    );
}

#[test]
fn alpine_filtered_network_uses_its_provided_resolver() {
    if !ready() {
        return;
    }

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-alpine-provided-resolver",
        "containment": "lxc",
        "process": { "commandLine": "nslookup -type=a localhost." },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "alpine", "release": "3.23" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{
                    "ports": [
                        { "protocol": "udp", "port": 53 },
                        { "protocol": "tcp", "port": 53 }
                    ]
                }]
            }
        }
    });

    let result = run_platform_config_value("lxc Alpine provided resolver", &config, &[], None);

    assert_eq!(
        result.code,
        Some(0),
        "Alpine could not resolve localhost using its provided resolver\n{}",
        result.combined_output()
    );
}

#[test]
fn ubuntu_filtered_network_uses_its_original_resolver() {
    if !ready() {
        return;
    }

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-ubuntu-original-resolver",
        "containment": "lxc",
        "process": { "commandLine": "getent -s dns ahostsv4 localhost." },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" },
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{
                    "ports": [
                        { "protocol": "udp", "port": 53 },
                        { "protocol": "tcp", "port": 53 }
                    ]
                }]
            }
        }
    });

    let result = run_platform_config_value("lxc Ubuntu original resolver", &config, &[], None);

    assert_eq!(
        result.code,
        Some(0),
        "Ubuntu could not resolve localhost using its original resolver symlink\n{}",
        result.combined_output()
    );
}

#[test]
fn ubuntu_without_network_can_ping_loopback() {
    if !ready() {
        return;
    }

    // Copy ping without its file capabilities to exercise unprivileged ICMP.
    let command = "install -m 0755 \"$(command -v ping)\" /tmp/mxc-ping \
                   && /tmp/mxc-ping -c 1 127.0.0.1";

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-ubuntu-no-network-loopback",
        "containment": "lxc",
        "process": { "commandLine": command },
        "lifecycle": { "destroyOnExit": true },
        "lxc": { "distribution": "ubuntu", "release": "noble" }
    });

    let result = run_platform_config_value("lxc Ubuntu no-network loopback", &config, &[], None);

    assert_eq!(
        result.code,
        Some(0),
        "Ubuntu could not ping loopback with no network section after the capability drop\n{}",
        result.combined_output()
    );
}

#[test]
fn retained_container_keeps_an_ipv4_address_with_no_local_expiry() {
    use std::process::Command;

    if !ready() {
        return;
    }

    let name = format!("lxc-ipv4-no-expiry-{}", std::process::id());
    let mut config = json!({
        "version": "0.9.0-alpha",
        "containerId": name,
        "containment": "lxc",
        "process": { "commandLine": "true" },
        "lifecycle": { "destroyOnExit": false },
        "lxc": { "distribution": "alpine", "release": "3.23" },
        "network": { "egress": { "default": "allow" } }
    });
    let outcome = std::panic::catch_unwind(|| {
        let result = run_platform_config_value("retain LXC IPv4 address", &config, &[], None);
        if result.code != Some(0) {
            panic!(
                "MXC could not run the retained container ({:?})\n{}",
                result.code,
                result.combined_output()
            );
        }
        let init = Command::new("lxc-info")
            .args(["-n", &name, "-pH"])
            .output()
            .expect("read retained container init PID");
        if !init.status.success() {
            panic!("lxc-info could not read the retained container init PID: {init:?}");
        }
        let pid = String::from_utf8_lossy(&init.stdout);
        let addresses = Command::new("nsenter")
            .args(["-t", pid.trim(), "-n", "--"])
            .args(["ip", "-j", "-4", "address", "show", "dev", "eth0"])
            .output()
            .expect("read retained container IPv4 lifetimes");
        if !addresses.status.success() {
            panic!("could not read retained container IPv4 lifetimes: {addresses:?}");
        }
        addresses
    });

    config["lifecycle"]["destroyOnExit"] = json!(true);
    let cleanup = run_platform_config_value("destroy LXC IPv4 fixture", &config, &[], None);
    if cleanup.code != Some(0) {
        panic!(
            "MXC could not destroy the retained container ({:?})\n{}",
            cleanup.code,
            cleanup.combined_output()
        );
    }
    let addresses = outcome.expect("inspect retained container IPv4 lifetimes");
    let addresses: serde_json::Value =
        serde_json::from_slice(&addresses.stdout).unwrap_or_else(|error| {
            panic!("could not parse retained container IPv4 lifetimes: {error}; {addresses:?}")
        });

    assert!(
        addresses[0]["addr_info"]
            .as_array()
            .unwrap_or_else(|| panic!("no IPv4 address entries in {addresses}"))
            .iter()
            .any(|address| {
                address["scope"] == "global"
                    && address["valid_life_time"] == json!(u32::MAX)
                    && address["preferred_life_time"] == json!(u32::MAX)
            }),
        "the retained container must keep a global IPv4 address with no local expiry\n{addresses}"
    );
}
