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

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-ping-allowed",
        "containment": "lxc",
        "process": { "commandLine": "ping -c 1 127.0.0.1" },
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

    let config = json!({
        "version": "0.9.0-alpha",
        "containerId": "lxc-ubuntu-no-network-loopback",
        "containment": "lxc",
        "process": { "commandLine": "ping -c 1 127.0.0.1" },
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
