// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mxc_sdk::v1::{
    ContainerRequest, Containment, NetworkAction, NetworkEgressPolicy, NetworkPeerPolicy,
    NetworkPolicy, NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig,
    WaitResult,
};
use serde_json::{json, Value};

use super::windows_x64::assert_no_run_state;

const GREETING: &[u8] = b"NVX_DIRECT_OK";
const DIRECT_PROBE: &str = r#"import errno, json, os, socket
host = os.environ["MXC_NVX_NETWORK_HOST"]
ports = json.loads(os.environ["MXC_NVX_NETWORK_PORTS"])
def connect(port):
    try:
        connection = socket.create_connection((host, port), timeout=2)
    except OSError as error:
        if isinstance(error, TimeoutError) or error.errno in (
            errno.EACCES, errno.EPERM, errno.ENETUNREACH,
            errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.ETIMEDOUT
        ):
            return "blocked"
        raise
    with connection, connection.makefile("rb") as reader:
        assert reader.read(len(b"NVX_DIRECT_OK")) == b"NVX_DIRECT_OK"
    return "reached"
direct = [connect(port) for port in ports]
"#;

struct ControlledServices {
    host: Ipv4Addr,
    ports: [u16; 2],
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<io::Result<()>>>,
}

impl ControlledServices {
    fn new() -> Self {
        let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        // Select a local route without sending traffic to this documentation-only address.
        route
            .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
            .expect("network tests require a default IPv4 route");
        let host = match route.local_addr().unwrap().ip() {
            IpAddr::V4(host) if !host.is_loopback() && !host.is_unspecified() => host,
            address => {
                panic!("network tests require a non-loopback host IPv4 address, got {address}")
            }
        };
        assert_ne!(
            host.octets()[..3],
            [10, 0, 0],
            "the host endpoint must be outside the signed agent's fixed 10.0.0.0/24 guest network"
        );
        let listeners = [
            TcpListener::bind((host, 0)).unwrap(),
            TcpListener::bind((host, 0)).unwrap(),
        ];
        let ports = listeners
            .each_ref()
            .map(|listener| listener.local_addr().unwrap().port());
        let mut services = Self {
            host,
            ports,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
        };
        for listener in listeners {
            listener.set_nonblocking(true).unwrap();
            let stop = services.stop.clone();
            services.workers.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut connection, _)) => {
                            connection.set_nonblocking(false)?;
                            connection.set_write_timeout(Some(Duration::from_secs(5)))?;
                            connection.write_all(GREETING)?;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            }));
        }
        services
    }

    fn request(&self, script: &str, network: NetworkPolicy) -> ContainerRequest {
        ContainerRequest {
            containment: Containment::MicroVm {
                image: "python:3.12-alpine".to_owned(),
            },
            network: Some(network),
            environment: Some(vec![
                ("MXC_NVX_NETWORK_HOST".to_owned(), self.host.to_string()),
                (
                    "MXC_NVX_NETWORK_PORTS".to_owned(),
                    serde_json::to_string(&self.ports).unwrap(),
                ),
            ]),
            inherit_default_environment: Some(true),
            timeout_ms: Some(30_000),
            ..ContainerRequest::new(format!("python3 -c '{DIRECT_PROBE}\n{script}'"))
        }
    }

    fn probe(&self, egress: NetworkEgressPolicy) -> Value {
        let request = self.request(
            "print(json.dumps(direct))",
            NetworkPolicy {
                egress: Some(egress),
                ..Default::default()
            },
        );
        let result = mxc_sdk::v1::experimental::run(request, Default::default()).unwrap();
        assert_eq!(result.outcome, WaitResult::Exited(0), "{result:?}");
        assert_no_run_state(std::process::id());
        serde_json::from_slice(&result.stdout).expect("guest direct-connection outcomes")
    }

    fn rule(&self, port: Option<u16>) -> NetworkRulePolicy {
        NetworkRulePolicy {
            to: Some(vec![NetworkPeerPolicy::new(format!("{}/32", self.host))]),
            ports: port.map(|port| {
                vec![NetworkPortPolicy {
                    protocol: Some(NetworkProtocol::Tcp),
                    port: Some(port),
                    end_port: None,
                }]
            }),
        }
    }
}

impl Drop for ControlledServices {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let result = worker
                .join()
                .map_err(|panic| format!("service thread panicked: {panic:?}"))
                .and_then(|result| result.map_err(|error| format!("host service failed: {error}")));
            if thread::panicking() {
                if let Err(error) = result {
                    eprintln!("{error}");
                }
            } else {
                result.expect("controlled host service must remain healthy");
            }
        }
    }
}

fn allow_all() -> NetworkEgressPolicy {
    NetworkEgressPolicy {
        default: Some(NetworkAction::Allow),
        ..Default::default()
    }
}

#[test]
#[ignore = "VM: requires Windows x64, WHP, a host IPv4 route and the exact signed official bundle"]
fn signed_bundle_network_rules_enforce_allow_deny_and_port_selectors() {
    let services = ControlledServices::new();
    assert_eq!(services.probe(allow_all()), json!(["reached", "reached"]));
    for (label, policy, expected) in [
        (
            "only the first TCP port matches",
            NetworkEgressPolicy {
                allow: Some(vec![services.rule(Some(services.ports[0]))]),
                ..Default::default()
            },
            json!(["reached", "blocked"]),
        ),
        (
            "only the second TCP port matches",
            NetworkEgressPolicy {
                allow: Some(vec![services.rule(Some(services.ports[1]))]),
                ..Default::default()
            },
            json!(["blocked", "reached"]),
        ),
        (
            "explicit deny overrides the broad allow",
            NetworkEgressPolicy {
                allow: Some(vec![services.rule(None)]),
                deny: Some(vec![services.rule(Some(services.ports[0]))]),
                ..Default::default()
            },
            json!(["blocked", "reached"]),
        ),
        (
            "deny-default without an allow rule",
            NetworkEgressPolicy::default(),
            json!(["blocked", "blocked"]),
        ),
    ] {
        assert_eq!(services.probe(policy), expected, "{label}");
    }
    assert_eq!(services.probe(allow_all()), json!(["reached", "reached"]));
    println!("VM_EXECUTED reachable controls and network allow/deny/nonmatching-port enforcement");
}

#[test]
#[ignore = "VM: requires Windows x64, WHP, a host IPv4 route and the exact signed official bundle"]
fn signed_bundle_deny_default_proxy_policy() {
    let services = ControlledServices::new();
    assert_eq!(services.probe(allow_all()), json!(["reached", "reached"]));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || -> io::Result<Vec<u8>> {
        while !server_stop.load(Ordering::Acquire) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => return Err(error),
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                stream.read_exact(&mut byte)?;
                request.push(byte[0]);
            }
            if !request.ends_with(b"\r\n\r\n") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy request headers exceed 8192 bytes",
                ));
            }
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nNVX_PROXY_OK",
            )?;
            return Ok(request);
        }
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "workload did not reach the host proxy",
        ))
    });
    let request = services.request(
        r#"import urllib.request
data = urllib.request.urlopen("http://mxc-policy.invalid/probe", timeout=10).read()
assert data == b"NVX_PROXY_OK", data
print(json.dumps({"direct": direct, "proxy": data.decode()}))"#,
        NetworkPolicy {
            egress: Some(NetworkEgressPolicy::default()),
            runtime_config: Some(NetworkRuntimeConfig {
                network_proxy: Some(format!("http://127.0.0.1:{port}")),
            }),
            ..Default::default()
        },
    );
    let result = mxc_sdk::v1::experimental::run(request, Default::default());
    stop.store(true, Ordering::Release);
    let received = server.join().expect("host proxy thread");
    let result = result.expect("proxy-only guest execution");
    let received = received.expect("request must reach the host proxy");
    assert!(
        received.starts_with(b"GET http://mxc-policy.invalid/probe HTTP/1.1\r\n"),
        "{}",
        String::from_utf8_lossy(&received)
    );
    assert_eq!(result.outcome, WaitResult::Exited(0), "{result:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        json!({"direct": ["blocked", "blocked"], "proxy": "NVX_PROXY_OK"})
    );
    assert_no_run_state(std::process::id());
    assert_eq!(services.probe(allow_all()), json!(["reached", "reached"]));
    println!("VM_EXECUTED reachable controls, blocked direct egress and successful proxy traffic");
}
