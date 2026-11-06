// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mxc_sdk::{__ffi, v1::WaitResult};
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

const DATAGRAM_PROBE: &str = r#"
nonce = os.environ["MXC_NVX_NETWORK_NONCE"].encode()
def datagram(port):
    payload = nonce + str(port).encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        try:
            client.sendto(payload, (host, port))
            reply, peer = client.recvfrom(1024)
        except OSError as error:
            if isinstance(error, TimeoutError) or error.errno in (
                errno.EACCES, errno.EPERM, errno.ENETUNREACH,
                errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.ETIMEDOUT
            ):
                return "blocked"
            raise
        assert peer == (host, port), peer
        assert reply == b"NVX_DIRECT_OK" + payload, reply
        return "reached"
print(json.dumps({"tcp": direct, "udp": [datagram(port) for port in ports]}))
"#;

struct ControlledServices {
    host: Ipv4Addr,
    ports: [u16; 2],
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<io::Result<()>>>,
    datagrams: [Arc<AtomicUsize>; 2],
}

fn bind_tcp_udp(
    host: Ipv4Addr,
    mut bind_tcp: impl FnMut((Ipv4Addr, u16)) -> io::Result<TcpListener>,
) -> io::Result<(TcpListener, UdpSocket)> {
    let mut last_error = String::new();
    for _ in 0..32 {
        // Windows can exclude different port ranges for TCP and UDP.
        let udp = UdpSocket::bind((host, 0))?;
        let port = udp.local_addr()?.port();
        match bind_tcp((host, port)) {
            Ok(tcp) => return Ok((tcp, udp)),
            Err(error) if matches!(error.raw_os_error(), Some(10013 | 10048)) => {
                last_error = format!("TCP {host}:{port}: {error}");
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!(
            "could not reserve a shared TCP/UDP port after 32 attempts; last error: {last_error}"
        ),
    ))
}

#[test]
fn host_only_controlled_ports_reserve_both_protocols_and_bound_retries() {
    let mut attempts = 0;
    let (tcp, udp) = bind_tcp_udp(Ipv4Addr::LOCALHOST, |address| {
        attempts += 1;
        if attempts == 1 {
            return Err(io::Error::from_raw_os_error(10013));
        }
        if attempts == 2 {
            let _occupied = TcpListener::bind(address)?;
            return TcpListener::bind(address);
        }
        TcpListener::bind(address)
    })
    .expect("retry excluded/conflicting TCP ports while reserving UDP first");
    assert!((3..=32).contains(&attempts));
    assert_eq!(tcp.local_addr().unwrap(), udp.local_addr().unwrap());

    attempts = 0;
    let error = bind_tcp_udp(Ipv4Addr::LOCALHOST, |_| {
        attempts += 1;
        Err(io::Error::from_raw_os_error(10013))
    })
    .unwrap_err();
    assert_eq!(attempts, 32);
    assert!(error.to_string().contains("after 32 attempts"));
    assert!(error.to_string().contains("10013"));

    attempts = 0;
    let error = bind_tcp_udp(Ipv4Addr::LOCALHOST, |_| {
        attempts += 1;
        Err(io::Error::from_raw_os_error(10022))
    })
    .unwrap_err();
    assert_eq!(attempts, 1);
    assert_eq!(error.raw_os_error(), Some(10022));
}

impl ControlledServices {
    fn new(with_udp: bool) -> Self {
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
        let bind = || {
            if with_udp {
                bind_tcp_udp(host, TcpListener::bind).map(|(tcp, udp)| (tcp, Some(udp)))
            } else {
                TcpListener::bind((host, 0)).map(|tcp| (tcp, None))
            }
        };
        let mut listeners = [
            bind().expect("reserve the first controlled endpoint"),
            bind().expect("reserve the second controlled endpoint"),
        ];
        listeners.sort_by_key(|(listener, _)| listener.local_addr().unwrap().port());
        let ports = listeners
            .each_ref()
            .map(|(listener, _)| listener.local_addr().unwrap().port());
        let mut services = Self {
            host,
            ports,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Vec::new(),
            datagrams: std::array::from_fn(|_| Arc::new(AtomicUsize::new(0))),
        };
        for (index, (listener, socket)) in listeners.into_iter().enumerate() {
            if let Some(socket) = socket {
                socket.set_nonblocking(true).unwrap();
                let stop = services.stop.clone();
                let received = services.datagrams[index].clone();
                services.workers.push(thread::spawn(move || {
                    let mut buffer = [0; 1024];
                    while !stop.load(Ordering::Acquire) {
                        match socket.recv_from(&mut buffer) {
                            Ok((length, peer)) => {
                                received.fetch_add(1, Ordering::Release);
                                let mut reply = GREETING.to_vec();
                                reply.extend_from_slice(&buffer[..length]);
                                socket.send_to(&reply, peer)?;
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

    fn request(&self, script: &str, network: Value, runtime_config: Option<Value>) -> Value {
        let mut request = json!({
            "version": "1.1.0-alpha",
            "containment": "microvm",
            "microvm": {"image": "docker.io/library/python:3.12-alpine"},
            "network": network,
            "process": {
                "commandLine": format!("python3 -c '{DIRECT_PROBE}\n{script}'"),
                "env": [
                    format!("MXC_NVX_NETWORK_HOST={}", self.host),
                    format!("MXC_NVX_NETWORK_PORTS={}", serde_json::to_string(&self.ports).unwrap())
                ],
                "inheritDefaultEnv": true,
                "timeout": 30000
            }
        });
        if let Some(runtime_config) = runtime_config {
            request["runtimeConfig"] = runtime_config;
        }
        request
    }

    fn probe(&self, egress: Value) -> Value {
        let request = self.request("print(json.dumps(direct))", json!({"egress": egress}), None);
        let result = __ffi::run_json(&request.to_string(), true).unwrap();
        assert_eq!(result.outcome, WaitResult::Exited(0), "{result:?}");
        assert_no_run_state(std::process::id());
        serde_json::from_slice(&result.stdout).expect("guest direct-connection outcomes")
    }

    fn rule(&self, port: Option<u16>) -> Value {
        let mut rule = json!({"to": [{"cidr": format!("{}/32", self.host)}]});
        if let Some(port) = port {
            rule["ports"] = json!([{"protocol": "tcp", "port": port}]);
        }
        rule
    }

    fn probe_network(&self, egress: Value, tcp: Value, udp: Value, label: &str) {
        let before = self
            .datagrams
            .each_ref()
            .map(|count| count.load(Ordering::Acquire));
        let mut request = self.request(DATAGRAM_PROBE, json!({"egress": egress}), None);
        request["process"]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!(
                "MXC_NVX_NETWORK_NONCE={}",
                uuid::Uuid::new_v4()
            )));
        let result = __ffi::run_json(&request.to_string(), true).unwrap();
        assert_no_run_state(std::process::id());
        assert_eq!(result.outcome, WaitResult::Exited(0), "{label}: {result:?}");
        assert_eq!(
            serde_json::from_slice::<Value>(&result.stdout).expect("TCP/UDP outcomes"),
            json!({"tcp": tcp, "udp": udp}),
            "{label}"
        );
        for (index, count) in self.datagrams.iter().enumerate() {
            assert_eq!(
                count.load(Ordering::Acquire) - before[index],
                usize::from(udp[index] == "reached"),
                "{label}: UDP endpoint {} delivery count",
                self.ports[index]
            );
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

fn allow_all() -> Value {
    json!({"default": "allow"})
}

#[test]
#[ignore = "VM: requires Windows x64, WHP, a host IPv4 route and the exact signed official bundle"]
fn signed_bundle_network_rules_enforce_allow_deny_and_port_selectors() {
    let services = ControlledServices::new(true);
    let reached = json!(["reached", "reached"]);
    let blocked = json!(["blocked", "blocked"]);
    services.probe_network(
        allow_all(),
        reached.clone(),
        reached.clone(),
        "before control",
    );
    let [low, high] = services.ports;
    let port_range = |start, end| {
        let mut rule = services.rule(None);
        rule["ports"] = json!([{"protocol": "tcp", "port": start, "endPort": end}]);
        rule
    };
    let protocol_rule = |protocol: &str| {
        let mut rule = services.rule(None);
        rule["ports"] = json!([{"protocol": protocol, "port": low, "endPort": high}]);
        rule
    };
    let nonmatching_host = Ipv4Addr::from(u32::from(services.host) ^ 1);
    for (label, policy, tcp, udp) in [
        (
            "only the first TCP port matches",
            json!({"allow": [services.rule(Some(services.ports[0]))]}),
            json!(["reached", "blocked"]),
            blocked.clone(),
        ),
        (
            "only the second TCP port matches",
            json!({"allow": [services.rule(Some(services.ports[1]))]}),
            json!(["blocked", "reached"]),
            blocked.clone(),
        ),
        (
            "explicit deny overrides the broad allow",
            json!({"allow": [services.rule(None)], "deny": [services.rule(Some(services.ports[0]))]}),
            json!(["blocked", "reached"]),
            reached.clone(),
        ),
        (
            "TCP protocol matches both TCP endpoints",
            json!({"allow": [protocol_rule("tcp")]}),
            json!(["reached", "reached"]),
            blocked.clone(),
        ),
        (
            "UDP protocol does not grant TCP connections",
            json!({"allow": [protocol_rule("udp")]}),
            json!(["blocked", "blocked"]),
            reached.clone(),
        ),
        (
            "any protocol includes both TCP endpoints",
            json!({"allow": [protocol_rule("any")]}),
            json!(["reached", "reached"]),
            reached.clone(),
        ),
        (
            "a nonmatching destination CIDR grants neither reachable endpoint",
            json!({"allow": [{"to": [{"cidr": format!("{nonmatching_host}/32")}]}]}),
            json!(["blocked", "blocked"]),
            blocked.clone(),
        ),
        (
            "a matching destination CIDR reaches both endpoints",
            json!({"allow": [{"to": [{"cidr": "0.0.0.0/0"}]}]}),
            json!(["reached", "reached"]),
            reached.clone(),
        ),
        (
            "except excludes the reachable host from a matching CIDR",
            json!({"allow": [{"to": [{
                "cidr": "0.0.0.0/0",
                "except": [format!("{}/32", services.host)]
            }]}]}),
            json!(["blocked", "blocked"]),
            blocked.clone(),
        ),
        (
            "both inclusive TCP range endpoints are reachable",
            json!({"allow": [port_range(low, high)]}),
            json!(["reached", "reached"]),
            blocked.clone(),
        ),
        (
            "the lower TCP port is outside the range",
            json!({"allow": [port_range(low + 1, high)]}),
            json!(["blocked", "reached"]),
            blocked.clone(),
        ),
        (
            "the upper TCP port is outside the range",
            json!({"allow": [port_range(low, high - 1)]}),
            json!(["reached", "blocked"]),
            blocked.clone(),
        ),
        (
            "only the first UDP port matches",
            json!({"allow": [{
                "to": [{"cidr": format!("{}/32", services.host)}],
                "ports": [{"protocol": "udp", "port": low}]
            }]}),
            blocked.clone(),
            json!(["reached", "blocked"]),
        ),
        (
            "only the second UDP port matches",
            json!({"allow": [{
                "to": [{"cidr": format!("{}/32", services.host)}],
                "ports": [{"protocol": "udp", "port": high}]
            }]}),
            blocked.clone(),
            json!(["blocked", "reached"]),
        ),
        (
            "UDP deny overrides the broad allow without denying TCP",
            json!({"allow": [services.rule(None)], "deny": [{
                "to": [{"cidr": format!("{}/32", services.host)}],
                "ports": [{"protocol": "udp", "port": low, "endPort": high}]
            }]}),
            reached.clone(),
            blocked.clone(),
        ),
        (
            "the lower UDP port is outside the range",
            json!({"allow": [{
                "to": [{"cidr": format!("{}/32", services.host)}],
                "ports": [{"protocol": "udp", "port": low + 1, "endPort": high}]
            }]}),
            blocked.clone(),
            json!(["blocked", "reached"]),
        ),
        (
            "the upper UDP port is outside the range",
            json!({"allow": [{
                "to": [{"cidr": format!("{}/32", services.host)}],
                "ports": [{"protocol": "udp", "port": low, "endPort": high - 1}]
            }]}),
            blocked.clone(),
            json!(["reached", "blocked"]),
        ),
        (
            "deny-default without an allow rule",
            json!({}),
            json!(["blocked", "blocked"]),
            blocked.clone(),
        ),
    ] {
        services.probe_network(policy, tcp, udp, label);
    }
    services.probe_network(allow_all(), reached.clone(), reached, "after control");
    println!("VM_EXECUTED reachable controls and network allow/deny/nonmatching-port enforcement");
    println!("VM_EXECUTED UDP datagrams replies delivery counts protocol separation and inclusive ranges");
}

const INGRESS_LISTENER: &str = r#"import json, os, pathlib, socket, threading, time
directory = pathlib.Path(os.environ["MXC_NVX_INGRESS_DIRECTORY"])
nonce = os.environ["MXC_NVX_INGRESS_NONCE"].encode()
ports = json.loads(os.environ["MXC_NVX_INGRESS_PORTS"])
stop = threading.Event()
errors = []
hits = [0, 0]
tcp = socket.socket()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp.bind(("0.0.0.0", ports[0]))
tcp.listen(8)
udp.bind(("0.0.0.0", ports[1]))
tcp.settimeout(0.1)
udp.settimeout(0.1)
def serve(index, listener):
    try:
        while not stop.is_set():
            try:
                if index == 0:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(2)
                        with connection.makefile("rb") as reader:
                            payload = reader.read(len(nonce) + 1)
                        assert payload in (b"H" + nonce, b"L" + nonce), payload
                        hits[index] += int(payload == b"H" + nonce)
                        connection.sendall(b"NVX_INGRESS:" + payload)
                else:
                    payload, peer = listener.recvfrom(1024)
                    assert payload in (b"H" + nonce, b"L" + nonce), payload
                    hits[index] += int(payload == b"H" + nonce)
                    listener.sendto(b"NVX_INGRESS:" + payload, peer)
            except socket.timeout:
                continue
    except Exception as error:
        errors.append(repr(error))
workers = [threading.Thread(target=serve, args=(i, s)) for i, s in enumerate((tcp, udp))]
for worker in workers:
    worker.start()
def local_control():
    payload = b"L" + nonce
    with socket.create_connection(("127.0.0.1", ports[0]), timeout=2) as client:
        client.sendall(payload)
        with client.makefile("rb") as reader:
            assert reader.read(len(b"NVX_INGRESS:") + len(payload)) == b"NVX_INGRESS:" + payload
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(payload, ("127.0.0.1", ports[1]))
        reply, peer = client.recvfrom(1024)
        assert peer == ("127.0.0.1", ports[1]), peer
        assert reply == b"NVX_INGRESS:" + payload, reply
try:
    local_control()
    ready = directory / "ready.tmp"
    ready.write_text(json.dumps({"ports": ports, "local": "reached"}))
    ready.replace(directory / "ready")
    deadline = time.monotonic() + 45
    while not (directory / "stop").exists():
        assert not errors, errors
        assert time.monotonic() < deadline, "host did not stop the ingress probe"
        time.sleep(0.05)
    local_control()
finally:
    stop.set()
    for worker in workers:
        worker.join()
    tcp.close()
    udp.close()
assert not errors, errors
print(json.dumps({"hits": hits, "local_before": "reached", "local_after": "reached"}))
"#;

fn ingress_probe(port: u16, udp: bool, payload: &[u8]) -> io::Result<bool> {
    let address = (Ipv4Addr::LOCALHOST, port);
    let mut expected = b"NVX_INGRESS:".to_vec();
    expected.extend_from_slice(payload);
    let received = if udp {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_read_timeout(Some(Duration::from_millis(300)))?;
        socket.connect(address)?;
        socket.send(payload)?;
        let mut reply = [0; 1024];
        socket
            .recv(&mut reply)
            .map(|length| reply[..length].to_vec())
    } else {
        TcpStream::connect_timeout(&address.into(), Duration::from_millis(300)).and_then(
            |mut connection| {
                connection.set_read_timeout(Some(Duration::from_millis(300)))?;
                connection.set_write_timeout(Some(Duration::from_millis(300)))?;
                connection.write_all(payload)?;
                let mut reply = vec![0; expected.len()];
                connection.read_exact(&mut reply)?;
                Ok(reply)
            },
        )
    };
    match received {
        Ok(reply) if reply == expected => Ok(true),
        Ok(reply) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected host-loopback reply: {reply:?}"),
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn host_loopback_case(ports: [u16; 2], posture: &str, egress: &str) {
    let directory = tempfile::tempdir().expect("owned ingress coordination directory");
    let canonical = directory.path().canonicalize().unwrap();
    let host_path = canonical.to_str().unwrap();
    let drive_path = host_path.strip_prefix(r"\\?\").unwrap_or(host_path);
    assert_eq!(&drive_path[1..3], ":\\");
    let guest_path = format!(
        "/mnt/{}/{}",
        drive_path[..1].to_ascii_lowercase(),
        drive_path[3..].replace('\\', "/")
    );
    let nonce = uuid::Uuid::new_v4().to_string();
    let request = json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "microvm": {"image": "docker.io/library/python:3.12-alpine"},
        "filesystem": {"readwritePaths": [host_path]},
        "network": {
            "egress": {"default": egress},
            "ingress": {"default": "deny", "hostLoopback": posture}
        },
        "process": {
            "commandLine": format!("python3 -c '{INGRESS_LISTENER}'"),
            "inheritDefaultEnv": true,
            "env": [
                format!("MXC_NVX_INGRESS_DIRECTORY={guest_path}"),
                format!("MXC_NVX_INGRESS_NONCE={nonce}"),
                format!("MXC_NVX_INGRESS_PORTS={}", serde_json::to_string(&ports).unwrap())
            ],
            "timeout": 60000
        }
    });
    let (observed, stopped, result) = thread::scope(|scope| {
        let worker = scope.spawn(|| __ffi::run_json(&request.to_string(), true));
        let observed = (|| -> Result<[bool; 2], Box<dyn std::error::Error>> {
            let ready = directory.path().join("ready");
            let deadline = Instant::now() + Duration::from_secs(120);
            while !ready.try_exists()? {
                if worker.is_finished() || Instant::now() >= deadline {
                    return Err("guest listeners did not become ready".into());
                }
                thread::sleep(Duration::from_millis(50));
            }
            let readiness: Value = serde_json::from_slice(&std::fs::read(ready)?)?;
            if readiness != json!({"ports": ports, "local": "reached"}) {
                return Err(format!("invalid guest listener readiness: {readiness}").into());
            }
            // The pinned nvx-ingress helper settles UDP listeners for one second.
            thread::sleep(Duration::from_millis(1500));
            let payload = format!("H{nonce}");
            let mut reached = [false; 2];
            for (index, port) in ports.into_iter().enumerate() {
                let deadline =
                    Instant::now() + Duration::from_secs(if posture == "allow" { 8 } else { 3 });
                while Instant::now() < deadline {
                    if ingress_probe(port, index == 1, payload.as_bytes())? {
                        reached[index] = true;
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
            Ok(reached)
        })();
        let stopped = std::fs::write(directory.path().join("stop"), b"stop");
        (observed, stopped, worker.join())
    });
    let result = result
        .expect("guest ingress execution thread")
        .expect("guest ingress execution");
    assert_no_run_state(std::process::id());
    stopped.expect("stop the guest listeners");
    assert_eq!(result.outcome, WaitResult::Exited(0), "{result:?}");
    let observed = observed.expect("ready guest listeners and bounded host probes");
    let allowed = posture == "allow";
    assert_eq!(
        observed, [allowed; 2],
        "hostLoopback={posture}, egress={egress}"
    );
    let guest: Value = serde_json::from_slice(&result.stdout).expect("guest ingress outcomes");
    assert_eq!(guest["local_before"], "reached");
    assert_eq!(guest["local_after"], "reached");
    for index in 0..2 {
        let hits = guest["hits"][index].as_u64().expect("guest delivery count");
        if allowed {
            assert!(hits > 0, "host reply without guest delivery: {guest}");
        } else {
            assert_eq!(hits, 0, "denied host traffic reached the guest: {guest}");
        }
    }
}

#[test]
#[ignore = "VM: requires Windows x64, WHP and the exact signed official bundle"]
fn signed_bundle_host_loopback_ingress() {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let ports = [
        tcp.local_addr().unwrap().port(),
        udp.local_addr().unwrap().port(),
    ];
    drop((tcp, udp));
    host_loopback_case(ports, "allow", "allow");
    host_loopback_case(ports, "deny", "allow");
    host_loopback_case(ports, "allow", "deny");
    host_loopback_case(ports, "allow", "allow");
    println!(
        "VM_EXECUTED host-loopback ingress TCP/UDP allow deny ready listeners and reply controls"
    );
}

#[test]
#[ignore = "VM: requires Windows x64, WHP, a host IPv4 route and the exact signed official bundle"]
fn signed_bundle_deny_default_proxy_policy() {
    let services = ControlledServices::new(false);
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
        json!({"egress": {}}),
        Some(json!({"networkProxy": format!("http://127.0.0.1:{port}")})),
    );
    let result = __ffi::run_json(&request.to_string(), true);
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
