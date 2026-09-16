// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use learning_mode_core::DenialsDocument;
use process_security_environment_spec::process_security_environment_layout as psec_layout;
use serde_json::json;
use wxc_common::config_parser::load_mxc_request_from_json;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{CaptureDenialsConfig, ExecutionRequest, NetworkAction, ProxyConfig};
use wxc_common::sandbox_process::{SandboxBackend, StdioMode};
use wxc_common::state_aware_request::MxcRequest;

use super::{build_psec_spec, ResolvedPsecContract, LOOPBACK_NETWORK_PEER};
use crate::base_container_runner::BaseContainerRunner;
use crate::network_policy_helpers::PRIVATE_NETWORK_CAPABILITY;
use crate::secenv::{SecurityEnvironmentApi, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE};

fn runtime_proxy_request(proxy: &TcpListener) -> ExecutionRequest {
    let config = json!({
        "version": "0.9.0-alpha",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd.exe /d /c echo proxy-launched",
            "timeout": 30000,
        },
        "network": {
            "egress": { "default": "deny" },
            "ingress": { "default": "allow", "hostLoopback": "allow" },
        },
        "runtimeConfig": {
            "networkProxy": format!("http://{}", proxy.local_addr().unwrap()),
        },
        "ui": { "disable": false },
    });
    let mut logger = Logger::new(Mode::Buffer);
    let MxcRequest::OneShot(request) =
        load_mxc_request_from_json(&config.to_string(), &mut logger).unwrap()
    else {
        panic!("expected a one-shot request");
    };
    request
}

#[test]
fn runtime_proxy_uses_peer_and_capability_without_native_ingress() {
    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let request = runtime_proxy_request(&proxy);
    let bytes = build_psec_spec(
        &request,
        ResolvedPsecContract::with_all_contract_capabilities(&request),
    );
    let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
    let network = spec.network_policy().expect("network policy");
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());

    assert_eq!(spec.version().minor(), 1);
    assert_eq!(
        spec.capabilities().unwrap().split(',').collect::<Vec<_>>(),
        [PRIVATE_NETWORK_CAPABILITY, "networkLoopback"]
    );
    assert_eq!(
        network.proxy().and_then(|proxy| proxy.url()),
        Some(proxy_url.as_str())
    );
    assert_eq!(
        network.allowed_appcontainer_peer(),
        Some(LOOPBACK_NETWORK_PEER)
    );
    assert!(network.egress().is_none());
    assert!(
        network.ingress().is_none(),
        "PSEC proxy mode must not include the incompatible native ingress table"
    );
}

#[test]
fn runtime_proxy_creates_native_security_environment() {
    if !BaseContainerRunner::supports_ingress_host_loopback_allow() {
        eprintln!("SKIPPED: native proxy regression requires usable PSEC 1.1 ingress support");
        return;
    }
    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let request = runtime_proxy_request(&proxy);
    let bytes = build_psec_spec(
        &request,
        ResolvedPsecContract::with_all_contract_capabilities(&request),
    );
    let environment = SecurityEnvironmentApi::load()
        .unwrap()
        .create(&bytes, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .unwrap_or_else(|error| {
            panic!("valid runtime proxy policy failed to create PSEC: {error}")
        });
    environment.close();
}

#[test]
fn identity_scoped_proxy_does_not_grant_host_loopback() {
    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let mut request = runtime_proxy_request(&proxy);
    request
        .policy
        .network_ingress
        .as_mut()
        .unwrap()
        .host_loopback = NetworkAction::Deny;
    request.policy.allowed_proxy_peer = Some("Contoso.Proxy_12345".to_string());
    let bytes = build_psec_spec(
        &request,
        ResolvedPsecContract::with_all_contract_capabilities(&request),
    );
    let spec = psec_layout::root_as_process_security_environment(&bytes).unwrap();
    let network = spec.network_policy().unwrap();

    assert_eq!(spec.version().minor(), 0);
    assert_eq!(spec.capabilities(), Some(PRIVATE_NETWORK_CAPABILITY));
    assert_eq!(
        network.allowed_appcontainer_peer(),
        Some("Contoso.Proxy_12345")
    );
    assert!(network.proxy().is_some());
    assert!(network.ingress().is_none());
    assert!(network.egress().is_none());
}

fn run_proxy_command(request: ExecutionRequest) -> String {
    run_proxy_command_with_stdout(request, |mut stdout| {
        let mut output = String::new();
        stdout.read_to_string(&mut output).map(|_| output)
    })
}

fn run_proxy_command_with_stdout(
    mut request: ExecutionRequest,
    read_stdout: impl FnOnce(Box<dyn Read + Send>) -> io::Result<String> + Send,
) -> String {
    let working_directory = tempfile::tempdir().unwrap();
    request.working_directory = working_directory.path().to_str().unwrap().to_string();
    request.policy.readwrite_paths = vec![request.working_directory.clone()];
    let system_root = std::env::var("SystemRoot").unwrap();
    request.policy.readonly_paths = vec![Path::new(&system_root)
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()];

    let mut logger = Logger::new(Mode::Buffer);
    let mut child = BaseContainerRunner::new()
        .spawn(&request, &mut logger, StdioMode::Pipes)
        .unwrap_or_else(|error| panic!("proxy child failed: {error:?}\n{}", logger.get_buffer()));
    drop(child.take_stdin());
    let stdout = child.take_stdout().unwrap();
    let mut stderr = child.take_stderr().unwrap();
    let (status, stdout, stderr) = std::thread::scope(|scope| {
        let stdout = scope.spawn(move || read_stdout(stdout));
        let stderr = scope.spawn(move || {
            let mut output = String::new();
            stderr.read_to_string(&mut output).map(|_| output)
        });
        (child.wait(), stdout.join().unwrap(), stderr.join().unwrap())
    });
    let stdout = stdout.unwrap();
    let stderr = stderr.unwrap();
    assert_eq!(status.unwrap(), 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    stdout
}

#[test]
fn runtime_proxy_launches_child() {
    if !BaseContainerRunner::supports_ingress_host_loopback_allow() {
        eprintln!("SKIPPED: native proxy launch requires usable PSEC 1.1 ingress support");
        return;
    }
    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let output = run_proxy_command(runtime_proxy_request(&proxy));
    assert_eq!(output.trim(), "proxy-launched");
}

#[test]
fn runtime_proxy_captures_denials_and_launches_child() {
    let _guard = crate::test_env::lock();
    if !BaseContainerRunner::supports_ingress_host_loopback_allow()
        || !BaseContainerRunner::is_native_capture_available()
    {
        eprintln!("SKIPPED: native proxy capture requires PSEC 1.1 and Learning Mode APIs");
        return;
    }
    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let output_directory = tempfile::tempdir().unwrap();
    let mut request = runtime_proxy_request(&proxy);
    request.policy.capture_denials = Some(CaptureDenialsConfig {
        output_path: Some(
            output_directory
                .path()
                .join("denials.json")
                .to_str()
                .unwrap()
                .to_string(),
        ),
        ..Default::default()
    });
    assert_eq!(run_proxy_command(request).trim(), "proxy-launched");
    let documents: Vec<_> = std::fs::read_dir(output_directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .ends_with(".verbose.json")
        })
        .collect();
    assert_eq!(
        documents.len(),
        1,
        "expected one denials document: {documents:?}"
    );
    let document: DenialsDocument =
        serde_json::from_slice(&std::fs::read(&documents[0]).unwrap()).unwrap();
    assert_eq!(document.summary.exit_code, 0);
}

#[test]
fn runtime_proxy_allows_only_its_ipv4_loopback_endpoint() {
    if !BaseContainerRunner::supports_ingress_host_loopback_allow() {
        eprintln!("SKIPPED: native proxy networking requires usable PSEC 1.1 ingress support");
        return;
    }
    assert_proxy_endpoint_only("127.0.0.1");
}

#[test]
fn runtime_proxy_blocks_ipv6_loopback_bypass() {
    if !BaseContainerRunner::supports_ingress_host_loopback_allow() {
        eprintln!("SKIPPED: native proxy networking requires usable PSEC 1.1 ingress support");
        return;
    }
    assert_proxy_endpoint_only("::1");
}

fn assert_proxy_endpoint_only(other_host: &str) {
    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let other = TcpListener::bind((other_host, 0)).unwrap();
    drop(TcpStream::connect(proxy.local_addr().unwrap()).unwrap());
    drop(TcpStream::connect(other.local_addr().unwrap()).unwrap());

    let script = r#"
        $ErrorActionPreference = 'Stop';
        $proxy = [Net.Sockets.TcpClient]::new();
        try {
            $proxy.Connect('127.0.0.1', @PROXY_PORT@);
            'proxy-connected';
        } finally { $proxy.Dispose(); }
        $other = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::@OTHER_FAMILY@);
        try {
            $other.Connect('@OTHER_HOST@', @OTHER_PORT@);
            throw 'direct connection bypassed proxy confinement';
        } catch {
            if ($_.Exception.InnerException.NativeErrorCode -ne 10013) { throw; }
            'other-port-denied';
        } finally { $other.Dispose(); }
    "#
    .replace(
        "@OTHER_FAMILY@",
        if other_host == "::1" {
            "InterNetworkV6"
        } else {
            "InterNetwork"
        },
    )
    .replace("@OTHER_HOST@", other_host)
    .replace(
        "@PROXY_PORT@",
        &proxy.local_addr().unwrap().port().to_string(),
    )
    .replace(
        "@OTHER_PORT@",
        &other.local_addr().unwrap().port().to_string(),
    );
    let powershell = Path::new(&std::env::var("SystemRoot").unwrap())
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut request = runtime_proxy_request(&proxy);
    request.script_code = format!(
        "\"{}\" -NoLogo -NoProfile -NonInteractive -Command \"{}\"",
        powershell.display(),
        script.replace(['\r', '\n'], " ")
    );
    let output = run_proxy_command(request);
    assert_eq!(
        output.lines().map(str::trim).collect::<Vec<_>>(),
        ["proxy-connected", "other-port-denied"]
    );
}

#[test]
fn runtime_proxy_preserves_allowed_host_to_container_loopback() {
    if !BaseContainerRunner::supports_ingress_host_loopback_allow() {
        eprintln!("SKIPPED: native proxy ingress requires usable PSEC 1.1 ingress support");
        return;
    }
    let proxy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let powershell = Path::new(&std::env::var("SystemRoot").unwrap())
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let mut request = runtime_proxy_request(&proxy);
    request.script_code = format!(
        r#""{}" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference = 'Stop'; $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); try {{ $listener.Start(); [Console]::Out.WriteLine($listener.LocalEndpoint.Port); $client = $listener.AcceptTcpClient(); $client.Dispose(); 'host-connected'; }} finally {{ $listener.Stop(); }}""#,
        powershell.display()
    );
    let read_stdout = |stdout: Box<dyn Read + Send>| {
        let mut reader = BufReader::new(stdout);
        let mut port = String::new();
        reader.read_line(&mut port)?;
        let port: u16 = port
            .trim()
            .parse()
            .expect("child must report its listening port");
        drop(TcpStream::connect(("127.0.0.1", port))?);
        let mut output = String::new();
        reader.read_to_string(&mut output).map(|_| output)
    };
    let mut direct = request.clone();
    direct.policy.network_proxy = ProxyConfig::default();
    direct.policy.runtime_network_proxy_specified = false;
    direct.policy.network_egress.as_mut().unwrap().default = NetworkAction::Allow;
    eprintln!("Checking native full-ingress host-to-container control");
    assert_eq!(
        run_proxy_command_with_stdout(direct, read_stdout).trim(),
        "host-connected"
    );
    eprintln!("Checking proxy-mode host-to-container ingress");
    let output = run_proxy_command_with_stdout(request, read_stdout);
    assert_eq!(output.trim(), "host-connected");
}
