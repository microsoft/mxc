// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_common::{
    config_parser::load_mxc_request_from_json,
    logger::{Logger, Mode},
    models::{ContainmentBackend, ExecutionRequest},
    mxc_error::{MxcError, MxcErrorCode},
    state_aware_dispatch::DispatchOutcome,
    state_aware_request::MxcRequest,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
#[cfg(target_os = "windows")]
use std::time::Instant;

const POOL: &str = "11111111-1111-1111-1111-111111111111";
const A: &str = "22222222-2222-2222-2222-222222222222";
const B: &str = "33333333-3333-3333-3333-333333333333";
static ENV: Mutex<()> = Mutex::new(());

#[cfg(any(target_os = "windows", target_os = "macos"))]
const FIXTURE_IDENTITY_PASSWORD: &str = "fixture-only";

#[cfg(target_os = "windows")]
struct FixtureKey(Option<schannel::ncrypt_key::NcryptKey>);

#[cfg(target_os = "windows")]
impl Drop for FixtureKey {
    fn drop(&mut self) {
        use schannel::RawPointer;
        use windows::Win32::Security::Cryptography::{NCryptDeleteKey, NCRYPT_KEY_HANDLE};

        let key = self.0.take().unwrap();
        // Delete only this fixture's imported key; success also frees its handle.
        match unsafe { NCryptDeleteKey(NCRYPT_KEY_HANDLE(key.as_ptr() as usize), 0) } {
            Ok(()) => std::mem::forget(key),
            Err(error) => {
                eprintln!("cannot delete W365 fixture key: {error}");
                assert!(std::thread::panicking(), "fixture key cleanup failed");
            }
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn fixture_pkcs12(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("certificate.pem");
    let key = directory.path().join("key.pem");
    let archive = directory.path().join("identity.p12");
    std::fs::write(&certificate, cert.cert.pem()).unwrap();
    std::fs::write(&key, cert.signing_key.serialize_pem()).unwrap();
    let openssl = std::env::var_os("MXC_W365_TEST_OPENSSL").unwrap_or_else(|| "openssl".into());
    // macOS cannot import rcgen's EC PKCS#8 PEM. These PKCS#12 algorithms work
    // with its identity importer; they do not configure TLS or production crypto.
    let output = std::process::Command::new(openssl)
        .args(["pkcs12", "-export", "-out"])
        .arg(&archive)
        .arg("-inkey")
        .arg(&key)
        .arg("-in")
        .arg(&certificate)
        .args([
            "-passout",
            &format!("pass:{FIXTURE_IDENTITY_PASSWORD}"),
            "-keypbe",
            "PBE-SHA1-3DES",
            "-certpbe",
            "PBE-SHA1-3DES",
            "-macalg",
            "sha1",
        ])
        .output()
        .expect("W365 TLS fixtures require openssl on PATH or MXC_W365_TEST_OPENSSL");
    assert!(
        output.status.success(),
        "fixture PKCS#12 conversion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(archive).unwrap()
}

#[cfg(target_os = "windows")]
fn fixture_tls(
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> (schannel::schannel_cred::SchannelCred, FixtureKey) {
    // SChannel needs a persisted server key; retain its exact handle for cleanup.
    let store = schannel::cert_store::PfxImportOptions::new()
        .password(FIXTURE_IDENTITY_PASSWORD)
        .import(&fixture_pkcs12(cert))
        .unwrap();
    let certificate = store.certs().next().expect("fixture certificate required");
    let key = match certificate.private_key().silent(true).acquire().unwrap() {
        schannel::cert_context::PrivateKey::NcryptKey(key) => FixtureKey(Some(key)),
        _ => panic!("fixture EC key must use CNG"),
    };
    let tls = schannel::schannel_cred::SchannelCred::builder()
        .cert(certificate)
        .acquire(schannel::schannel_cred::Direction::Inbound)
        .unwrap();
    (tls, key)
}

#[cfg(not(target_os = "windows"))]
fn fixture_tls(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> native_tls::TlsAcceptor {
    #[cfg(target_os = "macos")]
    let identity =
        native_tls::Identity::from_pkcs12(&fixture_pkcs12(cert), FIXTURE_IDENTITY_PASSWORD)
            .unwrap();
    #[cfg(not(target_os = "macos"))]
    let identity = native_tls::Identity::from_pkcs8(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    native_tls::TlsAcceptor::new(identity).unwrap()
}

struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Environment {
    fn new() -> Self {
        let environment = Self(
            [
                "W365A_CONTROLPLANE_URL",
                "W365A_CP_TOKEN",
                "MXC_W365_TEST_CA",
                "MXC_W365_TEST_PORT",
                "MXC_W365_TEST_TIMEOUT_MS",
            ]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect(),
        );
        std::env::remove_var("MXC_W365_TEST_TIMEOUT_MS");
        environment
    }
    fn set(&self, key: &str, value: &str) {
        std::env::set_var(key, value);
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

enum FixtureReply {
    Complete(String),
    Disconnect,
    Hold {
        prefix: String,
        ready: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    },
}

struct HeldReply {
    ready: mpsc::Receiver<()>,
    _release: mpsc::Sender<()>,
}

struct Fixture {
    port: u16,
    ca: tempfile::NamedTempFile,
    requests: Arc<Mutex<Vec<String>>>,
    replies: Arc<Mutex<std::collections::VecDeque<FixtureReply>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    #[cfg(target_os = "windows")]
    _key: FixtureKey,
}
impl Fixture {
    fn new() -> Self {
        Self::with_hostname("localhost")
    }
    fn with_hostname(hostname: &str) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec![hostname.into()]).unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(cert.cert.pem().as_bytes()).unwrap();
        #[cfg(target_os = "windows")]
        let (tls, key) = fixture_tls(&cert);
        #[cfg(not(target_os = "windows"))]
        let tls = fixture_tls(&cert);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(std::collections::VecDeque::<FixtureReply>::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, responses, stopping) = (requests.clone(), replies.clone(), stop.clone());
        let worker = std::thread::spawn(move || {
            while !stopping.load(std::sync::atomic::Ordering::Relaxed) {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                #[cfg(target_os = "windows")]
                let handshake = schannel::tls_stream::Builder::new().accept(tls.clone(), socket);
                #[cfg(not(target_os = "windows"))]
                let handshake = tls.accept(socket);
                let mut stream = match handshake {
                    Ok(stream) => stream,
                    // Trust and hostname rejection probes deliberately fail the handshake.
                    Err(_) => continue,
                };
                let mut data = Vec::new();
                let mut buf = [0; 1024];
                while !data.windows(4).any(|v| v == b"\r\n\r\n") {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Err(_) => break,
                        Ok(n) => data.extend_from_slice(&buf[..n]),
                    }
                    assert!(data.len() < 16384);
                }
                if data.is_empty() {
                    continue;
                } // Rejected TLS never carries an HTTP request.
                seen.lock().unwrap().push(String::from_utf8(data).unwrap());
                let reply = responses.lock().unwrap().pop_front();
                match reply {
                    Some(FixtureReply::Complete(reply)) => {
                        stream.write_all(reply.as_bytes()).unwrap();
                        stream.flush().unwrap();
                    }
                    Some(FixtureReply::Hold {
                        prefix,
                        ready,
                        release,
                    }) => {
                        stream.write_all(prefix.as_bytes()).unwrap();
                        stream.flush().unwrap();
                        let _ = ready.send(());
                        // Dropping the test's gate also unblocks cleanup after a failed assertion.
                        let _ = release.recv();
                    }
                    Some(FixtureReply::Disconnect) | None => {}
                }
            }
        });
        Self {
            port,
            ca,
            requests,
            replies,
            stop,
            worker: Some(worker),
            #[cfg(target_os = "windows")]
            _key: key,
        }
    }
    fn configure(&self, env: &Environment) {
        env.set("W365A_CONTROLPLANE_URL", "localhost");
        env.set("W365A_CP_TOKEN", "fixture-token-never-log");
        env.set("MXC_W365_TEST_CA", self.ca.path().to_str().unwrap());
        env.set("MXC_W365_TEST_PORT", &self.port.to_string());
    }
    fn reply(&self, status: u16, body: &str) {
        self.reply_with_length(status, body, body.len());
    }
    fn reply_with_length(&self, status: u16, body: &str, length: usize) {
        self.replies.lock().unwrap().push_back(FixtureReply::Complete(format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {length}\r\nx-ms-request-id: fixture-request\r\nConnection: close\r\n\r\n{body}"
        )));
    }
    fn drop_reply(&self) {
        self.replies
            .lock()
            .unwrap()
            .push_back(FixtureReply::Disconnect);
    }
    fn hold_reply(&self, prefix: &str) -> HeldReply {
        let (ready, received) = mpsc::channel();
        let (release, released) = mpsc::channel();
        self.replies.lock().unwrap().push_back(FixtureReply::Hold {
            prefix: prefix.into(),
            ready,
            release: released,
        });
        HeldReply {
            ready: received,
            _release: release,
        }
    }
    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    fn request(&self, index: usize) -> String {
        self.requests.lock().unwrap()[index].clone()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn provision() -> Value {
    json!({"version":"1.1.0-alpha", "phase":"provision", "containment":"w365_agents",
        "w365Agents":{"provision":{"poolId":POOL}}})
}
fn request(phase: &str, session: &str) -> Value {
    let mut value = json!({"version":"1.1.0-alpha","phase":phase,
        "sandboxId":format!("w365:{POOL}:{session}")});
    if phase == "exec" {
        value["process"] = json!({"commandLine":"echo must-not-run"});
    }
    value
}
fn invoke(value: &Value, opt_in: bool) -> Result<Value, MxcError> {
    let MxcRequest::StateAware(mut parsed) =
        load_mxc_request_from_json(&value.to_string(), &mut Logger::new(Mode::Buffer))
            .map_err(|e| e.to_mxc_error())?
    else {
        panic!("lifecycle");
    };
    parsed.set_experimental_enabled(opt_in);
    match mxc_sdk::mxc_engine::run_state_aware(parsed, false)? {
        DispatchOutcome::Envelope(value) => Ok(value),
        other => panic!("{other:?}"),
    }
}

#[test]
fn transport_deadlines_fixture() {
    const TIMEOUT: Duration = Duration::from_secs(2);
    const WATCHDOG: Duration = Duration::from_secs(15);
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    fixture.configure(&env);
    env.set("MXC_W365_TEST_TIMEOUT_MS", &TIMEOUT.as_millis().to_string());
    let partial_body = format!(
        "HTTP/1.1 200 Fixture\r\nContent-Length: 1000\r\nx-ms-request-id: fixture-request\r\n\r\n{{\"sessionId\":\"{A}\""
    );
    for (phase, prefix, code) in [
        ("provision", "", "checkout_transport"),
        ("provision", partial_body.as_str(), "checkout_response"),
        ("stop", "", "release_transport"),
        (
            "deprovision",
            "HTTP/1.1 204 Fixture\r\nx-ms-request-id: fixture-request\r\n",
            "release_transport",
        ),
    ] {
        let before = fixture.count();
        let value = if phase == "provision" {
            provision()
        } else {
            request(phase, A)
        };
        let error = std::thread::scope(|scope| {
            let held = fixture.hold_reply(prefix);
            let (completed, result) = mpsc::channel();
            let client = scope.spawn(move || {
                completed.send(invoke(&value, true)).unwrap();
            });
            let ready = held.ready.recv_timeout(WATCHDOG);
            let outcome = result.recv_timeout(WATCHDOG);
            // Keep the connection open until the client returns; the watchdog must fail,
            // not close the socket early and accidentally satisfy the timeout assertion.
            drop(held);
            client.join().unwrap();
            ready.expect("fixture must receive the request and hold its response open");
            outcome
                .expect("client did not enforce its short transport deadline")
                .unwrap_err()
        });
        assert_eq!(error.code, MxcErrorCode::BackendError, "{phase}/{code}");
        let details = error.details.unwrap();
        assert_eq!(details["code"], code, "{phase}/{code}");
        assert_eq!(details["possiblySucceeded"], true);
        assert_eq!(
            fixture.count(),
            before + 1,
            "deadline expiration must not replay checkout or release"
        );
        if phase == "provision" {
            assert!(details.get("sandboxId").is_none());
            assert!(details.get("sessionId").is_none());
        } else {
            assert_eq!(details["sandboxId"], format!("w365:{POOL}:{A}"));
            assert_eq!(details["sessionId"], A);
            assert!(fixture
                .request(before)
                .starts_with(&format!("DELETE /api/sessions/{A}?api-version=2.0")));
        }
        if code == "checkout_response" {
            assert_eq!(details["httpStatus"], 200);
            assert_eq!(details["requestId"], "fixture-request");
        } else {
            assert!(details.get("httpStatus").is_none());
        }
    }
}

#[test]
fn lifecycle_contract_and_recovery_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    for configured in [false, true] {
        fixture.configure(&env);
        if !configured {
            std::env::remove_var("W365A_CONTROLPLANE_URL");
            std::env::remove_var("W365A_CP_TOKEN");
        }
        for experimental_enabled in [false, true] {
            for dry_run in [false, true] {
                let execution = ExecutionRequest {
                    containment: ContainmentBackend::W365Agents,
                    script_code: "echo must-not-run".into(),
                    experimental_enabled,
                    dry_run,
                    ..Default::default()
                };
                let result = mxc_sdk::mxc_engine::run(&execution, &mut Logger::new(Mode::Buffer));
                if experimental_enabled {
                    let response = result.expect("the engine must select the refusing W365 runner");
                    assert_eq!(response.exit_code, 1);
                    assert_eq!(
                        response.failure_phase.error_code(),
                        MxcErrorCode::PolicyValidation
                    );
                    assert!(response
                        .error_message
                        .contains("container lifecycle operations only"));
                    assert!(response.standard_out.is_empty());
                    assert!(response.standard_err.is_empty());
                } else {
                    assert_eq!(result.unwrap_err().code.as_str(), "backend_unavailable");
                }
                let error = mxc_sdk::mxc_engine::spawn_execution_request(&execution, false)
                    .err()
                    .expect("create-and-run streaming must never start a process");
                assert_eq!(
                    error.code.as_str(),
                    if !experimental_enabled {
                        "backend_unavailable"
                    } else if dry_run {
                        "malformed_request"
                    } else {
                        "policy_validation"
                    }
                );
                if experimental_enabled && !dry_run {
                    assert!(error
                        .message
                        .contains("container lifecycle operations only"));
                }
            }
        }
    }
    assert_eq!(
        fixture.count(),
        0,
        "execution refusal must not call the service"
    );
    fixture.configure(&env);
    for key in ["W365A_CONTROLPLANE_URL", "W365A_CP_TOKEN"] {
        std::env::remove_var(key);
        assert_eq!(
            invoke(&provision(), true).unwrap_err().code,
            MxcErrorCode::PolicyValidation
        );
        fixture.configure(&env);
    }
    let before = fixture.count();
    for phase in ["provision", "start", "exec", "stop", "deprovision"] {
        let value = if phase == "provision" {
            provision()
        } else {
            request(phase, A)
        };
        assert_eq!(
            invoke(&value, false).unwrap_err().code,
            MxcErrorCode::BackendUnavailable
        );
    }
    let invalid_guids = [
        "22222222222222222222222222222222",
        "{22222222-2222-2222-2222-222222222222}",
        "urn:uuid:22222222-2222-2222-2222-222222222222",
        "2222222-22222-2222-2222-222222222222",
    ];
    for bad in invalid_guids {
        for field in ["poolId", "userObjectId"] {
            let mut value = provision();
            value["w365Agents"]["provision"][field] = json!(bad);
            assert_eq!(
                invoke(&value, true).unwrap_err().code,
                MxcErrorCode::MalformedRequest,
                "{field}={bad}"
            );
        }
    }
    for phase in ["start", "exec"] {
        assert_eq!(
            invoke(&request(phase, A), true).unwrap_err().code,
            MxcErrorCode::UnsupportedPhase
        );
    }
    for phase in ["stop", "deprovision"] {
        for bad in [
            "",
            "../escape",
            "not-guid",
            "22222222-2222-2222-2222-222222222222:extra",
        ]
        .into_iter()
        .chain(invalid_guids)
        {
            assert_eq!(
                invoke(&request(phase, bad), true).unwrap_err().code,
                MxcErrorCode::MalformedId
            );
        }
    }
    for key in ["filesystem", "network", "ui", "clipboard", "runtimeConfig"] {
        for phase in ["provision", "exec", "stop"] {
            let mut value = if phase == "provision" {
                provision()
            } else {
                request(phase, A)
            };
            value[key] = json!({});
            assert!(invoke(&value, true).is_err(), "{key}/{phase}");
        }
    }
    for host in [
        "",
        " ",
        "https://localhost",
        "localhost:443",
        "localhost/path",
        "localhost\r\nx:y",
    ] {
        env.set("W365A_CONTROLPLANE_URL", host);
        assert_eq!(
            invoke(&provision(), true).unwrap_err().code,
            MxcErrorCode::PolicyValidation
        );
    }
    fixture.configure(&env);
    for token in ["", " ", "\r\nsecret", "secret token"] {
        env.set("W365A_CP_TOKEN", token);
        assert_eq!(
            invoke(&provision(), true).unwrap_err().code,
            MxcErrorCode::PolicyValidation
        );
    }
    fixture.configure(&env);
    let mut absent = provision();
    absent.as_object_mut().unwrap().remove("w365Agents");
    assert_eq!(
        invoke(&absent, true).unwrap_err().code,
        MxcErrorCode::PolicyValidation
    );
    absent["w365Agents"] = json!({});
    assert_eq!(
        invoke(&absent, true).unwrap_err().code,
        MxcErrorCode::PolicyValidation
    );
    assert_eq!(fixture.count(), before);

    let wrong_ca = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut wrong_file = tempfile::NamedTempFile::new().unwrap();
    wrong_file
        .write_all(wrong_ca.cert.pem().as_bytes())
        .unwrap();
    env.set("MXC_W365_TEST_CA", wrong_file.path().to_str().unwrap());
    assert!(invoke(&provision(), true).is_err());
    assert_eq!(
        fixture.count(),
        before,
        "invalid TLS cannot transmit credentials or checkout"
    );
    let wrong_hostname = Fixture::with_hostname("not-localhost.invalid");
    wrong_hostname.configure(&env);
    assert!(invoke(&provision(), true).is_err());
    assert_eq!(
        wrong_hostname.count(),
        0,
        "a trusted certificate for another hostname must not receive credentials or checkout"
    );
    fixture.configure(&env);
    assert!(mxc_sdk::mxc_engine::available_backends()
        .iter()
        .all(|b| b.backend != "w365_agents"));
    assert_eq!(
        fixture.count(),
        before,
        "local probing must not use W365 services"
    );

    {
        use mxc_sdk::v1::dev as sdk;
        let options = sdk::JsonOptions { experimental: true };
        let source = provision().to_string();
        let before = fixture.count();
        assert_eq!(
            sdk::provision_container_json(&source, sdk::JsonOptions::default())
                .unwrap_err()
                .code,
            mxc_sdk::v1::ErrorCode::BackendUnavailable
        );
        sdk::validate_provision_json(&source, options).unwrap();
        for error in [
            sdk::start_container_json(&request("start", A).to_string(), options).err(),
            sdk::run_in_container_json(&request("exec", A).to_string(), options).err(),
            sdk::spawn_in_container_json(&request("exec", A).to_string(), options).err(),
            sdk::spawn_in_container_with_pty_json(
                &request("exec", A).to_string(),
                sdk::PtyJsonOptions {
                    experimental: true,
                    ..Default::default()
                },
            )
            .err(),
        ] {
            assert_eq!(
                error.unwrap().code,
                mxc_sdk::v1::ErrorCode::UnsupportedPhase
            );
        }
        assert_eq!(
            fixture.count(),
            before,
            "SDK validation cannot use the service"
        );
        fixture.reply(
            200,
            &json!({"sessionId":A,"status":"Succeeded"}).to_string(),
        );
        let value: Value =
            serde_json::from_str(&sdk::provision_container_json(&source, options).unwrap())
                .unwrap();
        assert_eq!(value["result"]["sandboxId"], format!("w365:{POOL}:{A}"));
        for phase in ["stop", "deprovision"] {
            fixture.reply(204, "");
            let call = if phase == "stop" {
                sdk::stop_container_json
            } else {
                sdk::deprovision_container_json
            };
            let value: Value =
                serde_json::from_str(&call(&request(phase, A).to_string(), options).unwrap())
                    .unwrap();
            assert_eq!(value["result"]["metadata"]["releaseRequested"], true);
        }
        for (body, known_id) in [
            (json!({"sessionId":A}), true),
            (json!({"sessionId":"invalid"}), false),
            (json!({}), false),
        ] {
            fixture.reply(500, &body.to_string());
            let error = sdk::provision_container_json(&source, options).unwrap_err();
            assert_eq!(error.code, mxc_sdk::v1::ErrorCode::BackendError);
            let details = error.details.as_ref().unwrap();
            let client_id = details["clientRequestId"].as_str().unwrap();
            assert!(error
                .message
                .contains(&format!("clientRequestId={client_id}")));
            assert!(fixture.request(fixture.count() - 1).contains(client_id));
            assert!(error.message.contains("requestId=fixture-request"));
            assert!(error.message.contains("possiblySucceeded=true"));
            assert_eq!(
                error.message.contains(&format!("w365:{POOL}:{A}")),
                known_id
            );
            assert_eq!(error.message.contains("sandboxId"), known_id);
            assert_eq!(
                error.details.as_ref().unwrap().get("sandboxId").is_some(),
                known_id
            );
        }
        env.set("W365A_CP_TOKEN", "renewed-sdk-fixture-token");
        fixture.reply(204, "");
        sdk::deprovision_container_json(&request("deprovision", A).to_string(), options).unwrap();
        assert!(fixture
            .request(fixture.count() - 1)
            .contains("renewed-sdk-fixture-token"));
        fixture.configure(&env);
    }

    let first_checkout = fixture.count();
    for body in [
        json!({"sessionId":A,"computerId":A,"status":"Succeeded"}),
        json!({"sessionId":A,"status":"Succeeded"}),
    ] {
        fixture.reply(200, &body.to_string());
        assert_eq!(
            invoke(&provision(), true).unwrap()["result"]["sandboxId"],
            format!("w365:{POOL}:{A}")
        );
    }
    let first = fixture.request(first_checkout).to_ascii_lowercase();
    assert!(first.starts_with(&format!("post /api/pools/{POOL}/sessions?api-version=2.0 ")));
    assert!(!first.contains("user-type:"));
    assert!(!first.contains("user-object-id:"));
    assert!(first.contains("x-ms-client-request-id:"));
    let mut human = provision();
    human["w365Agents"]["provision"]["userType"] = json!("HumanUser");
    human["w365Agents"]["provision"]["userObjectId"] = json!(B);
    fixture.reply(
        200,
        &json!({"sessionId":A,"status":"Succeeded"}).to_string(),
    );
    invoke(&human, true).unwrap();
    let sent = fixture.request(first_checkout + 2);
    assert!(sent.to_ascii_lowercase().contains("user-type: humanuser"));
    assert!(sent.contains(B));
    assert_eq!(
        sent.split_once("\r\n\r\n").unwrap().1,
        "",
        "API 2.0 checkout is bodyless"
    );

    for (kind, oid) in [(true, false), (false, true)] {
        let mut value = provision();
        if kind {
            value["w365Agents"]["provision"]["userType"] = json!("HumanUser");
        }
        if oid {
            value["w365Agents"]["provision"]["userObjectId"] = json!(B);
        }
        fixture.reply(
            200,
            &json!({"sessionId":A,"status":"Succeeded"}).to_string(),
        );
        let n = fixture.count();
        invoke(&value, true).unwrap();
        let sent = fixture.request(n).to_ascii_lowercase();
        assert_eq!(sent.contains("user-type:"), kind);
        assert_eq!(sent.contains("user-object-id:"), oid);
    }
    for user_type in ["Local", "HumanUser", "Agentic"] {
        for oid in [false, true] {
            let mut value = provision();
            value["w365Agents"]["provision"]["userType"] = json!(user_type);
            if oid {
                value["w365Agents"]["provision"]["userObjectId"] = json!(B);
            }
            let n = fixture.count();
            assert!(invoke(&value, false).is_err());
            assert_eq!(fixture.count(), n, "all user types require authorization");
            fixture.reply(
                200,
                &json!({"sessionId":A,"status":"Succeeded"}).to_string(),
            );
            invoke(&value, true).unwrap();
            let sent = fixture.request(n);
            assert!(sent.contains(&format!("user-type: {user_type}\r\n")));
            assert_eq!(sent.contains("user-object-id:"), oid);
            if oid {
                assert!(sent.contains(&format!("user-object-id: {B}\r\n")));
            }
            assert_eq!(sent.split_once("\r\n\r\n").unwrap().1, "");
        }
    }
    let upper = "AAAAAAAA-bbbb-CCCC-dddd-EEEEEEEEEEEE";
    let mut value = provision();
    value["w365Agents"]["provision"]["poolId"] = json!(upper);
    fixture.reply(
        200,
        &json!({
            "sessionId":upper,"computerId":upper.to_ascii_lowercase(),"status":"Succeeded",
            "connectivityUrl":"https://example.invalid/?ticket=must-not-persist",
        })
        .to_string(),
    );
    let value = invoke(&value, true).unwrap();
    assert_eq!(
        value["result"]["sandboxId"],
        format!("w365:{0}:{0}", upper.to_ascii_lowercase())
    );
    assert!(!value.to_string().contains("must-not-persist"));
    fixture.reply(
        201,
        &json!({"sessionId":A,"status":"Succeeded"}).to_string(),
    );
    assert_eq!(
        invoke(&provision(), true).unwrap_err().details.unwrap()["sandboxId"],
        format!("w365:{POOL}:{A}")
    );

    for body in [
        json!({"sessionId":A,"computerId":B,"status":"Succeeded"}),
        json!({"sessionId":A,"computerId":"bad","status":"Succeeded"}),
        json!({"sessionId":A,"computerId":null,"status":"Succeeded"}),
        json!({"sessionId":A,"status":"Failed"}),
    ] {
        fixture.reply(200, &body.to_string());
        let error = invoke(&provision(), true).unwrap_err();
        assert!(error.message.contains(&format!("w365:{POOL}:{A}")));
        let details = error.details.unwrap();
        assert_eq!(details["possiblySucceeded"], true);
        assert_eq!(details["sandboxId"], format!("w365:{POOL}:{A}"));
        fixture.reply(204, "");
        invoke(&request("deprovision", A), true).unwrap();
        assert!(fixture
            .request(fixture.count() - 1)
            .starts_with(&format!("DELETE /api/sessions/{A}?api-version=2.0")));
    }
    for body in ["{bad", "{}", r#"{"sessionId":"bad","status":"Succeeded"}"#]
        .into_iter()
        .map(str::to_owned)
        .chain(invalid_guids.map(|id| json!({"sessionId":id,"status":"Succeeded"}).to_string()))
    {
        let n = fixture.count();
        fixture.reply(200, &body);
        let details = invoke(&provision(), true).unwrap_err().details.unwrap();
        assert_eq!(details["possiblySucceeded"], true);
        assert!(details.get("sandboxId").is_none());
        assert_eq!(fixture.count(), n + 1);
    }
    for (status, code) in [(500, "provision_timeout"), (408, "checkout_failed")] {
        let n = fixture.count();
        fixture.reply(
            status,
            &json!({
                "sessionId":upper,
                "computerId":B,
                "connectivityUrl":"https://example.invalid/?ticket=must-not-persist",
            })
            .to_string(),
        );
        let error = invoke(&provision(), true).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(!format!("{error:?}").contains("must-not-persist"));
        let details = error.details.unwrap();
        assert_eq!(details["code"], code);
        assert_eq!(details["httpStatus"], status);
        assert_eq!(details["possiblySucceeded"], true);
        assert_eq!(details["requestId"], "fixture-request");
        assert!(uuid::Uuid::parse_str(details["clientRequestId"].as_str().unwrap()).is_ok());
        assert_eq!(details["poolId"], POOL);
        assert_eq!(details["sessionId"], upper.to_ascii_lowercase());
        assert_eq!(
            details["sandboxId"],
            format!("w365:{POOL}:{}", upper.to_ascii_lowercase())
        );
        assert_eq!(fixture.count(), n + 1, "failed checkout must not replay");
        fixture.reply(204, "");
        invoke(&request("deprovision", upper), true).unwrap();
        assert!(fixture.request(n + 1).starts_with(&format!(
            "DELETE /api/sessions/{}?api-version=2.0",
            upper.to_ascii_lowercase()
        )));

        let valid_body = json!({"sessionId":A}).to_string();
        for (body, length) in [
            ("{bad", 4),
            ("{}", 2),
            (r#"{"sessionId":"bad"}"#, 19),
            (valid_body.as_str(), valid_body.len() + 1),
            (valid_body.as_str(), 1024 * 1024 + 1),
        ] {
            let n = fixture.count();
            fixture.reply_with_length(status, body, length);
            let details = invoke(&provision(), true).unwrap_err().details.unwrap();
            assert_eq!(details["code"], code);
            assert_eq!(details["httpStatus"], status);
            assert_eq!(details["possiblySucceeded"], true);
            assert!(details.get("sandboxId").is_none());
            assert!(details.get("sessionId").is_none());
            assert_eq!(fixture.count(), n + 1);
        }
    }
    for status in [401, 403, 404, 408, 429, 500, 502, 201, 302, 418] {
        let n = fixture.count();
        fixture.reply(status, "ticket-secret-must-not-surface");
        let error = invoke(&provision(), true).unwrap_err();
        assert!(!format!("{error:?}").contains("ticket-secret"));
        let uncertain = status >= 500 || status == 408 || (200..400).contains(&status);
        assert!(error
            .message
            .contains(&format!("possiblySucceeded={uncertain}")));
        let details = error.details.unwrap();
        assert_eq!(details["httpStatus"], status);
        assert_eq!(details["requestId"], "fixture-request");
        assert_eq!(
            details["possiblySucceeded"],
            status >= 500 || status == 408 || (200..400).contains(&status)
        );
        assert_eq!(fixture.count(), n + 1);
    }
    fixture.drop_reply();
    let n = fixture.count();
    assert_eq!(
        invoke(&provision(), true).unwrap_err().details.unwrap()["possiblySucceeded"],
        true
    );
    assert_eq!(fixture.count(), n + 1);

    for phase in ["stop", "deprovision"] {
        for status in [200, 202, 204, 404] {
            fixture.reply(status, "");
            let value = invoke(&request(phase, A), true).unwrap();
            assert_eq!(value["result"]["metadata"]["releaseRequested"], true);
            assert_eq!(value["result"]["metadata"]["restartable"], false);
        }
    }
    for status in [401, 403, 408, 429, 500, 302, 418] {
        let before = fixture.count();
        fixture.reply(status, "secret");
        let error = invoke(&request("stop", A), true).unwrap_err();
        assert!(!error.message.contains("sandboxId"));
        let details = error.details.unwrap();
        assert_eq!(details["sandboxId"], format!("w365:{POOL}:{A}"));
        assert_eq!(details["httpStatus"], status);
        assert_eq!(
            details["possiblySucceeded"],
            status >= 500 || status == 408 || (200..400).contains(&status)
        );
        assert_eq!(
            fixture.count(),
            before + 1,
            "release must not retry automatically"
        );
        env.set("W365A_CP_TOKEN", "renewed-fixture-token");
        fixture.reply(204, "");
        invoke(&request("deprovision", A), true).unwrap();
        let sent = fixture.request(fixture.count() - 1);
        assert!(sent.contains("renewed-fixture-token"));
        assert!(sent.starts_with(&format!("DELETE /api/sessions/{A}?api-version=2.0")));
        assert_eq!(fixture.count(), before + 2);
    }
    fixture.drop_reply();
    assert_eq!(
        invoke(&request("deprovision", A), true)
            .unwrap_err()
            .details
            .unwrap()["possiblySucceeded"],
        true
    );
    fixture.reply(
        200,
        &json!({"sessionId":B,"status":"Succeeded"}).to_string(),
    );
    invoke(&provision(), true).unwrap();
    fixture.reply(204, "");
    invoke(&request("deprovision", A), true).unwrap();
    assert!(fixture
        .request(fixture.count() - 1)
        .starts_with(&format!("DELETE /api/sessions/{A}?")));
    for request in fixture.requests.lock().unwrap().iter() {
        let user_agent = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("user-agent")
                .then_some(value.trim())
        });
        assert_eq!(
            user_agent,
            Some(concat!("mxc/", env!("CARGO_PKG_VERSION"), " (w365_agents)"))
        );
    }
}

// CI explicitly supplies a test-support executor. This never uses a live service.
#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires a separately built test-support native executor"]
fn lifecycle_fresh_executor_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    fixture.configure(&env);
    let exe = std::env::var("MXC_W365_TEST_EXECUTOR").expect("fixture executor required");
    let run = |mut value: Value, opt_in: bool| {
        let phase = value["phase"].as_str().unwrap().to_owned();
        let id = value["sandboxId"].as_str().map(str::to_owned);
        value.as_object_mut().unwrap().remove("phase");
        value.as_object_mut().unwrap().remove("sandboxId");
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(value.to_string().as_bytes()).unwrap();
        let mut command = std::process::Command::new(&exe);
        command
            .arg("--operation")
            .arg(phase)
            .arg("--config")
            .arg(file.path());
        if let Some(id) = id {
            command.arg("--container-id").arg(id);
        }
        if opt_in {
            command.arg("--experimental");
        }
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().unwrap();
        let until = Instant::now() + Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= until {
                child.kill().unwrap();
                panic!("executor fixture timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    };
    assert!(!run(provision(), false).status.success());
    assert!(!run(request("deprovision", "bad"), true).status.success());
    assert_eq!(fixture.count(), 0);
    fixture.reply(
        200,
        &json!({"sessionId":A,"status":"Succeeded"}).to_string(),
    );
    let output = run(provision(), true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = value["result"]["sandboxId"].as_str().unwrap();
    assert_eq!(id, format!("w365:{POOL}:{A}"));
    assert!(!run(request("start", A), true).status.success());
    assert!(!run(request("exec", A), true).status.success());
    assert_eq!(fixture.count(), 1);
    env.set("W365A_CP_TOKEN", "renewed-fixture-token");
    fixture.reply(408, "no");
    let failed = run(request("deprovision", A), true);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stdout).contains(id));
    let error: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(error["error"]["details"]["httpStatus"], 408);
    assert_eq!(error["error"]["details"]["possiblySucceeded"], true);
    assert_eq!(error["error"]["details"]["sandboxId"], id);
    assert_eq!(fixture.count(), 2, "release must not retry automatically");
    fixture.reply(202, "");
    assert!(run(request("stop", A), true).status.success());
    assert_eq!(fixture.count(), 3);
    assert!(fixture
        .request(2)
        .starts_with(&format!("DELETE /api/sessions/{A}?")));
    fixture.reply(
        200,
        &json!({"sessionId":A,"computerId":B,"status":"Succeeded"}).to_string(),
    );
    let rejected = run(provision(), true);
    assert!(!rejected.status.success());
    let error: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(error["error"]["details"]["sandboxId"], id);
    assert_eq!(error["error"]["details"]["possiblySucceeded"], true);
    fixture.reply(204, "");
    assert!(run(request("deprovision", A), true).status.success());
    assert_eq!(fixture.count(), 5);
    assert!(fixture
        .request(4)
        .starts_with(&format!("DELETE /api/sessions/{A}?")));

    fixture.reply(500, &json!({"sessionId":B}).to_string());
    let failed = run(provision(), true);
    assert!(!failed.status.success());
    let error: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(error["error"]["details"]["code"], "provision_timeout");
    assert_eq!(error["error"]["details"]["httpStatus"], 500);
    assert_eq!(error["error"]["details"]["possiblySucceeded"], true);
    assert_eq!(
        error["error"]["details"]["sandboxId"],
        format!("w365:{POOL}:{B}")
    );
    assert_eq!(fixture.count(), 6, "failed checkout must not replay");
    let mut cleanup = request("deprovision", B);
    cleanup["sandboxId"] = error["error"]["details"]["sandboxId"].clone();
    env.set("W365A_CP_TOKEN", "renewed-error-cleanup-token");
    fixture.reply(204, "");
    let output = run(cleanup, true);
    assert!(
        output.status.success(),
        "cleanup failed: stdout={}; stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.count(), 7);
    assert!(fixture
        .request(6)
        .starts_with(&format!("DELETE /api/sessions/{B}?")));
    assert!(fixture
        .request(6)
        .contains("Bearer renewed-error-cleanup-token"));
}
