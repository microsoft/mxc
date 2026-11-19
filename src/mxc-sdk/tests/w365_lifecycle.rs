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
use std::time::{Duration, Instant};

const POOL: &str = "11111111-1111-1111-1111-111111111111";
const A: &str = "22222222-2222-2222-2222-222222222222";
const B: &str = "33333333-3333-3333-3333-333333333333";
static ENV: Mutex<()> = Mutex::new(());

#[path = "w365_lifecycle/execution.rs"]
mod execution;

#[test]
fn readiness_contract_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    fixture.configure(&env);
    env.set("W365A_DP_SUFFIX", "localhost");
    env.set("W365A_DP_TOKEN", "synthetic-data-plane-token");
    for state in ["Waiting", "Live", "Ready"] {
        fixture.reply(
            200,
            &json!({"status":state, "computerUrl":"https://invalid/?ticket=secret"}).to_string(),
        );
    }
    let result = invoke(&request("start", A), true).unwrap();
    assert_eq!(result["result"]["metadata"]["status"], "Ready");
    assert!(!result.to_string().contains("ticket"));
    assert_eq!(fixture.count(), 3);
    for n in 0..3 {
        let sent = fixture.request(n);
        assert!(sent.starts_with(&format!("GET /computers/{A}/status?api-version=1.0")));
        assert!(sent
            .to_ascii_lowercase()
            .contains(&format!("x-ms-computerid: {A}")));
    }
    fixture.reply(200, r#"{"status":"Deleting"}"#);
    assert_eq!(
        invoke(&request("start", A), true)
            .unwrap_err()
            .details
            .unwrap()["code"],
        "unknown_device_status"
    );
    for status in [401, 403, 404, 410, 429, 500, 302] {
        fixture.reply(status, "{}");
        let error = invoke(&request("start", A), true).unwrap_err();
        assert_eq!(error.details.unwrap()["httpStatus"], status);
    }
    fixture.reply(200, "{bad");
    assert_eq!(
        invoke(&request("start", A), true)
            .unwrap_err()
            .details
            .unwrap()["code"],
        "unparsable_response"
    );
    fixture.drop_reply();
    assert_eq!(
        invoke(&request("start", A), true)
            .unwrap_err()
            .details
            .unwrap()["code"],
        "status_transport"
    );

    let n = fixture.count();
    env.set("MXC_W365_TEST_READY_BUDGET_MS", "0");
    let error = invoke(&request("start", A), true).unwrap_err();
    assert_eq!(error.details.unwrap()["code"], "attach_timeout");
    assert_eq!(fixture.count(), n, "zero budget must not dial");
    env.set("MXC_W365_TEST_READY_BUDGET_MS", "1000");
    fixture.reply(200, r#"{"status":"Waiting"}"#);
    let began = Instant::now();
    let error = invoke(&request("start", A), true).unwrap_err();
    let details = error.details.unwrap();
    assert_eq!(details["code"], "attach_timeout");
    assert_eq!(details["lastState"], "Waiting");
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_eq!(fixture.count(), n + 1);
    for prefix in [
        "",
        "HTTP/1.1 200 Fixture\r\nContent-Length: 1000\r\nx-ms-request-id: fixture-request\r\n\r\n{\"status\":\"Waiting\"",
    ] {
        env.set("MXC_W365_TEST_READY_BUDGET_MS", "2000");
        let before = fixture.count();
        let error = std::thread::scope(|scope| {
            let held = fixture.hold_reply(prefix);
            let (completed, result) = mpsc::channel();
            let client = scope.spawn(move || {
                completed.send(invoke(&request("start", A), true)).unwrap();
            });
            let ready = held.ready.recv_timeout(Duration::from_secs(15));
            let began = Instant::now();
            let outcome = result.recv_timeout(Duration::from_secs(5));
            drop(held);
            client.join().unwrap();
            ready.expect("readiness request must reach the held response");
            let error = outcome
                .expect("readiness budget must interrupt the response")
                .unwrap_err();
            assert!(began.elapsed() < Duration::from_secs(5));
            error
        });
        assert_eq!(error.details.unwrap()["code"], "attach_timeout");
        assert_eq!(fixture.count(), before + 1, "readiness must not retry after expiry");
    }
    std::env::remove_var("MXC_W365_TEST_READY_BUDGET_MS");
    fixture.reply(200, r#"{"status":"Ready"}"#);
    let ready = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("small-foreign-stack".into())
            .stack_size(128 * 1024)
            .spawn_scoped(scope, || {
                mxc_sdk::v1::dev::start_container_json(
                    &request("start", A).to_string(),
                    mxc_sdk::v1::dev::JsonOptions { experimental: true },
                )
            })
            .unwrap()
            .join()
            .unwrap()
            .unwrap()
    });
    let ready: Value = serde_json::from_str(&ready).unwrap();
    assert_eq!(ready["result"]["metadata"]["status"], "Ready");
    assert_eq!(fixture.count(), n + 4);
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|request| request.starts_with("GET ")));
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
const FIXTURE_IDENTITY_PASSWORD: &str = "fixture-only";

struct FixtureCertificate {
    certificate: String,
    key: String,
}

impl FixtureCertificate {
    fn new(hostname: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let key = directory.path().join("key.pem");
        let config = directory.path().join("openssl.cnf");
        // Keep host OpenSSL defaults from adding duplicate certificate extensions.
        std::fs::write(
            &config,
            format!(
                "[req]\n\
                 distinguished_name=dn\n\
                 x509_extensions=server\n\
                 [dn]\n\
                 [server]\n\
                 subjectAltName=DNS:{hostname}\n\
                 basicConstraints=critical,CA:FALSE\n\
                 keyUsage=critical,digitalSignature\n\
                 extendedKeyUsage=serverAuth\n"
            ),
        )
        .unwrap();
        let output = fixture_openssl()
            .args(["req", "-config"])
            .arg(&config)
            .args([
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "1",
                "-subj",
                &format!("/CN={hostname}"),
                "-out",
            ])
            .arg(&certificate)
            .arg("-keyout")
            .arg(&key)
            .output()
            .expect("W365 TLS fixtures require openssl on PATH or MXC_W365_TEST_OPENSSL");
        assert!(
            output.status.success(),
            "fixture certificate generation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            certificate: std::fs::read_to_string(certificate).unwrap(),
            key: std::fs::read_to_string(key).unwrap(),
        }
    }
}

fn fixture_openssl() -> std::process::Command {
    std::process::Command::new(
        std::env::var_os("MXC_W365_TEST_OPENSSL").unwrap_or_else(|| "openssl".into()),
    )
}

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
fn fixture_pkcs12(cert: &FixtureCertificate) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("certificate.pem");
    let key = directory.path().join("key.pem");
    let archive = directory.path().join("identity.p12");
    std::fs::write(&certificate, &cert.certificate).unwrap();
    std::fs::write(&key, &cert.key).unwrap();
    // macOS imports the fixture identity as PKCS#12. These algorithms work
    // with its identity importer; they do not configure TLS or production crypto.
    let output = fixture_openssl()
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
fn fixture_tls(cert: &FixtureCertificate) -> (schannel::schannel_cred::SchannelCred, FixtureKey) {
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
fn fixture_tls(cert: &FixtureCertificate) -> native_tls::TlsAcceptor {
    #[cfg(target_os = "macos")]
    let identity =
        native_tls::Identity::from_pkcs12(&fixture_pkcs12(cert), FIXTURE_IDENTITY_PASSWORD)
            .unwrap();
    #[cfg(not(target_os = "macos"))]
    let identity =
        native_tls::Identity::from_pkcs8(cert.certificate.as_bytes(), cert.key.as_bytes()).unwrap();
    native_tls::TlsAcceptor::new(identity).unwrap()
}

struct Environment(
    Vec<(&'static str, Option<std::ffi::OsString>)>,
    tempfile::TempDir,
);
impl Environment {
    fn new() -> Self {
        let state = tempfile::tempdir().unwrap();
        let environment = Self(
            [
                "W365A_CP_TOKEN",
                "W365A_DP_SUFFIX",
                "W365A_DP_TOKEN",
                "W365A_GRAPH_TOKEN",
                "W365A_GRAPH_ENVIRONMENT",
                "MXC_W365_TEST_GRAPH_LOCALHOST",
                "MXC_W365_TEST_STATE_ROOT",
                "MXC_W365_TEST_STATE_WRITE_FAIL",
                "MXC_W365_TEST_CA",
                "MXC_W365_TEST_PORT",
                "MXC_W365_TEST_TIMEOUT_MS",
                "MXC_W365_TEST_READY_BUDGET_MS",
                "MXC_W365_TEST_DNS_DELAY_MS",
                "MXC_W365_TEST_EXEC_ELAPSED_MS",
            ]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect(),
            state,
        );
        environment.set("W365A_GRAPH_TOKEN", "synthetic-graph-token");
        environment.set("W365A_GRAPH_ENVIRONMENT", "public");
        environment.set("MXC_W365_TEST_GRAPH_LOCALHOST", "1");
        environment.set(
            "MXC_W365_TEST_STATE_ROOT",
            environment
                .1
                .path()
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap(),
        );
        environment.seed(A);
        environment.seed(B);
        std::env::remove_var("MXC_W365_TEST_TIMEOUT_MS");
        std::env::remove_var("MXC_W365_TEST_READY_BUDGET_MS");
        std::env::remove_var("MXC_W365_TEST_DNS_DELAY_MS");
        std::env::remove_var("MXC_W365_TEST_EXEC_ELAPSED_MS");
        std::env::remove_var("MXC_W365_TEST_STATE_WRITE_FAIL");
        environment
    }
    fn set(&self, key: &str, value: &str) {
        std::env::set_var(key, value);
    }
    fn record(&self, session: &str) -> std::path::PathBuf {
        self.record_for_pool(POOL, session)
    }
    fn record_for_pool(&self, pool: &str, session: &str) -> std::path::PathBuf {
        self.1
            .path()
            .join("Microsoft")
            .join("MXC")
            .join("w365")
            .join(pool)
            .join(session)
            .join("connection.json")
    }
    fn seed(&self, session: &str) {
        let path = self.record(session);
        let directory = path.parent().unwrap();
        #[cfg(windows)]
        {
            use mxc_sdk::mxc_common::filesystem_security::*;
            let _guard = lock_owner_only_directory_path(
                self.1.path(),
                &[
                    "Microsoft".as_ref(),
                    "MXC".as_ref(),
                    "w365".as_ref(),
                    POOL.as_ref(),
                    session.as_ref(),
                ],
                2,
            )
            .unwrap();
            for path in [
                directory,
                directory.parent().unwrap(),
                directory.parent().unwrap().parent().unwrap(),
            ] {
                set_current_user_owner(path).unwrap();
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
                .unwrap();
        }
        std::fs::write(&path, json!({
            "version":1,"poolId":POOL,"sessionId":session,
            "controlPlaneHost":"localhost","controlPlaneSource":"environment","computerHost":"localhost",
        }).to_string()).unwrap();
        #[cfg(windows)]
        {
            use mxc_sdk::mxc_common::filesystem_security::*;
            set_owner_only_dacl(&path, false).unwrap();
            set_current_user_owner(&path).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
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
    graph_requests: Arc<Mutex<Vec<String>>>,
    graph_replies: Arc<Mutex<std::collections::VecDeque<FixtureReply>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    #[cfg(target_os = "windows")]
    _key: Option<FixtureKey>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_hostname("localhost")
    }
    fn with_hostname(hostname: &str) -> Self {
        let cert = FixtureCertificate::new(hostname);
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(cert.certificate.as_bytes()).unwrap();
        #[cfg(target_os = "windows")]
        let (tls, key) = fixture_tls(&cert);
        #[cfg(not(target_os = "windows"))]
        let tls = fixture_tls(&cert);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(std::collections::VecDeque::<FixtureReply>::new()));
        let graph_requests = Arc::new(Mutex::new(Vec::new()));
        let graph_replies = Arc::new(Mutex::new(std::collections::VecDeque::<FixtureReply>::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, responses, stopping) = (requests.clone(), replies.clone(), stop.clone());
        let (graph_seen, graph_responses) = (graph_requests.clone(), graph_replies.clone());
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
                    Err(error) => {
                        eprintln!("W365 loopback fixture server TLS handshake failed: {error:?}");
                        continue;
                    }
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
                let header_end = data.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
                let header = String::from_utf8_lossy(&data[..header_end]);
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while data.len() < header_end + length {
                    let n = stream.read(&mut buf).unwrap();
                    assert_ne!(n, 0);
                    data.extend_from_slice(&buf[..n]);
                }
                let data = String::from_utf8(data).unwrap();
                let graph = data.starts_with("GET /beta/me/cloudPcPools")
                    || data.starts_with("GET /testprodbeta_cpc_sh/me/cloudPcPools")
                    || data.starts_with("GET /beta/deviceManagement/virtualEndpoint/cloudPcPools/")
                    || data.starts_with(
                        "GET /testprodbeta_cpc_sh/deviceManagement/virtualEndpoint/cloudPcPools/",
                    );
                let reply = if graph {
                    let body = if data.contains("/deviceManagement/virtualEndpoint/cloudPcPools/") {
                        let path = data.split_whitespace().nth(1).unwrap();
                        let pool = path.rsplit('/').next().unwrap();
                        graph_pool(pool, 1).to_string()
                    } else {
                        json!({"value":[]}).to_string()
                    };
                    graph_seen.lock().unwrap().push(data);
                    graph_responses.lock().unwrap().pop_front().or_else(|| {
                        Some(FixtureReply::Complete(format!(
                            "HTTP/1.1 200 Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())))
                    })
                } else {
                    seen.lock().unwrap().push(data);
                    responses.lock().unwrap().pop_front()
                };
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
            graph_requests,
            graph_replies,
            stop,
            worker: Some(worker),
            #[cfg(target_os = "windows")]
            _key: Some(key),
        }
    }
    fn configure(&self, env: &Environment) {
        env.set("W365A_CP_TOKEN", "fixture-token-never-log");
        env.set("MXC_W365_TEST_CA", self.ca.path().to_str().unwrap());
        env.set("MXC_W365_TEST_PORT", &self.port.to_string());
    }
    fn graph_reply(&self, status: u16, body: Value) {
        let body = body.to_string();
        self.graph_replies
            .lock()
            .unwrap()
            .push_back(FixtureReply::Complete(format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )));
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
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn provision() -> Value {
    json!({"version":"1.1.0-alpha", "phase":"provision", "containment":"w365_agents",
        "w365Agents":{"provision":{"poolId":POOL,"userObjectId":B}}})
}
fn computer_url(session: &str) -> String {
    format!("https://localhost/computers/{session}?api-version=1.0")
}
fn pool_url(pool: &str) -> String {
    format!("https://localhost/api/pools/{pool}/sessions")
}
fn graph_pool(pool: &str, available_sessions: i32) -> Value {
    json!({
        "id":pool,
        "poolUrl":pool_url(pool),
        "sessionUsage":{"availableSessionsCount":available_sessions},
    })
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
    for key in ["W365A_GRAPH_TOKEN", "W365A_CP_TOKEN"] {
        std::env::remove_var(key);
        assert_eq!(
            invoke(&provision(), true).unwrap_err().code,
            MxcErrorCode::PolicyValidation
        );
        fixture.configure(&env);
        env.set("W365A_GRAPH_TOKEN", "synthetic-graph-token");
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
    for key in ["W365A_DP_SUFFIX", "W365A_DP_TOKEN"] {
        std::env::remove_var(key);
    }
    for phase in ["start", "exec"] {
        let error = invoke(&request(phase, A), true).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation, "{error:?}");
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
        for phase in ["provision", "stop"] {
            let mut value = if phase == "provision" {
                provision()
            } else {
                request(phase, A)
            };
            value[key] = json!({});
            assert_eq!(
                invoke(&value, true).unwrap_err().code,
                MxcErrorCode::MalformedRequest,
                "{key}/{phase}"
            );
        }
    }
    let policy_errors = [
        ("network", json!({})),
        (
            "runtimeConfig",
            json!({"networkProxy":"http://127.0.0.1:8080"}),
        ),
    ]
    .map(|(key, policy)| {
        let mut value = request("exec", A);
        value[key] = policy;
        (key, invoke(&value, true).unwrap_err().code)
    });
    assert_eq!(
        policy_errors,
        [
            ("network", MxcErrorCode::PolicyValidation),
            ("runtimeConfig", MxcErrorCode::PolicyValidation),
        ]
    );
    assert_eq!(
        fixture.count(),
        before,
        "exec policy refusal must not call the service"
    );
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

    let wrong_ca = FixtureCertificate::new("localhost");
    let mut wrong_file = tempfile::NamedTempFile::new().unwrap();
    wrong_file
        .write_all(wrong_ca.certificate.as_bytes())
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
                mxc_sdk::v1::ErrorCode::PolicyValidation
            );
        }
        assert_eq!(
            fixture.count(),
            before,
            "SDK validation cannot use the service"
        );
        fixture.reply(
            200,
            &json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)}).to_string(),
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
        json!({"sessionId":A,"computerId":A,"status":"Succeeded","computerUrl":computer_url(A)}),
        json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)}),
    ] {
        fixture.reply(200, &body.to_string());
        assert_eq!(
            invoke(&provision(), true).unwrap()["result"]["sandboxId"],
            format!("w365:{POOL}:{A}")
        );
    }
    let first = fixture.request(first_checkout).to_ascii_lowercase();
    assert!(first.starts_with(&format!("post /api/pools/{POOL}/sessions?api-version=3.0 ")));
    assert!(!first.contains("user-type:"));
    assert!(!first.contains("user-object-id:"));
    assert!(first.contains("x-ms-client-request-id:"));
    let mut human = provision();
    human["w365Agents"]["provision"]["userType"] = json!("HumanUser");
    human["w365Agents"]["provision"]["userObjectId"] = json!(B);
    fixture.reply(
        200,
        &json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)}).to_string(),
    );
    invoke(&human, true).unwrap();
    let sent = fixture.request(first_checkout + 2);
    assert!(!sent.to_ascii_lowercase().contains("user-type:"));
    assert!(sent.contains(B));
    assert_eq!(
        serde_json::from_str::<Value>(sent.split_once("\r\n\r\n").unwrap().1).unwrap(),
        json!({"userObjectId":B,"sessionKind":"human"}),
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
            &json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)}).to_string(),
        );
        let n = fixture.count();
        invoke(&value, true).unwrap();
        let sent = fixture.request(n);
        assert!(!sent.to_ascii_lowercase().contains("user-type:"));
        assert!(!sent.to_ascii_lowercase().contains("user-object-id:"));
        let body: Value = serde_json::from_str(sent.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["userObjectId"], B);
        assert_eq!(body.get("sessionKind").is_some(), kind);
    }
    for user_type in ["Local", "HumanUser", "Agentic"] {
        for oid in [false, true] {
            let mut value = provision();
            value["w365Agents"]["provision"]["userType"] = json!(user_type);
            if oid {
                value["w365Agents"]["provision"]["userObjectId"] = json!(B);
            } else {
                value["w365Agents"]["provision"]
                    .as_object_mut()
                    .unwrap()
                    .remove("userObjectId");
            }
            let n = fixture.count();
            assert!(invoke(&value, false).is_err());
            assert_eq!(fixture.count(), n, "all user types require authorization");
            if !oid || user_type == "Agentic" {
                assert_eq!(
                    invoke(&value, true).unwrap_err().code,
                    MxcErrorCode::PolicyValidation
                );
                assert_eq!(fixture.count(), n);
                continue;
            }
            fixture.reply(
                200,
                &json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)})
                    .to_string(),
            );
            invoke(&value, true).unwrap();
            let sent = fixture.request(n);
            assert!(!sent.contains("user-type:"));
            assert!(!sent.contains("user-object-id:"));
            let body: Value = serde_json::from_str(sent.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(
                body,
                json!({"userObjectId":B,"sessionKind":if user_type=="Local" {"local"} else {"human"}})
            );
        }
    }
    let upper = "AAAAAAAA-bbbb-CCCC-dddd-EEEEEEEEEEEE";
    let mut value = provision();
    value["w365Agents"]["provision"]["poolId"] = json!(upper);
    fixture.reply(
        200,
        &json!({
            "sessionId":upper,"computerId":upper.to_ascii_lowercase(),"status":"Succeeded",
            "computerUrl":computer_url(&upper.to_ascii_lowercase()),
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
        203,
        &json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)}).to_string(),
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
        &json!({"sessionId":B,"status":"Succeeded","computerUrl":computer_url(B)}).to_string(),
    );
    invoke(&provision(), true).unwrap();
    fixture.reply(204, "");
    invoke(&request("deprovision", A), true).unwrap();
    assert!(fixture
        .request(fixture.count() - 1)
        .starts_with(&format!("DELETE /api/sessions/{A}?")));

    // Completion must address the allocated ID, never allocate a replacement.
    let before = fixture.count();
    fixture.reply(201, &json!({"sessionId":A,"status":"Created"}).to_string());
    fixture.reply(
        200,
        &json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)}).to_string(),
    );
    invoke(&provision(), true).unwrap();
    let first = fixture.request(before);
    let completed = fixture.request(before + 1);
    assert!(completed
        .to_ascii_lowercase()
        .contains(&format!("x-ms-sessionid: {A}")));
    assert_eq!(completed.split_once("\r\n\r\n").unwrap().1, "{}");
    let client_request_id = |request: &str| {
        request
            .lines()
            .find(|line| {
                line.to_ascii_lowercase()
                    .starts_with("x-ms-client-request-id:")
            })
            .unwrap()
            .to_owned()
    };
    assert_eq!(client_request_id(&first), client_request_id(&completed));

    let graph_before = fixture.graph_requests.lock().unwrap().len();
    let before = fixture.count();
    let root = std::env::var("MXC_W365_TEST_STATE_ROOT").unwrap();
    env.set("MXC_W365_TEST_STATE_ROOT", "relative-state-is-not-allowed");
    assert_eq!(
        invoke(&provision(), true).unwrap_err().details.unwrap()["code"],
        "routing_state_root"
    );
    assert_eq!(fixture.graph_requests.lock().unwrap().len(), graph_before);
    assert_eq!(
        fixture.count(),
        before,
        "storage preflight must precede discovery and allocation"
    );
    env.set("MXC_W365_TEST_STATE_ROOT", &root);
    let mut automatic = provision();
    automatic["w365Agents"]["provision"]
        .as_object_mut()
        .unwrap()
        .remove("poolId");
    for (status, body) in [
        (401, json!({})),
        (404, json!({})),
        (429, json!({})),
        (200, json!({"value":[{"id":POOL},{"id":POOL}]})),
        (
            200,
            json!({"value":[], "@odata.nextLink":"https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPcPools"}),
        ),
    ] {
        fixture.graph_reply(status, body);
        assert!(invoke(&automatic, true).is_err());
        assert_eq!(
            fixture.count(),
            before,
            "discovery errors cannot fall back or allocate"
        );
    }
    for (status, body) in [
        (401, json!({})),
        (403, json!({})),
        (404, json!({})),
        (429, json!({})),
        (500, json!({})),
        (302, json!({})),
        (200, json!(null)),
        (200, json!({"value":[{"id":POOL}]})),
        (200, graph_pool(A, 1)),
        (
            200,
            json!({"id":POOL,"poolUrl":123,"sessionUsage":{"availableSessionsCount":1}}),
        ),
        (
            200,
            json!({"id":POOL,"poolUrl":"http://localhost/sessions","sessionUsage":{"availableSessionsCount":1}}),
        ),
        (
            200,
            json!({"id":POOL,"poolUrl":"https://localhost/sessions#fragment","sessionUsage":{"availableSessionsCount":1}}),
        ),
        (
            200,
            json!({"id":POOL,"poolUrl":"https://user:secret@localhost/sessions","sessionUsage":{"availableSessionsCount":1}}),
        ),
    ] {
        let graphs = fixture.graph_requests.lock().unwrap().len();
        fixture.graph_reply(status, body);
        assert!(invoke(&provision(), true).is_err());
        assert_eq!(fixture.graph_requests.lock().unwrap().len(), graphs + 1);
        assert_eq!(
            fixture.count(),
            before,
            "pool resource errors cannot fall back or allocate"
        );
    }
    for pool in [
        json!({"id":POOL,"sessionUsage":{"availableSessionsCount":1}}),
        json!({"id":POOL,"poolUrl":null,"sessionUsage":{"availableSessionsCount":1}}),
        json!({"id":POOL,"poolUrl":"","sessionUsage":{"availableSessionsCount":1}}),
    ] {
        let calls = fixture.count();
        fixture.graph_reply(200, pool);
        let error = invoke(&provision(), true).unwrap_err();
        assert_eq!(error.details.unwrap()["code"], "invalid_pool_url");
        assert_eq!(
            fixture.count(),
            calls,
            "missing resource poolUrl must fail before checkout"
        );
    }
    let discovered = "55555555-5555-5555-5555-555555555555";
    for (url, target) in [
        (
            pool_url(POOL),
            format!("/api/pools/{POOL}/sessions?api-version=3.0"),
        ),
        (
            format!("https://localhost/api/pools/{POOL}/sessions?route=blue%2Fgreen"),
            format!("/api/pools/{POOL}/sessions?route=blue%2Fgreen&api-version=3.0"),
        ),
        (
            "https://localhost/graph-owned/checkout?route=blue%2Fgreen".to_owned(),
            "/graph-owned/checkout?route=blue%2Fgreen&api-version=3.0".to_owned(),
        ),
        (
            "https://localhost/sessions".to_owned(),
            "/sessions?api-version=3.0".to_owned(),
        ),
    ] {
        let calls = fixture.count();
        let mut pool = graph_pool(POOL, 1);
        pool["poolUrl"] = json!(url);
        fixture.graph_reply(200, pool);
        fixture.reply(
            201,
            &json!({"sessionId":discovered,"status":"Created"}).to_string(),
        );
        fixture.reply(
            200,
            &json!({"sessionId":discovered,"status":"Succeeded","computerUrl":computer_url(discovered)}).to_string(),
        );
        invoke(&provision(), true).unwrap();
        assert_eq!(fixture.count(), calls + 2);
        for offset in 0..2 {
            assert!(
                fixture
                    .request(calls + offset)
                    .starts_with(&format!("POST {target} ")),
                "checkout and same-ID completion must preserve Graph's path and query"
            );
        }
        assert!(fixture
            .request(calls + 1)
            .to_ascii_lowercase()
            .contains(&format!("x-ms-sessionid: {discovered}")));
        let stored = std::fs::read_to_string(env.record(discovered)).unwrap();
        assert!(!stored.contains("graph-owned") && !stored.contains("route="));
        let record: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(record["controlPlaneHost"], "localhost");
        assert_eq!(record["controlPlaneSource"], "graph");
    }
    let graphs = fixture.graph_requests.lock().unwrap().len();
    fixture.reply(204, "");
    invoke(&request("deprovision", discovered), true).unwrap();
    assert!(fixture.request(fixture.count() - 1).starts_with(&format!(
        "DELETE /api/sessions/{discovered}?api-version=2.0 "
    )));
    assert_eq!(fixture.graph_requests.lock().unwrap().len(), graphs);
    let c = "44444444-4444-4444-4444-444444444444";
    let graphs = fixture.graph_requests.lock().unwrap().len();
    fixture.graph_reply(200, json!({"value":[], "@odata.nextLink":"https://graph.microsoft.com/beta/me/cloudPcPools?$skiptoken=fixture"}));
    fixture.graph_reply(200, json!({"value":[{"id":POOL}]}));
    fixture.graph_reply(200, graph_pool(POOL, 1));
    fixture.reply(
        200,
        &json!({"sessionId":c,"status":"Succeeded","computerUrl":computer_url(c),
        "mcpUrl":"https://invalid/?ticket=must-not-persist"})
        .to_string(),
    );
    invoke(&automatic, true).unwrap();
    let stored = std::fs::read_to_string(env.record(c)).unwrap();
    assert!(!stored.contains("token") && !stored.contains("ticket"));
    let record: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(record["controlPlaneSource"], "graph");
    assert_eq!(record["computerHost"], "localhost");
    {
        let requests = fixture.graph_requests.lock().unwrap();
        assert_eq!(requests.len(), graphs + 3);
        assert!(requests[graphs].starts_with("GET /beta/me/cloudPcPools "));
        assert!(requests[graphs + 1].starts_with("GET /beta/me/cloudPcPools?$skiptoken=fixture "));
        assert!(requests[graphs + 2].starts_with(&format!(
            "GET /beta/deviceManagement/virtualEndpoint/cloudPcPools/{POOL} "
        )));
    }
    env.set("W365A_GRAPH_ENVIRONMENT", "canary");
    let graphs = fixture.graph_requests.lock().unwrap().len();
    fixture.graph_reply(200, graph_pool(POOL, 1));
    fixture.reply(
        200,
        &json!({"sessionId":c,"status":"Succeeded","computerUrl":computer_url(c)}).to_string(),
    );
    invoke(&provision(), true).unwrap();
    {
        let requests = fixture.graph_requests.lock().unwrap();
        assert_eq!(requests.len(), graphs + 1);
        assert!(requests[graphs].starts_with(&format!(
            "GET /testprodbeta_cpc_sh/deviceManagement/virtualEndpoint/cloudPcPools/{POOL} "
        )));
    }
    env.set("W365A_GRAPH_ENVIRONMENT", "public");
    for available in [-1, 0] {
        let graphs = fixture.graph_requests.lock().unwrap().len();
        let calls = fixture.count();
        fixture.graph_reply(200, json!({"value":[{"id":POOL},{"id":B}]}));
        fixture.graph_reply(
            200,
            json!({
                "id":POOL,"sessionUsage":{"availableSessionsCount":available},
            }),
        );
        fixture.graph_reply(200, graph_pool(B, 1));
        fixture.reply(
            200,
            &json!({"sessionId":c,"status":"Succeeded","computerUrl":computer_url(c)}).to_string(),
        );
        let selected = invoke(&automatic, true).unwrap();
        assert_eq!(selected["result"]["sandboxId"], format!("w365:{B}:{c}"));
        assert_eq!(selected["result"]["metadata"]["poolId"], B);
        assert_eq!(
            fixture.count(),
            calls + 1,
            "an unavailable pool must not receive checkout"
        );
        assert!(fixture
            .request(calls)
            .starts_with(&format!("POST /api/pools/{B}/sessions?api-version=3.0 ")));
        assert_eq!(fixture.graph_requests.lock().unwrap().len(), graphs + 3);
        let record: Value =
            serde_json::from_slice(&std::fs::read(env.record_for_pool(B, c)).unwrap()).unwrap();
        assert_eq!(record["poolId"], B);
    }
    for list_pools in [false, true] {
        let graphs = fixture.graph_requests.lock().unwrap().len();
        let calls = fixture.count();
        let value = if list_pools {
            automatic.clone()
        } else {
            provision()
        };
        let pools: &[&str] = if list_pools { &[POOL, B] } else { &[POOL] };
        if list_pools {
            fixture.graph_reply(200, json!({"value":[{"id":POOL},{"id":B}]}));
        }
        for pool in pools {
            fixture.graph_reply(200, graph_pool(pool, 0));
        }
        let error = invoke(&value, true).unwrap_err();
        assert_eq!(error.details.unwrap()["code"], "no_available_sessions");
        assert_eq!(fixture.count(), calls, "no capacity must mean no checkout");
        assert_eq!(
            fixture.graph_requests.lock().unwrap().len(),
            graphs + if list_pools { 3 } else { 1 },
        );
    }
    for usage in [
        None,
        Some(json!(null)),
        Some(json!({})),
        Some(json!({"availableSessionsCount":null})),
        Some(json!({"availableSessionsCount":"1"})),
        Some(json!({"availableSessionsCount":1.5})),
        Some(json!({"availableSessionsCount":2147483648_i64})),
    ] {
        let graphs = fixture.graph_requests.lock().unwrap().len();
        let calls = fixture.count();
        let mut pool = graph_pool(POOL, 1);
        if let Some(usage) = usage {
            pool["sessionUsage"] = usage;
        } else {
            pool.as_object_mut().unwrap().remove("sessionUsage");
        }
        fixture.graph_reply(200, json!({"value":[{"id":POOL},{"id":B}]}));
        fixture.graph_reply(200, pool);
        let error = invoke(&automatic, true).unwrap_err();
        assert_eq!(error.details.unwrap()["code"], "graph_response");
        assert_eq!(
            fixture.count(),
            calls,
            "invalid capacity must not reach checkout"
        );
        assert_eq!(
            fixture.graph_requests.lock().unwrap().len(),
            graphs + 2,
            "invalid discovery metadata must not be skipped",
        );
    }
    let graphs = fixture.graph_requests.lock().unwrap().len();
    let calls = fixture.count();
    fixture.graph_reply(200, json!({"value":[{"id":B},{"id":POOL}]}));
    fixture.graph_reply(200, graph_pool(B, 1));
    fixture.reply(
        200,
        &json!({
            "sessionId":c,"status":"Succeeded","computerUrl":computer_url(c)
        })
        .to_string(),
    );
    let selected = invoke(&automatic, true).unwrap();
    assert_eq!(selected["result"]["sandboxId"], format!("w365:{B}:{c}"));
    let selected_record: Value =
        serde_json::from_slice(&std::fs::read(env.record_for_pool(B, c)).unwrap()).unwrap();
    assert_eq!(selected_record["poolId"], B);
    assert_eq!(selected_record["controlPlaneSource"], "graph");
    assert_eq!(fixture.count(), calls + 1);
    assert!(fixture
        .request(calls)
        .starts_with(&format!("POST /api/pools/{B}/sessions?api-version=3.0 ")));
    assert_eq!(fixture.graph_requests.lock().unwrap().len(), graphs + 2);
    assert!(
        fixture.graph_requests.lock().unwrap()[graphs + 1].starts_with(&format!(
            "GET /beta/deviceManagement/virtualEndpoint/cloudPcPools/{B} "
        ))
    );

    let graphs = fixture.graph_requests.lock().unwrap().len();
    let calls = fixture.count();
    fixture.graph_reply(200, json!({"value":[{"id":POOL},{"id":B}]}));
    for pool in [POOL, B] {
        fixture.graph_reply(200, graph_pool(pool, 1));
    }
    fixture.reply(403, "{}");
    fixture.reply(
        200,
        &json!({"sessionId":c,"status":"Succeeded","computerUrl":computer_url(c)}).to_string(),
    );
    let selected = invoke(&automatic, true).unwrap();
    assert_eq!(selected["result"]["sandboxId"], format!("w365:{B}:{c}"));
    assert_eq!(fixture.count(), calls + 2);
    for (offset, pool) in [POOL, B].into_iter().enumerate() {
        assert!(fixture
            .request(calls + offset)
            .starts_with(&format!("POST /api/pools/{pool}/sessions?api-version=3.0 ")));
    }
    assert_eq!(fixture.graph_requests.lock().unwrap().len(), graphs + 3);

    fixture.graph_reply(200, json!({"value":[{"id":POOL},{"id":B}]}));
    for pool in [POOL, B] {
        fixture.graph_reply(200, graph_pool(pool, 1));
        fixture.reply(429, "{}");
    }
    let error = invoke(&automatic, true).unwrap_err();
    assert_eq!(
        error.details.as_ref().unwrap()["poolAttempts"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(error.details.as_ref().unwrap()["httpStatus"], 429);
    assert!(error.details.as_ref().unwrap().get("sandboxId").is_none());
    assert!(error.message.contains("pool checkout attempts=2"));

    for (status, response, write_failure) in [
        (403, json!({"sessionId":A}), false),
        (408, json!({}), false),
        (500, json!({}), false),
        (302, json!({}), false),
        (200, json!({"sessionId":A,"status":"Succeeded"}), false),
        (
            200,
            json!({"sessionId":"88888888-8888-8888-8888-888888888888",
            "status":"Succeeded",
            "computerUrl":computer_url("88888888-8888-8888-8888-888888888888")}),
            true,
        ),
    ] {
        let graphs = fixture.graph_requests.lock().unwrap().len();
        let calls = fixture.count();
        fixture.graph_reply(200, json!({"value":[{"id":POOL},{"id":B}]}));
        fixture.graph_reply(200, graph_pool(POOL, 1));
        fixture.reply(status, &response.to_string());
        if write_failure {
            env.set("MXC_W365_TEST_STATE_WRITE_FAIL", "1");
        }
        let result = invoke(&automatic, true);
        std::env::remove_var("MXC_W365_TEST_STATE_WRITE_FAIL");
        let error = result.unwrap_err();
        if write_failure {
            assert_eq!(
                error.details.as_ref().unwrap()["code"],
                "routing_state_write"
            );
        }
        assert_eq!(
            fixture.count(),
            calls + 1,
            "uncertain/allocated checkout cannot try another pool"
        );
        assert_eq!(fixture.graph_requests.lock().unwrap().len(), graphs + 2);
        assert_eq!(
            error.details.as_ref().unwrap().get("sessionId").is_some(),
            response.get("sessionId").is_some()
        );
    }
    let calls = fixture.count();
    fixture.graph_reply(200, json!({"value":[]}));
    assert_eq!(
        invoke(&automatic, true).unwrap_err().details.unwrap()["code"],
        "no_assigned_pools"
    );
    assert_eq!(fixture.count(), calls);
    for sent in &fixture.graph_requests.lock().unwrap()[graph_before..] {
        assert!(sent.contains("Bearer synthetic-graph-token"));
        assert!(!sent.contains("renewed-fixture-token"));
    }
    let graphs = fixture.graph_requests.lock().unwrap().len();
    std::env::remove_var("W365A_GRAPH_TOKEN");
    env.set("W365A_DP_SUFFIX", "must-not-use.invalid");
    env.set("W365A_DP_TOKEN", "separate-routing-fixture-token");
    fixture.reply(200, r#"{"status":"Ready"}"#);
    invoke(&request("start", c), true).unwrap();
    assert!(fixture
        .request(fixture.count() - 1)
        .contains("Bearer separate-routing-fixture-token"));
    fixture.reply(202, "");
    invoke(&request("stop", c), true).unwrap();
    assert!(
        env.record(c).exists(),
        "accepted release retains recovery routing"
    );
    assert_eq!(fixture.graph_requests.lock().unwrap().len(), graphs);
    fixture.configure(&env);
    env.set("W365A_GRAPH_TOKEN", "synthetic-graph-token");
    let before = fixture.count();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(env.record(c).with_file_name("connection.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    std::thread::scope(|scope| {
        let calls: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| invoke(&request("deprovision", c), true).unwrap_err()))
            .collect();
        for call in calls {
            assert_eq!(
                call.join().unwrap().details.unwrap()["code"],
                "routing_state_lock"
            );
        }
    });
    drop(lock);
    assert_eq!(
        fixture.count(),
        before,
        "contended records cannot route a request"
    );
    #[cfg(windows)]
    {
        use mxc_sdk::mxc_common::filesystem_security::set_owner_only_dacl;
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
        use windows::Win32::Security::Authorization::{
            GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            UNPROTECTED_DACL_SECURITY_INFORMATION,
        };
        let path: Vec<_> = env
            .record(c)
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        assert_eq!(
            unsafe {
                GetNamedSecurityInfoW(
                    PCWSTR(path.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(&mut dacl),
                    None,
                    &mut descriptor,
                )
            },
            ERROR_SUCCESS
        );
        let changed = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(path.as_ptr()),
                SE_FILE_OBJECT,
                OBJECT_SECURITY_INFORMATION(
                    DACL_SECURITY_INFORMATION.0 | UNPROTECTED_DACL_SECURITY_INFORMATION.0,
                ),
                None,
                None,
                Some(dacl.cast_const()),
                None,
            )
        };
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        assert_eq!(changed, ERROR_SUCCESS);
        assert_eq!(
            invoke(&request("start", c), true)
                .unwrap_err()
                .details
                .unwrap()["code"],
            "routing_state_permissions"
        );
        set_owner_only_dacl(&env.record(c), false).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(env.record(c), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(invoke(&request("start", c), true).is_err());
        std::fs::set_permissions(env.record(c), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    for malformed in [
        "{}".to_owned(),
        stored.replace("\"version\":1", "\"version\":2"),
        stored.replace(c, B),
        stored.replace(
            "\"computerHost\":\"localhost\"",
            "\"computerHost\":\"untrusted.invalid\"",
        ),
    ] {
        std::fs::write(env.record(c), malformed).unwrap();
        assert!(invoke(&request("start", c), true).is_err());
        assert!(invoke(&request("deprovision", c), true).is_err());
        assert_eq!(fixture.count(), before);
    }
    std::fs::remove_file(env.record(c)).unwrap();
    assert!(invoke(&request("deprovision", c), true).is_err());
    assert_eq!(
        fixture.count(),
        before,
        "missing record cannot use ambient endpoints"
    );
    std::fs::hard_link(env.record(A), env.record(c)).unwrap();
    assert!(invoke(&request("deprovision", c), true).is_err());
    std::fs::remove_file(env.record(c)).unwrap();
    assert_eq!(
        fixture.count(),
        before,
        "linked records cannot route a request"
    );

    // An allocated ID survives a failed atomic publication, without a false success.
    env.set("MXC_W365_TEST_STATE_WRITE_FAIL", "1");
    fixture.reply(
        200,
        &json!({"sessionId":c,"status":"Succeeded","computerUrl":computer_url(c)}).to_string(),
    );
    let failure = invoke(&provision(), true).unwrap_err();
    assert!(failure.message.contains("service-operator cleanup"));
    assert!(failure.message.contains("controlPlaneHost=localhost"));
    assert_eq!(
        failure.details.as_ref().unwrap()["sandboxId"],
        format!("w365:{POOL}:{c}")
    );
    assert_eq!(
        failure.details.as_ref().unwrap()["controlPlaneHost"],
        "localhost"
    );
    assert!(!env.record(c).exists());
    assert!(std::fs::read_dir(env.record(c).parent().unwrap())
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    std::env::remove_var("MXC_W365_TEST_STATE_WRITE_FAIL");
    for url in [
        format!("https://localhost/computers/{B}?api-version=1.0"),
        format!("https://localhost/computers/{c}?api-version=1.0&ticket=must-not-persist"),
        format!("https://untrusted.invalid/computers/{c}?api-version=1.0"),
    ] {
        fixture.reply(
            200,
            &json!({"sessionId":c,"status":"Succeeded","computerUrl":url}).to_string(),
        );
        let failure = invoke(&provision(), true).unwrap_err();
        assert_eq!(
            failure.details.as_ref().unwrap()["code"],
            "invalid_computer_url"
        );
        assert!(!format!("{failure:?}").contains("must-not-persist"));
    }
    fixture.reply(
        200,
        &json!({"sessionId":c,"status":"Succeeded",
        "mcpUrl":"https://localhost/computers/not-a-computer-resource"})
        .to_string(),
    );
    let failure = invoke(&provision(), true).unwrap_err();
    assert_eq!(
        failure.details.as_ref().unwrap()["code"],
        "missing_computer_url"
    );
    let record: Value =
        serde_json::from_str(&std::fs::read_to_string(env.record(c)).unwrap()).unwrap();
    assert!(record["computerHost"].is_null());
    assert!(invoke(&request("start", c), true).is_err());
    fixture.reply(204, "");
    invoke(&request("deprovision", c), true).unwrap();

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
#[cfg(windows)]
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
        &json!({"sessionId":A,"status":"Succeeded","computerUrl":computer_url(A)}).to_string(),
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
    assert!(fixture
        .request(0)
        .starts_with(&format!("POST /api/pools/{POOL}/sessions?api-version=3.0 ")));
    std::env::remove_var("W365A_DP_SUFFIX");
    std::env::remove_var("W365A_DP_TOKEN");
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
        .starts_with(&format!("DELETE /api/sessions/{A}?api-version=2.0 ")));
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
