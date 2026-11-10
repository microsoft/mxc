// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::mxc_common::{
    config_parser::load_mxc_request_from_json,
    logger::{Logger, Mode},
    mxc_error::{MxcError, MxcErrorCode},
    state_aware_dispatch::DispatchOutcome,
    state_aware_request::MxcRequest,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POOL: &str = "11111111-1111-1111-1111-111111111111";
const A: &str = "22222222-2222-2222-2222-222222222222";
const B: &str = "33333333-3333-3333-3333-333333333333";
static ENV: Mutex<()> = Mutex::new(());

mod execution;
mod sdk_lifecycle;

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

    let identity = super::service::Identity::parse(&format!("w365:{POOL}:{A}")).unwrap();
    let client = super::data_plane::client(&identity).unwrap();
    let n = fixture.count();
    let error =
        super::data_plane::poll(&identity, &client, Duration::ZERO, Duration::ZERO).unwrap_err();
    assert_eq!(error.details.unwrap()["code"], "attach_timeout");
    assert_eq!(fixture.count(), n, "zero budget must not dial");
    fixture.reply(200, r#"{"status":"Waiting"}"#);
    let began = Instant::now();
    let error = super::data_plane::poll(
        &identity,
        &client,
        Duration::from_millis(100),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert_eq!(error.details.unwrap()["code"], "attach_timeout");
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_eq!(fixture.count(), n + 1);
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|request| request.starts_with("GET ")));
}

struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Environment {
    fn new() -> Self {
        Self(
            [
                "W365A_CONTROLPLANE_URL",
                "W365A_CP_TOKEN",
                "W365A_DP_SUFFIX",
                "W365A_DP_TOKEN",
                "MXC_W365_TEST_CA",
                "MXC_W365_TEST_PORT",
            ]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect(),
        )
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

struct Fixture {
    port: u16,
    ca: tempfile::NamedTempFile,
    requests: Arc<Mutex<Vec<String>>>,
    replies: Arc<Mutex<std::collections::VecDeque<Option<String>>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(cert.cert.pem().as_bytes()).unwrap();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into();
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let tls = Arc::new(tls);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(
            std::collections::VecDeque::<Option<String>>::new(),
        ));
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
                let session = rustls::ServerConnection::new(tls.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(session, socket);
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
                if let Some(Some(reply)) = responses.lock().unwrap().pop_front() {
                    stream.write_all(reply.as_bytes()).unwrap();
                    stream.flush().unwrap();
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
        }
    }
    fn configure(&self, env: &Environment) {
        env.set("W365A_CONTROLPLANE_URL", "localhost");
        env.set("W365A_CP_TOKEN", "fixture-token-never-log");
        env.set("MXC_W365_TEST_CA", self.ca.path().to_str().unwrap());
        env.set("MXC_W365_TEST_PORT", &self.port.to_string());
    }
    fn reply(&self, status: u16, body: &str) {
        self.replies.lock().unwrap().push_back(Some(format!(
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nx-ms-request-id: fixture-request\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )));
    }
    fn drop_reply(&self) {
        self.replies.lock().unwrap().push_back(None);
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
    match crate::mxc_engine::run_state_aware(parsed, false)? {
        DispatchOutcome::Envelope(value) => Ok(value),
        other => panic!("{other:?}"),
    }
}

#[test]
fn lifecycle_contract_and_recovery_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
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
    for key in ["W365A_DP_SUFFIX", "W365A_DP_TOKEN"] {
        std::env::remove_var(key);
    }
    for phase in ["start", "exec"] {
        assert_eq!(
            invoke(&request(phase, A), true).unwrap_err().code,
            MxcErrorCode::PolicyValidation
        );
    }
    for phase in ["stop", "deprovision"] {
        for bad in [
            "",
            "../escape",
            "not-guid",
            "22222222-2222-2222-2222-222222222222:extra",
        ] {
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
    fixture.configure(&env);
    assert!(crate::mxc_engine::available_backends()
        .iter()
        .all(|b| b.backend != "w365_agents"));
    assert_eq!(
        fixture.count(),
        before,
        "local probing must not use W365 services"
    );

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
    let first = fixture.request(0).to_ascii_lowercase();
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
    let sent = fixture.request(2);
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
        let details = error.details.unwrap();
        assert_eq!(details["possiblySucceeded"], true);
        assert_eq!(details["sandboxId"], format!("w365:{POOL}:{A}"));
        fixture.reply(204, "");
        invoke(&request("deprovision", A), true).unwrap();
        assert!(fixture
            .request(fixture.count() - 1)
            .starts_with(&format!("DELETE /api/sessions/{A}?api-version=2.0")));
    }
    for body in ["{bad", "{}", r#"{"sessionId":"bad","status":"Succeeded"}"#] {
        let n = fixture.count();
        fixture.reply(200, body);
        let details = invoke(&provision(), true).unwrap_err().details.unwrap();
        assert_eq!(details["possiblySucceeded"], true);
        assert!(details.get("sandboxId").is_none());
        assert_eq!(fixture.count(), n + 1);
    }
    for status in [401, 403, 404, 408, 429, 500, 502, 201, 302, 418] {
        let n = fixture.count();
        fixture.reply(status, "ticket-secret-must-not-surface");
        let error = invoke(&provision(), true).unwrap_err();
        assert!(!format!("{error:?}").contains("ticket-secret"));
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
        let details = invoke(&request("stop", A), true)
            .unwrap_err()
            .details
            .unwrap();
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
}

// CI explicitly supplies a test-support executor. This never uses a live service.
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
}
