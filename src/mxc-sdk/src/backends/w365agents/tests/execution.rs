// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mxc_common::sandbox_process::SandboxProcess;
use std::collections::VecDeque;
use std::sync::mpsc;

type Stream = rustls::StreamOwned<rustls::ServerConnection, std::net::TcpStream>;
type Script = Box<dyn FnOnce(&mut Stream) + Send>;

struct ExecFixture {
    fixture: Fixture,
    worker: Option<std::thread::JoinHandle<()>>,
    scripts: Arc<Mutex<VecDeque<Script>>>,
    starts: Arc<Mutex<Vec<Value>>>,
}

impl ExecFixture {
    fn new(env: &Environment) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(cert.cert.pem().as_bytes()).unwrap();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into();
        let tls = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.cert.der().clone()], key)
                .unwrap(),
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let scripts = Arc::new(Mutex::new(VecDeque::<Script>::new()));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (work, seen, recorded, stop_worker) = (
            scripts.clone(),
            requests.clone(),
            starts.clone(),
            stop.clone(),
        );
        let worker = std::thread::spawn(move || {
            while !stop_worker.load(std::sync::atomic::Ordering::Relaxed) {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut stream =
                    Stream::new(rustls::ServerConnection::new(tls.clone()).unwrap(), socket);
                let mut header = Vec::new();
                let mut byte = [0];
                loop {
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    header.push(byte[0]);
                    if header.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(header.len() < 32768);
                }
                if header.is_empty() {
                    continue;
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8(header).unwrap());
                stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: exec\r\n\r\n").unwrap();
                stream.flush().unwrap();
                let (kind, start) = read_frame(&mut stream).unwrap();
                assert_eq!(kind, 1);
                recorded
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&start).unwrap());
                work.lock()
                    .unwrap()
                    .pop_front()
                    .expect("one explicit exec script")(&mut stream);
            }
        });
        let fixture = Fixture {
            port,
            ca,
            requests,
            stop,
            worker: None,
            replies: Arc::new(Mutex::new(VecDeque::new())),
            #[cfg(target_os = "windows")]
            _key: None,
        };
        fixture.configure(env);
        env.set("W365A_DP_SUFFIX", "localhost");
        env.set("W365A_DP_TOKEN", "synthetic-data-plane-token");
        Self {
            fixture,
            worker: Some(worker),
            scripts,
            starts,
        }
    }

    fn script(&self, work: impl FnOnce(&mut Stream) + Send + 'static) {
        self.scripts.lock().unwrap().push_back(Box::new(work));
    }
}

impl Drop for ExecFixture {
    fn drop(&mut self) {
        self.fixture
            .stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn read_frame(stream: &mut Stream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(len <= 65536);
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload)?;
    Ok((header[0], payload))
}

fn send(stream: &mut Stream, kind: u8, bytes: &[u8]) {
    assert!(bytes.len() <= 65536);
    stream.write_all(&[kind]).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
    stream.flush().unwrap();
}

fn started(stream: &mut Stream) {
    send(stream, 0x11, br#"{"pid":123}"#);
}
fn exit(stream: &mut Stream, code: i32) {
    send(stream, 0x14, &json!({"code":code}).to_string().into_bytes());
}
fn eof(stream: &mut Stream) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let (kind, payload) = read_frame(stream).unwrap();
        match kind {
            2 => bytes.extend(payload),
            3 => {
                assert!(payload.is_empty());
                return bytes;
            }
            _ => panic!("unexpected client frame {kind}"),
        }
    }
}

fn spawn(value: &Value) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let MxcRequest::StateAware(mut parsed) =
        load_mxc_request_from_json(&value.to_string(), &mut Logger::new(Mode::Buffer))
            .map_err(|error| error.to_mxc_error())?
    else {
        panic!("lifecycle request");
    };
    parsed.set_experimental_enabled(true);
    crate::mxc_engine::exec_native_state_aware(parsed, true)
}

fn exec_request() -> Value {
    let mut value = request("exec", A);
    value["process"] = json!({"commandLine":"cmd.exe /c echo fixture", "cwd":"C:\\work",
        "env":["X=first", "X=last=equals", "EMPTY"], "inheritDefaultEnv":true, "timeout":1234});
    value
}

fn drain(mut reader: Box<dyn Read + Send>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    })
}

fn details(error: std::io::Error) -> Value {
    error
        .get_ref()
        .unwrap()
        .downcast_ref::<MxcError>()
        .expect("typed backend error")
        .details
        .clone()
        .unwrap()
}

#[test]
fn native_execution_streams_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = ExecFixture::new(&env);
    let (release, gate) = mpsc::channel();
    fixture.script(move |stream| {
        started(stream);
        assert_eq!(eof(stream), b"binary\0stdin\xff");
        gate.recv_timeout(Duration::from_secs(5)).unwrap();
        send(stream, 0x12, b"stdout\0\xff");
        send(stream, 0x13, b"stderr\x80");
        exit(stream, 7);
    });
    let mut process = spawn(&exec_request()).unwrap();
    assert_eq!(
        process.try_wait().unwrap(),
        None,
        "spawn must return before EXIT"
    );
    let mut input = process.take_stdin().unwrap();
    input.write_all(b"binary\0stdin\xff").unwrap();
    drop(input);
    let out = drain(process.take_stdout().unwrap());
    let err = drain(process.take_stderr().unwrap());
    release.send(()).unwrap();
    assert_eq!(process.wait().unwrap(), 7);
    assert_eq!(process.wait().unwrap(), 7);
    assert_eq!(out.join().unwrap(), b"stdout\0\xff");
    assert_eq!(err.join().unwrap(), b"stderr\x80");
    drop(process);
    let start = fixture.starts.lock().unwrap()[0].clone();
    assert_eq!(start["command"], "cmd.exe /c echo fixture");
    assert_eq!(start["shell"], "raw");
    assert_eq!(start["mode"], "pipe");
    assert_eq!(start["env"]["X"], "last=equals");
    assert_eq!(start["env"]["EMPTY"], "");
    assert_eq!(start["timeoutMs"], 1234);
    assert_eq!(start["cwd"], "C:\\work");

    for code in [0, -1, 124] {
        fixture.script(move |stream| {
            started(stream);
            eof(stream);
            send(stream, 0x12, b"final");
            exit(stream, code);
        });
        let mut process = spawn(&exec_request()).unwrap();
        // Exercise native endpoint ownership, not just boxed streams.
        let mut pipes = process.take_native_stdio().unwrap().unwrap();
        drop(pipes.stdin.take());
        let out = drain(Box::new(std::fs::File::from(pipes.stdout.take().unwrap())));
        let err = drain(Box::new(std::fs::File::from(pipes.stderr.take().unwrap())));
        assert_eq!(process.wait().unwrap(), code);
        assert_eq!(out.join().unwrap(), b"final");
        assert!(err.join().unwrap().is_empty());
    }
    assert_eq!(fixture.fixture.count(), 4);
    for n in 0..4 {
        let header = fixture.fixture.request(n);
        assert!(header.starts_with(&format!(
            "GET /computers/{A}/microsoft.exec?api-version=1.0"
        )));
        assert!(header.contains("Upgrade: exec\r\n"));
        assert!(!header.contains("WebSocket"));
        assert!(!header.contains("websocket"));
    }
}

#[test]
fn native_execution_backpressure_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = ExecFixture::new(&env);
    const SIZE: usize = 12 * 1024 * 1024 + 17;
    fixture.script(|stream| {
        started(stream);
        eof(stream);
        for offset in (0..SIZE).step_by(65536) {
            let bytes: Vec<u8> = (offset..(offset + 65536).min(SIZE))
                .map(|i| (i % 251) as u8)
                .collect();
            send(stream, 0x12, &bytes);
            send(stream, 0x13, &bytes);
        }
        exit(stream, 0);
    });
    let mut process = spawn(&exec_request()).unwrap();
    drop(process.take_stdin());
    let out = drain(process.take_stdout().unwrap());
    let err = drain(process.take_stderr().unwrap());
    assert_eq!(process.wait().unwrap(), 0);
    let expected: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    assert_eq!(out.join().unwrap(), expected);
    assert_eq!(err.join().unwrap(), expected);
    drop(process);

    fixture.script(|stream| {
        started(stream);
        eof(stream);
        for offset in (0..SIZE).step_by(65536) {
            let bytes: Vec<u8> = (offset..(offset + 65536).min(SIZE))
                .map(|i| (i % 251) as u8)
                .collect();
            send(stream, 0x12, &bytes);
            send(stream, 0x13, &bytes);
        }
        exit(stream, -1);
    });
    let mut process = crate::sandbox::MxcProcess::new(spawn(&exec_request()).unwrap());
    drop(process.take_stdin());
    let output = process.wait_with_output().unwrap();
    assert_eq!(output.outcome, crate::v1::WaitResult::Exited(-1));
    assert_eq!(output.stdout, expected);
    assert_eq!(output.stderr, expected);

    for slow_kind in [0x12, 0x13] {
        fixture.script(move |stream| {
            started(stream);
            eof(stream);
            for _ in 0..(SIZE / 65536 + 1) {
                send(stream, slow_kind, &[0x42; 65536]);
            }
            exit(stream, 0);
        });
        let mut process = spawn(&exec_request()).unwrap();
        drop(process.take_stdin());
        let stdout = process.take_stdout().unwrap();
        let stderr = process.take_stderr().unwrap();
        let (unread, draining) = if slow_kind == 0x12 {
            (stdout, drain(stderr))
        } else {
            (stderr, drain(stdout))
        };
        let began = Instant::now();
        let error = details(process.wait().unwrap_err());
        assert_eq!(error["code"], "output_truncated");
        assert_eq!(error["exitCode"], 0);
        assert_eq!(error["pendingByteLimit"], 8 * 1024 * 1024);
        assert_eq!(
            error[if slow_kind == 0x12 {
                "stdoutTruncated"
            } else {
                "stderrTruncated"
            }],
            true
        );
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "terminal frames must bypass slow outputs"
        );
        // Drain the retained prefix after completion; overflow never replaces it.
        let prefix = drain(unread).join().unwrap();
        assert!(!prefix.is_empty());
        assert!(prefix.len() <= 8 * 1024 * 1024 + 65536 + 65536);
        assert!(prefix.iter().all(|byte| *byte == 0x42));
        assert!(draining.join().unwrap().is_empty());
        assert_eq!(
            details(process.wait().unwrap_err())["code"],
            "output_truncated"
        );
    }
}

#[test]
fn native_execution_failure_and_disposal_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = ExecFixture::new(&env);
    for (kind, payload, code) in [
        (
            0x15,
            br#"{"code":"invalid_cwd","message":"remote launch failed"}"#.to_vec(),
            "remote_exec_error",
        ),
        (0x11, b"{}".to_vec(), "exec_protocol"),
        (0x12, b"before-start".to_vec(), "exec_protocol"),
        (0x99, Vec::new(), "exec_protocol"),
    ] {
        fixture.script(move |stream| {
            send(stream, kind, &payload);
        });
        let mut process = spawn(&exec_request()).unwrap();
        let error = details(process.wait().unwrap_err());
        assert_eq!(error["code"], code);
        assert_eq!(details(process.wait().unwrap_err())["code"], code);
        if kind == 0x15 {
            assert_eq!(error["remoteCode"], "invalid_cwd");
        }
    }
    for script in [
        Box::new(|stream: &mut Stream| {
            started(stream);
            send(stream, 0x12, b"partial");
        }) as Script,
        Box::new(|stream: &mut Stream| {
            started(stream);
            stream.write_all(&[0x12, 0, 1, 0, 1]).unwrap();
            stream.flush().unwrap();
        }),
        Box::new(|stream: &mut Stream| {
            started(stream);
            send(stream, 0x14, br#"{"code":"bad"}"#);
        }),
        Box::new(|stream: &mut Stream| {
            started(stream);
            send(stream, 0x11, br#"{"pid":123}"#);
        }),
    ] {
        fixture.scripts.lock().unwrap().push_back(script);
        let mut process = spawn(&exec_request()).unwrap();
        let error = details(process.wait().unwrap_err());
        assert!(matches!(
            error["code"].as_str(),
            Some("exec_protocol" | "exec_transport")
        ));
    }
    fixture.script(|stream| {
        started(stream);
        send(stream, 0x12, b"partial capture is not success");
        send(
            stream,
            0x15,
            br#"{"code":"failed","message":"service failure"}"#,
        );
    });
    let process = crate::sandbox::MxcProcess::new(spawn(&exec_request()).unwrap());
    assert_eq!(
        details(process.wait_with_output().unwrap_err())["code"],
        "remote_exec_error"
    );
    fixture.script(|stream| {
        stream
            .sock
            .set_read_timeout(Some(Duration::from_secs(45)))
            .unwrap();
        started(stream);
        let mut bytes = [0; 1024];
        while stream.read(&mut bytes).is_ok_and(|count| count != 0) {}
    });
    let mut value = exec_request();
    value["process"]["timeout"] = json!(1);
    let mut process = spawn(&value).unwrap();
    let began = Instant::now();
    let error = process.wait().unwrap_err();
    assert_ne!(
        error.kind(),
        std::io::ErrorKind::TimedOut,
        "a local timeout is not a confirmed remote timeout"
    );
    assert_eq!(details(error)["code"], "exec_client_timeout");
    assert!(began.elapsed() < Duration::from_secs(40));
    drop(process);
    fixture.script(|stream| {
        started(stream);
        // Never complete: exercise blocked local reader/writer disposal.
        let mut bytes = [0; 1024];
        while stream.read(&mut bytes).is_ok_and(|count| count != 0) {}
    });
    let mut process = spawn(&exec_request()).unwrap();
    let mut input = process.take_stdin().unwrap();
    let mut output = process.take_stdout().unwrap();
    let (written, write_done) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = input.write_all(&vec![0; 32 * 1024 * 1024]);
        written.send(result).unwrap();
    });
    let (read, read_done) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut byte = [0];
        read.send(output.read(&mut byte)).unwrap();
    });
    std::thread::sleep(Duration::from_millis(100));
    let began = Instant::now();
    let error = details(process.kill().unwrap_err());
    assert_eq!(error["code"], "remote_termination_unsupported");
    drop(process);
    assert!(began.elapsed() < Duration::from_secs(5));
    assert!(write_done
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .is_err());
    assert!(matches!(
        read_done.recv_timeout(Duration::from_secs(5)).unwrap(),
        Ok(0) | Err(_)
    ));
    writer.join().unwrap();
    reader.join().unwrap();

    let count = fixture.fixture.count();
    for change in [
        json!({"commandLine":" "}),
        json!({"commandLine":"cmd.exe", "env":[]}),
        json!({"commandLine":"x".repeat(65536)}),
        json!({"commandLine":"cmd.exe", "env":["=bad"], "inheritDefaultEnv":true}),
    ] {
        let mut value = exec_request();
        value["process"] = change;
        assert!(spawn(&value).is_err());
    }
    let mut value = exec_request();
    value["network"] = json!({});
    assert_eq!(
        spawn(&value).err().unwrap().code,
        MxcErrorCode::PolicyValidation
    );
    assert_eq!(
        fixture.fixture.count(),
        count,
        "policy/start-size validation precedes dialing"
    );
}

#[test]
fn execution_upgrade_validation_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    fixture.configure(&env);
    env.set("W365A_DP_SUFFIX", "localhost");
    env.set("W365A_DP_TOKEN", "synthetic-data-plane-token");
    for status in [401, 403, 404, 410, 429, 500, 302, 200] {
        fixture.reply(status, "never-send-a-command");
        let error = spawn(&exec_request()).err().unwrap();
        assert_eq!(error.details.as_ref().unwrap()["httpStatus"], status);
        assert_eq!(error.details.as_ref().unwrap()["possiblySucceeded"], false);
        assert_eq!(
            error.details.as_ref().unwrap()["sandboxId"],
            format!("w365:{POOL}:{A}")
        );
    }
    assert_eq!(fixture.count(), 8);
    for n in 0..8 {
        assert_eq!(fixture.request(n).split_once("\r\n\r\n").unwrap().1, "");
    }
    for key in ["W365A_DP_SUFFIX", "W365A_DP_TOKEN"] {
        env.set(key, "");
        assert_eq!(
            spawn(&exec_request()).err().unwrap().code,
            MxcErrorCode::PolicyValidation
        );
        env.set("W365A_DP_SUFFIX", "localhost");
        env.set("W365A_DP_TOKEN", "synthetic-data-plane-token");
    }
    let mut value = exec_request();
    value["process"]["mode"] = json!("pty");
    assert!(
        spawn(&value).is_err(),
        "unsupported mode must fail before dialing"
    );
    assert_eq!(fixture.count(), 8);
    let mut wrong_ca = tempfile::NamedTempFile::new().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    wrong_ca.write_all(cert.cert.pem().as_bytes()).unwrap();
    env.set("MXC_W365_TEST_CA", wrong_ca.path().to_str().unwrap());
    assert_eq!(
        spawn(&exec_request()).err().unwrap().details.unwrap()["code"],
        "exec_upgrade_transport"
    );
    assert_eq!(
        fixture.count(),
        8,
        "untrusted TLS must carry neither credentials nor a command"
    );
}

#[test]
#[ignore = "requires a separately built test-support native executor"]
fn execution_fresh_executor_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = ExecFixture::new(&env);
    fixture.script(|stream| {
        started(stream);
        assert_eq!(eof(stream), b"executor-stdin\0\xff");
        send(stream, 0x12, b"executor-stdout\0\xff");
        send(stream, 0x13, b"executor-stderr\x80");
        exit(stream, 7);
    });
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let mut value = exec_request();
    value.as_object_mut().unwrap().remove("phase");
    value.as_object_mut().unwrap().remove("sandboxId");
    file.write_all(value.to_string().as_bytes()).unwrap();
    let exe = std::env::var("MXC_W365_TEST_EXECUTOR").expect("fixture executor required");
    let mut child = std::process::Command::new(exe)
        .args([
            "--operation",
            "exec",
            "--container-id",
            &format!("w365:{POOL}:{A}"),
            "--experimental",
            "--config",
        ])
        .arg(file.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"executor-stdin\0\xff")
        .unwrap();
    let began = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if began.elapsed() > Duration::from_secs(15) {
            child.kill().unwrap();
            panic!("executor exec timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"executor-stdout\0\xff");
    let stderr = output
        .stderr
        .strip_prefix(b"telemetry: Required diagnostics are not collected by this build\n")
        .unwrap_or(&output.stderr);
    assert_eq!(stderr, b"executor-stderr\x80");
    assert_eq!(fixture.fixture.count(), 1);
}
