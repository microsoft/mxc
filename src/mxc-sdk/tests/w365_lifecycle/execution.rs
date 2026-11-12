// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mxc_sdk::v1::{Error, ErrorCode, MxcProcess, WaitResult};
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

fn limit_receive_buffer(socket: &std::net::TcpStream) {
    let buffer = 65536_i32;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows::Win32::Networking::WinSock::{setsockopt, SOCKET, SOL_SOCKET, SO_RCVBUF};
        // SAFETY: the stream owns this socket and the option bytes live through the call.
        assert_eq!(
            unsafe {
                setsockopt(
                    SOCKET(socket.as_raw_socket() as usize),
                    SOL_SOCKET,
                    SO_RCVBUF,
                    Some(&buffer.to_ne_bytes()),
                )
            },
            0
        );
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the stream owns this socket and buffer has the option's integer layout.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&buffer as *const i32).cast(),
                    std::mem::size_of_val(&buffer) as libc::socklen_t,
                )
            },
            0
        );
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

fn spawn(value: &Value) -> Result<MxcProcess, Error> {
    mxc_sdk::v1::dev::spawn_in_container_json(
        &value.to_string(),
        mxc_sdk::v1::dev::JsonOptions { experimental: true },
    )
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
    let mut process = std::thread::Builder::new()
        .name("small-foreign-stack".into())
        .stack_size(128 * 1024)
        .spawn(|| {
            mxc_sdk::v1::dev::spawn_in_container_json(
                &exec_request().to_string(),
                mxc_sdk::v1::dev::JsonOptions { experimental: true },
            )
        })
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
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
    assert_eq!(process.wait().unwrap(), mxc_sdk::v1::WaitResult::Exited(7));
    assert_eq!(process.wait().unwrap(), mxc_sdk::v1::WaitResult::Exited(7));
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
        assert_eq!(process.wait().unwrap(), WaitResult::Exited(code));
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
        assert!(header.contains(concat!(
            "\r\nUser-Agent: mxc/",
            env!("CARGO_PKG_VERSION"),
            " (w365_agents)\r\n"
        )));
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
    assert_eq!(process.wait().unwrap(), WaitResult::Exited(0));
    let expected: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    assert_eq!(out.join().unwrap(), expected);
    assert_eq!(err.join().unwrap(), expected);
    drop(process);

    const INPUT_SIZE: usize = 32 * 1024 * 1024 + 19;
    let (sent, received) = mpsc::channel();
    fixture.script(move |stream| {
        started(stream);
        limit_receive_buffer(&stream.sock);
        stream.conn.set_buffer_limit(Some(128 * 1024));
        let result = (|| {
            // StreamOwned may read while flushing. Drive only TLS writes here
            // so the peer cannot relieve stdin backpressure before its output.
            for offset in (0..SIZE).step_by(65536) {
                let bytes: Vec<u8> = (offset..(offset + 65536).min(SIZE))
                    .map(|i| (i % 251) as u8)
                    .collect();
                for kind in [0x12, 0x13] {
                    let mut writer = stream.conn.writer();
                    writer.write_all(&[kind])?;
                    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
                    writer.write_all(&bytes)?;
                    while stream.conn.wants_write() {
                        stream.conn.write_tls(&mut stream.sock)?;
                    }
                }
            }
            let mut input = Vec::new();
            loop {
                let (kind, payload) = read_frame(stream)?;
                if kind == 3 {
                    assert!(payload.is_empty());
                    break;
                }
                assert_eq!(kind, 2);
                input.extend(payload);
            }
            exit(stream, 0);
            Ok::<_, std::io::Error>(input)
        })();
        sent.send(result).unwrap();
    });
    let mut value = exec_request();
    value["process"]["timeout"] = json!(60000);
    let input_bytes: Vec<u8> = (0..INPUT_SIZE).map(|i| (i % 239) as u8).collect();
    let mut process = spawn(&value).unwrap();
    let mut input = process.take_stdin().unwrap();
    let writer = std::thread::spawn(move || input.write_all(&input_bytes));
    let out = drain(process.take_stdout().unwrap());
    let err = drain(process.take_stderr().unwrap());
    let outcome = process.wait();
    let input_result = writer.join().unwrap();
    let stdout = out.join().unwrap();
    let stderr = err.join().unwrap();
    let guest_input = received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(outcome.unwrap(), WaitResult::Exited(0));
    input_result.unwrap();
    let expected_input: Vec<u8> = (0..INPUT_SIZE).map(|i| (i % 239) as u8).collect();
    assert_eq!(guest_input.unwrap(), expected_input);
    assert_eq!(stdout, expected);
    assert_eq!(stderr, expected);
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
    let output = mxc_sdk::v1::dev::run_in_container_json(
        &exec_request().to_string(),
        mxc_sdk::v1::dev::JsonOptions { experimental: true },
    )
    .unwrap();
    assert_eq!(output.outcome, mxc_sdk::v1::WaitResult::Exited(-1));
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
        let error = process.wait().unwrap_err().to_string();
        assert!(error.contains("output_truncated"), "{error}");
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
        assert_eq!(process.wait().unwrap_err().to_string(), error);
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
        let error = process.wait().unwrap_err().to_string();
        assert!(error.contains(code), "{error}");
        assert_eq!(process.wait().unwrap_err().to_string(), error);
        if kind == 0x15 {
            assert!(error.contains("remote launch failed"), "{error}");
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
        let error = process.wait().unwrap_err().to_string();
        assert!(
            error.contains("exec_protocol") || error.contains("exec_transport"),
            "{error}"
        );
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
    let error = mxc_sdk::v1::dev::run_in_container_json(
        &exec_request().to_string(),
        mxc_sdk::v1::dev::JsonOptions { experimental: true },
    )
    .unwrap_err();
    assert!(error.message.contains("remote_exec_error"));
    let (release, released) = mpsc::channel();
    fixture.script(move |stream| {
        limit_receive_buffer(&stream.sock);
        started(stream);
        // Keep the peer alive without reading stdin until the client finishes.
        released.recv_timeout(Duration::from_secs(45)).unwrap();
    });
    let mut value = exec_request();
    value["process"]["timeout"] = json!(1);
    let mut process = spawn(&value).unwrap();
    let mut input = process.take_stdin().unwrap();
    let writer = std::thread::spawn(move || input.write_all(&vec![0; 32 * 1024 * 1024]));
    let began = Instant::now();
    let error = process.wait().unwrap_err();
    release.send(()).unwrap();
    assert!(writer.join().unwrap().is_err());
    assert_ne!(
        error.kind(),
        std::io::ErrorKind::TimedOut,
        "a local timeout is not a confirmed remote timeout"
    );
    assert!(error.to_string().contains("exec_client_timeout"));
    assert!(began.elapsed() < Duration::from_secs(40));
    drop(process);
    let (release, released) = mpsc::channel();
    fixture.script(move |stream| {
        limit_receive_buffer(&stream.sock);
        started(stream);
        // Do not read stdin: disposal must interrupt a backpressured transport.
        released.recv_timeout(Duration::from_secs(10)).unwrap();
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
    let error = process.kill().unwrap_err().to_string();
    assert!(error.contains("remote_termination_unsupported"), "{error}");
    drop(process);
    release.send(()).unwrap();
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
        ErrorCode::PolicyValidation
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
            ErrorCode::PolicyValidation
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
    let wrong_host = Fixture::with_hostname("wrong-host.example");
    wrong_host.configure(&env);
    assert_eq!(
        spawn(&exec_request()).err().unwrap().details.unwrap()["code"],
        "exec_upgrade_transport"
    );
    assert_eq!(
        wrong_host.count(),
        0,
        "hostname rejection must precede credentials and command submission"
    );
}

#[test]
#[cfg(windows)]
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
    let example = std::path::Path::new(&exe)
        .parent()
        .unwrap()
        .join("examples")
        .join("w365_execution.exe");
    assert!(example.is_file(), "build the W365 execution example");
    let mut example_file = tempfile::NamedTempFile::new().unwrap();
    example_file
        .write_all(exec_request().to_string().as_bytes())
        .unwrap();
    let command = |example_mode: bool| {
        if example_mode {
            let mut command = std::process::Command::new(&example);
            command
                .args(["--experimental", "live"])
                .arg(example_file.path());
            command
        } else {
            let mut command = std::process::Command::new(&exe);
            command
                .args([
                    "--operation",
                    "exec",
                    "--container-id",
                    &format!("w365:{POOL}:{A}"),
                    "--experimental",
                    "--config",
                ])
                .arg(file.path());
            command
        }
    };
    let mut child = std::process::Command::new(&exe)
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

    fixture.script(|stream| {
        started(stream);
        eof(stream);
        send(
            stream,
            0x15,
            br#"{"code":"invalid_cwd","message":"remote launch failed"}"#,
        );
    });
    let output = std::process::Command::new(&exe)
        .args([
            "--operation",
            "exec",
            "--container-id",
            &format!("w365:{POOL}:{A}"),
            "--experimental",
            "--config",
        ])
        .arg(file.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let envelope: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(envelope["error"]["details"]["code"], "remote_exec_error");
    assert_eq!(envelope["error"]["details"]["remoteCode"], "invalid_cwd");
    assert_eq!(
        envelope["error"]["details"]["sandboxId"],
        format!("w365:{POOL}:{A}")
    );
    assert_eq!(fixture.fixture.count(), 2);
    for (example_mode, code) in [(false, 0), (false, 7), (true, 0), (true, 7)] {
        let (release, released) = mpsc::channel();
        fixture.script(move |stream| {
            started(stream);
            let (kind, input) = read_frame(stream).unwrap();
            assert_eq!(kind, 2);
            assert!(!input.is_empty());
            // Exit while most host input is still pending, but keep TLS open
            // until the executor finishes so a reset cannot mask pipe teardown.
            exit(stream, code);
            released.recv_timeout(Duration::from_secs(20)).unwrap();
        });
        let mut child = command(example_mode)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || input.write_all(&vec![0x42; 8 * 1024 * 1024]));
        let began = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if began.elapsed() > Duration::from_secs(15) {
                child.kill().unwrap();
                release.send(()).unwrap();
                writer.join().unwrap().unwrap_err();
                panic!("execution must not wait for remaining stdin after Exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        release.send(()).unwrap();
        writer.join().unwrap().unwrap_err();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        let stderr = output
            .stderr
            .strip_prefix(b"telemetry: Required diagnostics are not collected by this build\n")
            .unwrap_or(&output.stderr);
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(stderr));
    }
    for example_mode in [false, true] {
        fixture.script(|stream| {
            started(stream);
            assert!(eof(stream).is_empty());
            exit(stream, 0);
        });
        let host_input = tempfile::NamedTempFile::new().unwrap();
        let unreadable = std::fs::OpenOptions::new()
            .write(true)
            .open(host_input.path())
            .unwrap();
        let output = command(example_mode)
            .stdin(std::process::Stdio::from(unreadable))
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "host stdin read errors must survive Exit"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        let envelope: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
        assert!(envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("read host stdin"));
    }
    let (sent, prompt_sent) = mpsc::channel();
    let (received, guest_input) = mpsc::channel();
    fixture.script(move |stream| {
        started(stream);
        send(stream, 0x12, b"prompt>");
        sent.send(()).unwrap();
        let result = (|| {
            let mut input = Vec::new();
            loop {
                let (kind, bytes) = read_frame(stream)?;
                if kind == 3 {
                    assert!(bytes.is_empty());
                    break;
                }
                assert_eq!(kind, 2);
                input.extend(bytes);
            }
            send(stream, 0x12, b"done\0\xff");
            exit(stream, 0);
            Ok::<_, std::io::Error>(input)
        })();
        received.send(result).unwrap();
    });
    let mut child = std::process::Command::new(&exe)
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
    let mut stdout = child.stdout.take().unwrap();
    let (shown, visible) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut prompt = [0; 7];
        shown
            .send(stdout.read_exact(&mut prompt).map(|()| prompt))
            .unwrap();
        let mut tail = Vec::new();
        stdout.read_to_end(&mut tail).map(|_| tail)
    });
    prompt_sent.recv_timeout(Duration::from_secs(15)).unwrap();
    let prompt = visible.recv_timeout(Duration::from_secs(2));
    if !matches!(&prompt, Ok(Ok(bytes)) if bytes == b"prompt>") {
        child.kill().unwrap();
        child.wait_with_output().unwrap();
        reader.join().unwrap().unwrap();
        guest_input
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap_err();
        panic!("newline-free prompt must be visible before stdin or Exit: {prompt:?}");
    }
    assert!(child.try_wait().unwrap().is_none());
    child.stdin.take().unwrap().write_all(b"answer\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(reader.join().unwrap().unwrap(), b"done\0\xff");
    assert_eq!(
        guest_input
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap(),
        b"answer\n"
    );
    let stderr = output
        .stderr
        .strip_prefix(b"telemetry: Required diagnostics are not collected by this build\n")
        .unwrap_or(&output.stderr);
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(stderr));
    let (release, released) = mpsc::channel();
    fixture.script(move |stream| {
        started(stream);
        eof(stream);
        released.recv_timeout(Duration::from_secs(15)).unwrap();
        send(stream, 0x12, b"unflushed");
        exit(stream, 0);
    });
    let mut child = std::process::Command::new(&exe)
        .args([
            "--operation",
            "exec",
            "--container-id",
            &format!("w365:{POOL}:{A}"),
            "--experimental",
            "--config",
        ])
        .arg(file.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    release.send(()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "failed output flush must not become success"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    let envelope: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert!(envelope["error"]["message"]
        .as_str()
        .unwrap()
        .contains("W365 output relay failed"));
    fixture.script(|stream| {
        started(stream);
        assert!(eof(stream).is_empty());
        send(stream, 0x12, b"captured\0\xff");
        send(stream, 0x13, b"captured-error\x80");
        exit(stream, 7);
    });
    let output = std::process::Command::new(&example)
        .args(["--experimental", "capture"])
        .arg(example_file.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"captured\0\xff");
    assert_eq!(output.stderr, b"captured-error\x80");
    fixture.script(|stream| {
        started(stream);
        assert!(eof(stream).is_empty());
        send(
            stream,
            0x15,
            br#"{"code":"invalid_cwd","message":"remote launch failed"}"#,
        );
    });
    let output = command(true)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stdout.is_empty());
    let envelope: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(envelope["error"]["code"], "backend_error");
    assert!(!envelope["error"]["message"].as_str().unwrap().is_empty());
    assert_eq!(fixture.fixture.count(), 12);
    for n in 0..12 {
        assert!(fixture.fixture.request(n).contains(concat!(
            "\r\nUser-Agent: mxc/",
            env!("CARGO_PKG_VERSION"),
            " (w365_agents)\r\n"
        )));
    }
}
