// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use mxc_sdk::v1::{Error, ErrorCode, MxcProcess, WaitResult};
use std::collections::VecDeque;
use std::sync::mpsc;

#[cfg(windows)]
type Stream = schannel::tls_stream::TlsStream<std::net::TcpStream>;
#[cfg(not(windows))]
type Stream = native_tls::TlsStream<std::net::TcpStream>;
type Script = Box<dyn FnOnce(&mut Stream) + Send>;

struct ExecFixture {
    fixture: Fixture,
    worker: Option<std::thread::JoinHandle<()>>,
    scripts: Arc<Mutex<VecDeque<Script>>>,
    starts: Arc<Mutex<Vec<Value>>>,
}

impl ExecFixture {
    fn new(env: &Environment) -> Self {
        let cert = FixtureCertificate::new("localhost");
        let mut ca = tempfile::NamedTempFile::new().unwrap();
        ca.write_all(cert.certificate.as_bytes()).unwrap();
        #[cfg(windows)]
        let (tls, key) = fixture_tls(&cert);
        #[cfg(not(windows))]
        let tls = fixture_tls(&cert);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let scripts = Arc::new(Mutex::new(VecDeque::<Script>::new()));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (work, seen, stop_worker) = (scripts.clone(), requests.clone(), stop.clone());
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
                #[cfg(windows)]
                let handshake = schannel::tls_stream::Builder::new().accept(tls.clone(), socket);
                #[cfg(not(windows))]
                let handshake = tls.accept(socket);
                let mut stream = match handshake {
                    Ok(stream) => stream,
                    // Trust rejection probes deliberately fail the handshake.
                    Err(_) => continue,
                };
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
            _key: Some(key),
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
        self.script_with_upgrade(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: exec\r\n\r\n",
            work,
        );
    }

    fn script_with_upgrade(&self, reply: &str, work: impl FnOnce(&mut Stream) + Send + 'static) {
        let recorded = self.starts.clone();
        self.response(reply, move |stream| {
            let (kind, start) = read_frame(stream).unwrap();
            assert_eq!(kind, 1);
            recorded
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&start).unwrap());
            work(stream);
        });
    }

    fn response(&self, reply: &str, work: impl FnOnce(&mut Stream) + Send + 'static) {
        let reply = reply.to_owned();
        self.scripts
            .lock()
            .unwrap()
            .push_back(Box::new(move |stream| {
                stream.write_all(reply.as_bytes()).unwrap();
                stream.flush().unwrap();
                work(stream);
            }));
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
    if let Ok(mode) = std::env::var("MXC_W365_INPUT_CHILD") {
        repeated_attached_child(&mode);
        return;
    }
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
    repeated_attached_input(&fixture, "pipe");
    #[cfg(unix)]
    repeated_attached_input(&fixture, "shared");
    #[cfg(windows)]
    for mode in ["console", "console-eof"] {
        repeated_attached_input(&fixture, mode);
    }
}

fn attached_input_text() -> String {
    format!("next-command {}\u{1f980}\u{e9}", "x".repeat(2034))
}

fn repeated_attached_input(fixture: &ExecFixture, mode: &str) {
    let ready = tempfile::NamedTempFile::new().unwrap();
    let (release_first, first) = mpsc::channel();
    let (release_second, second) = mpsc::channel();
    let (received_input, input_result) = mpsc::channel();
    let expect_eof = mode == "console-eof";
    fixture.script(move |stream| {
        started(stream);
        exit(stream, 0);
        first.recv_timeout(Duration::from_secs(15)).unwrap();
    });
    fixture.script(move |stream| {
        started(stream);
        let mut input = Vec::new();
        while expect_eof || !input.ends_with(b"\n") {
            let (kind, bytes) = match read_frame(stream) {
                Ok(frame) => frame,
                Err(error) => {
                    received_input
                        .send(Err(std::io::Error::other(format!(
                            "{error}; received bytes: {input:?}"
                        ))))
                        .unwrap();
                    return;
                }
            };
            if expect_eof && kind == 3 {
                assert!(bytes.is_empty());
                break;
            }
            assert_eq!(kind, 2);
            input.extend(bytes);
        }
        received_input.send(Ok(input)).unwrap();
        exit(stream, 7);
        second.recv_timeout(Duration::from_secs(15)).unwrap();
    });
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "execution::native_execution_streams_fixture",
            "--nocapture",
        ])
        .env("MXC_W365_INPUT_CHILD", mode)
        .env("MXC_W365_INPUT_READY", ready.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::fs::read(ready.path()).unwrap() != b"ready" {
        if child.try_wait().unwrap().is_some() || std::time::Instant::now() >= deadline {
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
            }
            let output = child.wait_with_output().unwrap();
            release_first.send(()).unwrap();
            let _ = release_second.send(());
            panic!("first attached exec did not return with idle stdin: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    release_first.send(()).unwrap();
    // Keep the host writer open across both calls; EOF must not rescue a stale reader.
    let mut input = child.stdin.take().unwrap();
    if !mode.starts_with("console") {
        input
            .write_all(format!("{}\n", attached_input_text()).as_bytes())
            .unwrap();
    }
    while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let _ = release_second.send(());
    let received = input_result.recv_timeout(Duration::from_secs(5));
    assert!(
        output.status.success(),
        "same-process {mode} attached execution retained stdin or stole later input: {output:?}; received: {received:?}"
    );
    assert_eq!(
        String::from_utf8(received.unwrap().unwrap())
            .unwrap()
            .trim_end(),
        attached_input_text()
    );
    let count = fixture.fixture.count();
    assert_eq!(
        fixture.fixture.request(count - 1).split("\r\n").next(),
        fixture.fixture.request(count - 2).split("\r\n").next(),
        "both commands must use the same reservation"
    );
}

fn repeated_attached_child(mode: &str) {
    #[cfg(windows)]
    if mode.starts_with("console") {
        use std::os::windows::io::{AsRawHandle, BorrowedHandle};
        // SAFETY: preserve the subprocess diagnostic pipe before allocating its console.
        let diagnostics = std::fs::File::from(
            unsafe { BorrowedHandle::borrow_raw(std::io::stderr().as_raw_handle()) }
                .try_clone_to_owned()
                .unwrap(),
        );
        std::panic::set_hook(Box::new(move |info| {
            let _ = writeln!(&diagnostics, "{info}");
        }));
    }
    #[cfg(windows)]
    let _console = mode.starts_with("console").then(TestConsole::new);
    #[cfg(unix)]
    let _alias = (mode == "shared").then(SharedHostStdio::new);
    #[cfg(unix)]
    // SAFETY: stdin remains open throughout this isolated helper's two executions.
    let original_flags = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) };
    #[cfg(unix)]
    assert!(original_flags >= 0);
    let execute = || {
        if mode.starts_with("console") {
            let outcome =
                mxc_sdk::mxc_engine::exec_state_aware_attached(&exec_request().to_string(), true)
                    .unwrap();
            let mxc_sdk::mxc_common::state_aware_backend::ExecOutcome::Exited(code) = outcome
            else {
                panic!("confirmed Exit expected")
            };
            code
        } else {
            let MxcRequest::StateAware(mut parsed) = load_mxc_request_from_json(
                &exec_request().to_string(),
                &mut Logger::new(Mode::Buffer),
            )
            .unwrap() else {
                panic!("exec request")
            };
            parsed.set_experimental_enabled(true);
            let DispatchOutcome::ExecCompleted { exit_code } =
                mxc_sdk::mxc_engine::run_state_aware(parsed, false).unwrap()
            else {
                panic!("confirmed Exit expected")
            };
            exit_code
        }
    };
    assert_eq!(execute(), 0);
    #[cfg(unix)]
    assert_eq!(
        unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) },
        original_flags,
        "attached exec must restore host stdin flags before returning"
    );
    std::fs::write(std::env::var_os("MXC_W365_INPUT_READY").unwrap(), b"ready").unwrap();
    #[cfg(windows)]
    if mode.starts_with("console") {
        let end = if mode == "console-eof" {
            "\u{1a}"
        } else {
            "\r"
        };
        TestConsole::input(&format!("{}{end}", attached_input_text()));
    }
    assert_eq!(execute(), 7);
    #[cfg(unix)]
    assert_eq!(
        unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_GETFL) },
        original_flags,
        "the second execution must also restore host stdin flags"
    );
}

#[cfg(unix)]
struct SharedHostStdio(std::os::fd::OwnedFd);

#[cfg(unix)]
impl SharedHostStdio {
    fn new() -> Self {
        use std::os::fd::BorrowedFd;
        // SAFETY: stdout is live and retained for restoration after both calls.
        let original = unsafe { BorrowedFd::borrow_raw(libc::STDOUT_FILENO) }
            .try_clone_to_owned()
            .unwrap();
        // No guest output is sent: exercise shared descriptor flags without writing to a read end.
        // SAFETY: only the isolated helper replaces its standard handle.
        assert_eq!(
            unsafe { libc::dup2(libc::STDIN_FILENO, libc::STDOUT_FILENO) },
            libc::STDOUT_FILENO
        );
        Self(original)
    }
}

#[cfg(unix)]
impl Drop for SharedHostStdio {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: both relays have stopped, and the original stdout is still owned.
        assert_eq!(
            unsafe { libc::dup2(self.0.as_raw_fd(), libc::STDOUT_FILENO) },
            libc::STDOUT_FILENO
        );
    }
}

#[cfg(windows)]
struct TestConsole {
    original: [windows::Win32::Foundation::HANDLE; 3],
    _files: [std::fs::File; 2],
}

#[cfg(windows)]
impl TestConsole {
    fn new() -> Self {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Console::*;
        // SAFETY: only this isolated subprocess changes its console and standard handles.
        unsafe {
            let original = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
                .map(|kind| GetStdHandle(kind).unwrap());
            let _ = FreeConsole();
            AllocConsole().unwrap();
            let input = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("CONIN$")
                .unwrap();
            let output = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("CONOUT$")
                .unwrap();
            SetStdHandle(STD_INPUT_HANDLE, HANDLE(input.as_raw_handle())).unwrap();
            SetStdHandle(STD_OUTPUT_HANDLE, HANDLE(output.as_raw_handle())).unwrap();
            SetStdHandle(STD_ERROR_HANDLE, HANDLE(output.as_raw_handle())).unwrap();
            Self {
                original,
                _files: [input, output],
            }
        }
    }

    fn input(text: &str) {
        use windows::Win32::System::Console::*;
        let records: Vec<_> = text
            .encode_utf16()
            .map(|character| INPUT_RECORD {
                EventType: KEY_EVENT as u16,
                Event: INPUT_RECORD_0 {
                    KeyEvent: KEY_EVENT_RECORD {
                        bKeyDown: true.into(),
                        wRepeatCount: 1,
                        wVirtualKeyCode: match character {
                            13 | 32 => character,
                            26 => 0x5a,
                            45 => 0xbd,
                            48..=57 | 65..=90 | 97..=122 => {
                                (character as u8).to_ascii_uppercase() as u16
                            }
                            _ => 0,
                        },
                        wVirtualScanCode: if character == 13 { 0x1c } else { 0 },
                        uChar: KEY_EVENT_RECORD_0 {
                            UnicodeChar: character,
                        },
                        dwControlKeyState: if character == 26 {
                            LEFT_CTRL_PRESSED
                        } else {
                            0
                        },
                    },
                },
            })
            .collect();
        let mut written = 0;
        // SAFETY: the allocated console owns the input handle; records remain live.
        unsafe {
            WriteConsoleInputW(
                GetStdHandle(STD_INPUT_HANDLE).unwrap(),
                &records,
                &mut written,
            )
            .unwrap();
        }
        assert_eq!(written as usize, records.len());
    }
}

#[cfg(windows)]
impl Drop for TestConsole {
    fn drop(&mut self) {
        use windows::Win32::System::Console::*;
        // SAFETY: restore the subprocess's still-owned inherited handles for its test harness.
        unsafe {
            FreeConsole().unwrap();
            for (kind, handle) in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
                .into_iter()
                .zip(self.original)
            {
                SetStdHandle(kind, handle).unwrap();
            }
        }
    }
}

#[test]
fn native_execution_backpressure_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = ExecFixture::new(&env);
    const SIZE: usize = 12 * 1024 * 1024 + 17;
    for native_transfer in [false, true] {
        for discarded_kind in [0x12, 0x13] {
            let kept_kind = if discarded_kind == 0x12 { 0x13 } else { 0x12 };
            fixture.script(move |stream| {
                started(stream);
                assert!(eof(stream).is_empty());
                send(stream, kept_kind, b"kept\0");
                for _ in 0..(SIZE / 65536 + 1) {
                    send(stream, discarded_kind, &[0x42; 65536]);
                }
                send(stream, kept_kind, b"final\xff");
                exit(stream, -1);
            });
            let mut process = spawn(&exec_request()).unwrap();
            let (input, stdout, stderr): (
                Box<dyn Write + Send>,
                Box<dyn Read + Send>,
                Box<dyn Read + Send>,
            ) = if native_transfer {
                let mut pipes = process.take_native_stdio().unwrap().unwrap();
                (
                    Box::new(std::fs::File::from(pipes.stdin.take().unwrap())),
                    Box::new(std::fs::File::from(pipes.stdout.take().unwrap())),
                    Box::new(std::fs::File::from(pipes.stderr.take().unwrap())),
                )
            } else {
                (
                    process.take_stdin().unwrap(),
                    process.take_stdout().unwrap(),
                    process.take_stderr().unwrap(),
                )
            };
            let (discarded, kept) = if discarded_kind == 0x12 {
                (stdout, stderr)
            } else {
                (stderr, stdout)
            };
            drop(discarded);
            let kept = drain(kept);
            // Guest output begins only after the caller drops its output reader.
            drop(input);
            let began = Instant::now();
            let outcome = process.wait();
            assert_eq!(kept.join().unwrap(), b"kept\0final\xff");
            assert_eq!(outcome.unwrap(), WaitResult::Exited(-1));
            assert_eq!(process.wait().unwrap(), WaitResult::Exited(-1));
            assert!(began.elapsed() < Duration::from_secs(10));
        }
    }
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
        limit_receive_buffer(stream.get_ref());
        let result = (|| {
            // Write all output before reading stdin to exercise duplex backpressure.
            for offset in (0..SIZE).step_by(65536) {
                let bytes: Vec<u8> = (offset..(offset + 65536).min(SIZE))
                    .map(|i| (i % 251) as u8)
                    .collect();
                for kind in [0x12, 0x13] {
                    stream.write_all(&[kind])?;
                    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
                    stream.write_all(&bytes)?;
                    stream.flush()?;
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
        assert_eq!(process.wait().unwrap_err().to_string(), error);
        drop(process);
        // Drain the retained prefix after completion; overflow never replaces it.
        let prefix = drain(unread).join().unwrap();
        assert!(
            prefix.len() >= 8 * 1024 * 1024,
            "disposing the failed process lost queued output: {} bytes",
            prefix.len()
        );
        assert!(prefix.len() <= 8 * 1024 * 1024 + 65536 + 65536);
        assert!(prefix.iter().all(|byte| *byte == 0x42));
        assert!(draining.join().unwrap().is_empty());
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
        fixture.script(script);
        let mut process = spawn(&exec_request()).unwrap();
        let error = process.wait().unwrap_err().to_string();
        assert!(
            error.contains("exec_protocol") || error.contains("exec_transport"),
            "{error}"
        );
    }
    fixture.script(|stream| {
        started(stream);
        assert!(eof(stream).is_empty());
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
    assert!(error.message.contains("remote_exec_error"), "{error}");
    let (release, released) = mpsc::channel();
    fixture.script(move |stream| {
        limit_receive_buffer(stream.get_ref());
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
        limit_receive_buffer(stream.get_ref());
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
    execution_timeout_boundaries(&env, &fixture);
}

fn execution_timeout_boundaries(env: &Environment, fixture: &ExecFixture) {
    for timeout in [None, Some(0), Some(1)] {
        let (running, running_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let (finished, finished_rx) = mpsc::channel();
        fixture.script(move |stream| {
            started(stream);
            assert!(eof(stream).is_empty());
            running.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            if timeout != Some(1) {
                send(stream, 0x12, b"output after the former 330-second cutoff");
                exit(stream, 153);
                finished_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }
        });
        let mut value = exec_request();
        if let Some(timeout) = timeout {
            value["process"]["timeout"] = json!(timeout);
        } else {
            value["process"].as_object_mut().unwrap().remove("timeout");
        }
        let mut process = spawn(&value).unwrap();
        drop(process.take_stdin());
        let out = drain(process.take_stdout().unwrap());
        let err = drain(process.take_stderr().unwrap());
        running_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        env.set("MXC_W365_TEST_EXEC_ELAPSED_MS", "331000");
        if timeout == Some(1) {
            let began = Instant::now();
            let error = process.wait().unwrap_err();
            assert!(began.elapsed() < Duration::from_secs(5));
            assert!(error.to_string().contains("exec_client_timeout"), "{error}");
            assert_ne!(error.kind(), std::io::ErrorKind::TimedOut);
            release.send(()).unwrap();
            assert!(out.join().unwrap().is_empty());
        } else {
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(process.try_wait().unwrap(), None);
            release.send(()).unwrap();
            assert_eq!(process.wait().unwrap(), WaitResult::Exited(153));
            finished.send(()).unwrap();
            assert_eq!(
                out.join().unwrap(),
                b"output after the former 330-second cutoff"
            );
        }
        assert!(err.join().unwrap().is_empty());
        assert_eq!(
            fixture.starts.lock().unwrap().last().unwrap()["timeoutMs"],
            timeout.unwrap_or(0)
        );
        std::env::remove_var("MXC_W365_TEST_EXEC_ELAPSED_MS");
    }
}

fn fragmented_tls_deadline(env: &Environment) {
    let cert = FixtureCertificate::new("localhost");
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(cert.certificate.as_bytes()).unwrap();
    #[cfg(windows)]
    let (tls, _key) = fixture_tls(&cert);
    #[cfg(not(windows))]
    let tls = fixture_tls(&cert);
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    env.set("MXC_W365_TEST_CA", ca.path().to_str().unwrap());
    env.set(
        "MXC_W365_TEST_PORT",
        &listener.local_addr().unwrap().port().to_string(),
    );
    env.set("MXC_W365_TEST_TIMEOUT_MS", "5000");
    let (accepted, accepted_rx) = mpsc::channel();
    let (flight, flight_rx) = mpsc::channel();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = stop.clone();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        accepted.send(socket.try_clone().unwrap()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let socket = FragmentedHandshake {
            socket,
            flight: Some(flight),
            stop: stopped,
        };
        #[cfg(windows)]
        let handshake = schannel::tls_stream::Builder::new().accept(tls, socket);
        #[cfg(not(windows))]
        let handshake = tls.accept(socket);
        assert!(handshake.is_err(), "fragmented handshake must not finish");
    });
    let (result, result_rx) = mpsc::channel();
    let began = Instant::now();
    let client = std::thread::spawn(move || {
        result.send(spawn(&exec_request()).err()).unwrap();
    });
    let socket = accepted_rx.recv_timeout(Duration::from_secs(5));
    let sent_flight = flight_rx.recv_timeout(Duration::from_secs(5));
    let result = result_rx.recv_timeout(Duration::from_secs(7));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Ok(socket) = socket {
        let _ = socket.shutdown(std::net::Shutdown::Both);
    }
    server.join().unwrap();
    client.join().unwrap();
    assert!(
        sent_flight.is_ok(),
        "fixture must reach the real TLS handshake: {sent_flight:?}; client: {result:?}"
    );
    let error = result
        .expect("fragmented TLS exceeded the setup deadline")
        .unwrap();
    assert!(began.elapsed() < Duration::from_secs(7));
    assert_eq!(
        error.details.as_ref().unwrap()["code"],
        "exec_upgrade_timeout"
    );
    assert_eq!(error.details.as_ref().unwrap()["possiblySucceeded"], false);
}

#[derive(Debug)]
struct FragmentedHandshake {
    socket: std::net::TcpStream,
    flight: Option<mpsc::Sender<()>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl Read for FragmentedHandshake {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.socket.read(bytes)
    }
}

impl Write for FragmentedHandshake {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(flight) = self.flight.take() {
            flight.send(()).unwrap();
        }
        // Frequent valid TLS fragments must not restart the total setup budget.
        for byte in bytes {
            if self.stop.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.socket.write_all(&[*byte])?;
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

#[test]
fn execution_upgrade_validation_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = Fixture::new();
    fixture.configure(&env);
    env.set("W365A_DP_SUFFIX", "localhost");
    env.set("W365A_DP_TOKEN", "synthetic-data-plane-token");
    env.set("MXC_W365_TEST_TIMEOUT_MS", "200");
    env.set("MXC_W365_TEST_DNS_DELAY_MS", "6000");
    for attempt in 0..5 {
        let began = Instant::now();
        let error = spawn(&exec_request()).err().unwrap();
        assert!(began.elapsed() < Duration::from_secs(2));
        assert_eq!(
            error.details.as_ref().unwrap()["code"],
            "exec_upgrade_timeout"
        );
        assert_eq!(error.details.as_ref().unwrap()["possiblySucceeded"], false);
        if attempt == 4 {
            assert!(error.message.contains("DNS worker capacity (4)"));
        }
    }
    assert_eq!(
        fixture.count(),
        0,
        "late DNS must never initiate service work"
    );
    std::env::remove_var("MXC_W365_TEST_DNS_DELAY_MS");
    std::env::remove_var("MXC_W365_TEST_TIMEOUT_MS");
    // Waiting for capacity is charged to setup, and completed workers restore it.
    fixture.reply(401, "never-send-a-command");
    let error = spawn(&exec_request()).err().unwrap();
    assert_eq!(
        error.details.as_ref().unwrap()["httpStatus"],
        401,
        "{error:?}"
    );
    fragmented_tls_deadline(&env);
    fixture.configure(&env);
    std::env::remove_var("MXC_W365_TEST_TIMEOUT_MS");
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
    assert_eq!(fixture.count(), 9);
    for n in 0..9 {
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
    assert_eq!(fixture.count(), 9);
    let mut wrong_ca = tempfile::NamedTempFile::new().unwrap();
    let cert = FixtureCertificate::new("localhost");
    wrong_ca.write_all(cert.certificate.as_bytes()).unwrap();
    env.set("MXC_W365_TEST_CA", wrong_ca.path().to_str().unwrap());
    assert_eq!(
        spawn(&exec_request()).err().unwrap().details.unwrap()["code"],
        "exec_upgrade_transport"
    );
    assert_eq!(
        fixture.count(),
        9,
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
    selected_exec_upgrade(&env);
}

fn selected_exec_upgrade(env: &Environment) {
    let fixture = ExecFixture::new(env);
    for reply in [
        "HTTP/1.1 101 Switching Protocols\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: exec\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: not-upgrade\r\nUpgrade: exec\r\n\r\n",
        "HTTP/1.0 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: exec\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: exec, websocket\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: exec\r\nUpgrade: websocket\r\n\r\n",
    ] {
        let (observed, observed_rx) = mpsc::channel();
        fixture.response(reply, move |stream| {
            let mut byte = [0];
            observed.send(stream.read(&mut byte).map_err(|error| error.kind())).unwrap();
        });
        let result = spawn(&exec_request());
        let observed = observed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let error = result.err().expect("invalid upgrade must fail during setup");
        assert_eq!(error.details.as_ref().unwrap()["code"], "exec_upgrade_headers");
        assert_eq!(error.details.as_ref().unwrap()["possiblySucceeded"], false);
        assert!(matches!(
            observed,
            Ok(0) | Err(std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted)
        ), "command bytes sent after invalid upgrade: {observed:?}");
    }
    assert!(fixture.starts.lock().unwrap().is_empty());
    assert_eq!(
        fixture.fixture.count(),
        8,
        "no retry or replay after refusal"
    );
    for reply in [
        "HTTP/1.1 101 Switching Protocols\r\ncOnNeCtIoN: keep-alive, \tUPGRADE\r\nuPgRaDe: \texec \t\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive\r\nconnection: upgrade\r\nUpgrade: exec\r\n\r\n",
    ] {
        fixture.script_with_upgrade(reply, |stream| {
            started(stream);
            assert!(eof(stream).is_empty());
            exit(stream, 7);
        });
        let mut process = spawn(&exec_request()).unwrap();
        drop(process.take_stdin());
        assert_eq!(process.wait().unwrap(), WaitResult::Exited(7));
    }
    assert_eq!(fixture.starts.lock().unwrap().len(), 2);
    assert_eq!(fixture.fixture.count(), 10);
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
        pending_host_input(&fixture, command(example_mode), code);
    }
    for example_mode in [false, true] {
        unreadable_host_input(&fixture, command(example_mode));
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
    for example_mode in [false, true] {
        shared_host_output(&fixture, || command(example_mode));
        unread_host_output(&fixture, || command(example_mode));
    }
    assert_eq!(fixture.fixture.count(), 28);
    for n in 0..28 {
        assert!(fixture.fixture.request(n).contains(concat!(
            "\r\nUser-Agent: mxc/",
            env!("CARGO_PKG_VERSION"),
            " (w365_agents)\r\n"
        )));
    }
}

#[test]
#[cfg(unix)]
#[ignore = "requires a separately built test-support execution example"]
fn execution_host_output_fixture() {
    let _lock = ENV.lock().unwrap();
    let env = Environment::new();
    let fixture = ExecFixture::new(&env);
    let example = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("w365_execution");
    assert!(example.is_file(), "build the W365 execution example");
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(exec_request().to_string().as_bytes())
        .unwrap();
    let command = || {
        let mut command = std::process::Command::new(&example);
        command.args(["--experimental", "live"]).arg(file.path());
        command
    };
    shared_host_output(&fixture, command);
    for code in [0, 7] {
        pending_host_input(&fixture, command(), code);
    }
    unreadable_host_input(&fixture, command());
    unread_host_output(&fixture, command);
    assert_eq!(fixture.fixture.count(), 11);
}

fn shared_host_output(fixture: &ExecFixture, command: impl Fn() -> std::process::Command) {
    for guest_stderr in [false, true] {
        let (release, released) = mpsc::channel();
        fixture.script(move |stream| {
            started(stream);
            assert!(eof(stream).is_empty());
            for _ in 0..4 {
                send(stream, 0x12, &[0x42; 65536]);
                if guest_stderr {
                    send(stream, 0x13, &[0x43; 65536]);
                }
            }
            exit(stream, 0);
            released.recv_timeout(Duration::from_secs(20)).unwrap();
        });
        #[cfg(unix)]
        let (mut reader, writer) = std::io::pipe().unwrap();
        #[cfg(windows)]
        let (mut reader, writer) = {
            use std::os::windows::io::FromRawHandle;
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::System::Pipes::CreatePipe;
            let mut read = HANDLE::default();
            let mut write = HANDLE::default();
            // Leave room for a prefix before the synchronous host write blocks.
            // SAFETY: fresh pipe handles transfer immediately to their owning files.
            unsafe {
                CreatePipe(&mut read, &mut write, None, 65536).unwrap();
                (
                    std::fs::File::from_raw_handle(read.0),
                    std::fs::File::from_raw_handle(write.0),
                )
            }
        };
        let mut child = {
            let mut command = command();
            command
                .stdin(std::process::Stdio::null())
                .stdout(writer.try_clone().unwrap())
                .stderr(writer);
            command.spawn().unwrap()
        };
        let began = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if began.elapsed() > Duration::from_secs(15) {
                child.kill().unwrap();
                child.wait().unwrap();
                release.send(()).unwrap();
                panic!("shared unread output blocked completion with guest_stderr={guest_stderr}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let status = child.wait().unwrap();
        assert!(!status.success());
        release.send(()).unwrap();
        let mut prefix = Vec::new();
        // Reading after exit also checks restoration of shared descriptor flags.
        reader.read_to_end(&mut prefix).unwrap();
        assert!(!prefix.is_empty(), "shared output was empty: {status}");
        assert!(prefix.len() < 4 * 65536);
    }
}

fn pending_host_input(fixture: &ExecFixture, mut command: std::process::Command, code: i32) {
    let (release, released) = mpsc::channel();
    fixture.script(move |stream| {
        started(stream);
        let (kind, input) = read_frame(stream).unwrap();
        assert_eq!(kind, 2);
        assert!(!input.is_empty());
        // Hold TLS open after Exit so a reset cannot mask cancellation of pending host input.
        exit(stream, code);
        released.recv_timeout(Duration::from_secs(20)).unwrap();
    });
    let mut child = command
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

fn unreadable_host_input(fixture: &ExecFixture, mut command: std::process::Command) {
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
    let output = command
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

fn unread_host_output(fixture: &ExecFixture, command: impl Fn() -> std::process::Command) {
    for blocked_stderr in [false, true] {
        for terminal in [Some(false), Some(true), None] {
            let (release, released) = mpsc::channel();
            fixture.script(move |stream| {
                started(stream);
                assert!(eof(stream).is_empty());
                for _ in 0..4 {
                    send(
                        stream,
                        if blocked_stderr { 0x13 } else { 0x12 },
                        &[0x42; 65536],
                    );
                }
                if terminal == Some(true) {
                    send(
                        stream,
                        0x15,
                        br#"{"code":"failed","message":"service failure"}"#,
                    );
                } else if terminal == Some(false) {
                    exit(stream, 0);
                }
                released.recv_timeout(Duration::from_secs(45)).unwrap();
            });
            let diagnostic = tempfile::NamedTempFile::new().unwrap();
            let mut command = command();
            command.stdin(std::process::Stdio::null());
            if blocked_stderr {
                command
                    .stdout(diagnostic.reopen().unwrap())
                    .stderr(std::process::Stdio::piped());
            } else {
                command
                    .stdout(std::process::Stdio::piped())
                    .stderr(diagnostic.reopen().unwrap());
            }
            let mut child = command.spawn().unwrap();
            let began = Instant::now();
            // Retain the output pipe without reading it: closing it would
            // exercise BrokenPipe instead of cancellation of a blocked write.
            while child.try_wait().unwrap().is_none() {
                let budget = if terminal.is_none() { 45 } else { 15 };
                if began.elapsed() > Duration::from_secs(budget) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    release.send(()).unwrap();
                    panic!("open unread host output must not prevent execution completion");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            release.send(()).unwrap();
            assert!(
                !output.status.success(),
                "undelivered output must not become success"
            );
            let prefix = if blocked_stderr {
                output.stderr
            } else {
                output.stdout
            };
            assert!(!prefix.is_empty());
            assert!(prefix.len() < 4 * 65536);
            if !blocked_stderr {
                let text = std::fs::read_to_string(diagnostic.path()).unwrap();
                assert!(text.contains("host_output_undelivered"), "{text}");
                if terminal == Some(true) {
                    assert!(text.contains("service failure"), "{text}");
                }
                if terminal.is_none() {
                    assert!(text.contains("exec_client_timeout"), "{text}");
                }
            }
        }
    }
}
