// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use mxc_sdk::v1::{spawn_with_pty, ContainerRequest, MxcPtySize, SpawnWithPtyOptions, WaitResult};

pub const ROUND_TRIP_COMMAND: &str =
    "read value; stty size; printf 'stdout:%s\\n' \"$value\"; printf 'stderr:merged\\n' >&2";
pub const TIMEOUT_COMMAND: &str = "sleep 30";
pub const NATIVE_STDIO_COMMAND: &str =
    "read value; printf 'native-stdout:%s\\n' \"$value\"; printf 'native-stderr\\n' >&2";

pub fn assert_round_trip(request: ContainerRequest) {
    let terminal = spawn_with_pty(
        request,
        SpawnWithPtyOptions {
            size: MxcPtySize {
                rows: 24,
                cols: 80,
                ..MxcPtySize::default()
            },
            ..Default::default()
        },
    )
    .expect("spawn_with_pty");
    let resized = MxcPtySize {
        rows: 40,
        cols: 120,
        ..MxcPtySize::default()
    };
    terminal.resize(resized).expect("resize");
    assert_eq!(terminal.size().expect("size"), resized);

    let mut reader = terminal.try_clone_reader().expect("reader");
    let reader_thread = std::thread::spawn(move || {
        let mut output = String::new();
        reader.read_to_string(&mut output).expect("read output");
        output
    });
    let mut writer = terminal.take_writer().expect("writer");
    writer.write_all(b"hello").expect("write partial input");
    drop(writer);

    assert_eq!(terminal.wait().expect("wait"), WaitResult::Exited(0));
    let output = reader_thread.join().expect("reader thread");
    assert!(
        output.contains("40 120"),
        "resize was not observed: {output:?}"
    );
    assert!(
        output.contains("stdout:hello"),
        "stdout was not returned: {output:?}"
    );
    assert!(
        output.contains("stderr:merged"),
        "stderr was not merged into PTY output: {output:?}"
    );
}

pub fn assert_timeout(request: ContainerRequest, maximum: Duration) {
    let terminal = spawn_with_pty(request, Default::default()).expect("spawn_with_pty for timeout");
    let started = Instant::now();
    loop {
        match terminal.try_wait() {
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            result => panic!("unexpected PTY timeout poll result: {result:?}"),
        }
    }
    let repeated = terminal
        .try_wait()
        .expect_err("timeout classification must remain latched");
    assert_eq!(repeated.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(terminal.wait().expect("wait"), WaitResult::TimedOut);
    assert!(
        started.elapsed() < maximum,
        "PTY timeout exceeded {maximum:?}: {:?}",
        started.elapsed()
    );
}

pub fn assert_explicit_timeout_kill(request: ContainerRequest) {
    let terminal = spawn_with_pty(request, Default::default())
        .expect("spawn_with_pty for explicit timeout kill");
    terminal
        .kill_for_timeout()
        .expect("explicit timeout kill succeeds");
    let repeated = terminal
        .try_wait()
        .expect_err("explicit timeout kill must latch timeout classification");
    assert_eq!(repeated.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(terminal.wait().expect("wait"), WaitResult::TimedOut);
}

pub fn assert_native_stdio(request: ContainerRequest) {
    let mut terminal =
        spawn_with_pty(request, Default::default()).expect("spawn_with_pty for native stdio");
    let stdio = terminal
        .take_native_stdio()
        .expect("take native stdio")
        .expect("native PTY stdio available");
    assert!(stdio.stderr.is_none(), "PTY stderr must remain merged");

    let mut input = std::fs::File::from(stdio.stdin.expect("PTY input pipe"));
    let mut output = std::fs::File::from(stdio.stdout.expect("PTY output pipe"));
    input
        .write_all(b"hello")
        .expect("write partial native input");
    drop(input);

    let outcome = terminal.wait().expect("wait");
    let mut text = String::new();
    output
        .read_to_string(&mut text)
        .expect("read native output");
    assert_eq!(
        outcome,
        WaitResult::Exited(0),
        "native PTY output before termination: {text:?}"
    );
    assert!(
        text.contains("native-stdout:hello"),
        "stdout missing from native PTY output: {text:?}"
    );
    assert!(
        text.contains("native-stderr"),
        "stderr was not merged into native PTY output: {text:?}"
    );
}
