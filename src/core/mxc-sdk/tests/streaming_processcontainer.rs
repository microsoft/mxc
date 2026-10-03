// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows ProcessContainer streaming integration test, in its own
//! Windows-gated file. The sibling `streaming.rs` is `#![cfg(macos)]`, which
//! would otherwise make a `#[cfg(windows)]` test there impossible to compile.
//! Requires an elevated, host-prepped Windows host (see docs/host-prep.md), so
//! it is `#[ignore]`d.

#![cfg(target_os = "windows")]

use mxc_sdk::v1::configs::ProcessContainer;
use mxc_sdk::v1::WaitOutcome;
use mxc_sdk::v1::{spawn, ContainerRequest, Containment, FilesystemSection};

#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn streaming_processcontainer_bidirectional_stdio() {
    use std::io::{Read, Write};

    let mut request = ContainerRequest::new("cmd /c more");
    request.set_filesystem(FilesystemSection {
        readwrite_paths: vec!["C:\\Windows\\Temp".to_string()],
        readonly_paths: vec![],
        denied_paths: vec![],
        clear_policy_on_exit: None,
    });
    request.set_containment(Containment::ProcessContainer(ProcessContainer::default()));
    // `cmd /c more` echoes stdin to stdout until EOF, then exits.
    let mut proc = spawn(request).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\r\n").expect("write stdin");
    drop(stdin);

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    assert_eq!(proc.wait().expect("wait"), WaitOutcome::Exited(0));
}
