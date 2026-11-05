// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runs the real executor, so this needs a host that supports ProcessContainer.

#![cfg(windows)]

use std::process::Command;

#[test]
fn log_file_does_not_contain_the_proxy_password() {
    let dir = std::env::temp_dir().join(format!("mxc-proxy-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.json");
    let log = dir.join("run.log");
    std::fs::write(
        &config,
        r#"{
            "version": "1.0.0",
            "containment": "processcontainer",
            "process": { "commandLine": "cmd.exe /c echo hi", "timeout": 30000 },
            "network": { "ingress": { "default": "allow", "hostLoopback": "allow" } },
            "runtimeConfig": { "networkProxy": "http://alice:hunter2@127.0.0.1:18080" }
        }"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_wxc-exec"))
        .arg("--config")
        .arg(&config)
        .arg("--log-file")
        .arg(&log)
        .output()
        .unwrap();
    let contents = std::fs::read_to_string(&log).unwrap_or_default();
    println!("Log file contents:\n{contents}");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(output.status.success(), "{output:?}");
    assert!(
        contents.contains("effective proxy"),
        "the run never reached the proxy log line:\n{contents}"
    );
    let leaked: Vec<_> = contents
        .lines()
        .filter(|line| line.contains("hunter2"))
        .collect();
    assert!(leaked.is_empty(), "{leaked:#?}");
}
