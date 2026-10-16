// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn writes_config_parse_error_to_log_file() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let config_path = directory.join("unparseable_config.json");
    let log_path = directory.join("unparseable_config.log");
    fs::write(&config_path, "{ not json").expect("write config");
    fs::write(&log_path, "").expect("clear log left by an earlier run");

    let output = Command::new(env!("CARGO_BIN_EXE_lxc-exec"))
        .arg("--log-file")
        .arg(&log_path)
        .arg(&config_path)
        .output()
        .expect("run lxc-exec");

    let log = fs::read_to_string(&log_path).expect("read log file");
    assert!(
        log.contains("Configuration parse error"),
        "lxc-exec did not write the parse error to --log-file\nlog:\n{log}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
