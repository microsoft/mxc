// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{exit_after_signal_cleanup, install, with_container_startup, LxcContainer};
use nix::sys::signal::{killpg, pthread_sigmask, SigSet, SigmaskHow, Signal};
use nix::unistd::Pid;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn startup_timeout_finishes_cleanup_before_executor_exit() {
    const FIXTURE_ENV: &str = "MXC_STARTUP_CLEANUP_TEST_DIRECTORY";
    const CONTAINER_NAME: &str = "startup-timeout";

    if let Some(directory) = std::env::var_os(FIXTURE_ENV) {
        let directory = PathBuf::from(directory);
        fs::write(
            directory.join("executor.pid"),
            format!("{}\n", std::process::id()),
        )
        .expect("record the isolated executor PID");
        install().expect("install cleanup in the isolated executor");
        let container = LxcContainer::new(
            CONTAINER_NAME,
            Some(directory.to_str().expect("UTF-8 container directory")),
        );
        let result = with_container_startup(&container, || {
            std::thread::sleep(Duration::from_secs(62));
            Ok(())
        });
        if result.is_err() {
            exit_after_signal_cleanup(1);
        }
        return;
    }

    let fixture = tempfile::tempdir_in(".").expect("create isolated cleanup fixture");
    let directory = fixture
        .path()
        .canonicalize()
        .expect("absolute fixture path");
    let tools = directory.join("bin");
    fs::create_dir(&tools).expect("create fake cleanup tool directory");
    fs::create_dir(directory.join(CONTAINER_NAME)).expect("create fake container directory");
    fs::write(directory.join(CONTAINER_NAME).join("config"), "")
        .expect("write fake container configuration");

    // Reject completion after the executor has already exited.
    let cleanup_script = r#"#!/bin/sh
read -r executor_pid < "$MXC_STARTUP_CLEANUP_TEST_DIRECTORY/executor.pid" || exit 1
/bin/sleep 2
read -r _ _ state _ < "/proc/$executor_pid/stat" || exit 1
case "$state" in Z|X|x) exit 1 ;; esac
: > "$MXC_STARTUP_CLEANUP_TEST_DIRECTORY/cleanup-complete"
"#;
    for name in ["lxc-stop", "lxc-destroy"] {
        let path = tools.join(name);
        fs::write(&path, cleanup_script).expect("write fake cleanup tool");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .expect("make fake cleanup tool executable");
    }

    let log_path = directory.join("executor.log");
    let log = fs::File::create(&log_path).expect("create executor log");
    let thread = std::thread::current();
    let test_name = thread.name().expect("fully qualified libtest name");
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(FIXTURE_ENV, &directory)
        .env("PATH", &tools)
        .stdout(log.try_clone().expect("clone executor log"))
        .stderr(log)
        .process_group(0);

    // The child's main thread must inherit the mask before libtest starts its worker.
    let mut original_mask = SigSet::empty();
    pthread_sigmask(
        SigmaskHow::SIG_BLOCK,
        Some(&SigSet::all()),
        Some(&mut original_mask),
    )
    .expect("block signals while spawning the isolated executor");
    let started = Instant::now();
    let child = command.spawn();
    pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&original_mask), None)
        .expect("restore the parent test thread's signal mask");
    let mut child = child.expect("spawn isolated executor");
    let process_group = Pid::from_raw(child.id() as i32);
    let completed_path = directory.join("cleanup-complete");

    let (status, completed) = loop {
        if let Some(status) = child.try_wait().expect("check isolated executor exit") {
            break (status, completed_path.exists());
        }
        if started.elapsed() >= Duration::from_secs(90) {
            let _ = killpg(process_group, Signal::SIGKILL);
            child.wait().expect("reap hung executor");
            panic!(
                "startup timeout did not finish cleanup and exit within 90 seconds:\n{}",
                fs::read_to_string(&log_path).expect("read executor log")
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let elapsed = started.elapsed();
    let _ = killpg(process_group, Signal::SIGKILL);

    assert!(
        elapsed >= Duration::from_secs(60) && !status.success() && completed,
        "a successful 62-second startup must time out, finish cleanup, and exit unsuccessfully; \
         elapsed={elapsed:?}, status={status}, cleanup_completed_before_exit={completed}\n{}",
        fs::read_to_string(log_path).expect("read executor log")
    );
}
