// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::{
    exit_after_signal_cleanup, install, run_startup_tool, with_container_startup, LxcContainer,
};
use nix::sys::signal::{kill, killpg, pthread_sigmask, SigSet, SigmaskHow, Signal};
use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
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
    let exit_poll_flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;

    let completed = loop {
        if !matches!(
            waitid(Id::Pid(process_group), exit_poll_flags)
                .expect("observe isolated executor exit without reaping"),
            WaitStatus::StillAlive
        ) {
            break completed_path.exists();
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
    let status = child
        .wait()
        .expect("reap isolated executor after its final signal");

    assert!(
        elapsed >= Duration::from_secs(60) && !status.success() && completed,
        "a successful 62-second startup must time out, finish cleanup, and exit unsuccessfully; \
         elapsed={elapsed:?}, status={status}, cleanup_completed_before_exit={completed}\n{}",
        fs::read_to_string(log_path).expect("read executor log")
    );
}

#[test]
fn sigint_finishes_startup_command_cleanup_before_executor_exit() {
    const FIXTURE_ENV: &str = "MXC_STARTUP_COMMAND_CLEANUP_TEST_DIRECTORY";
    const CONTAINER_NAME: &str = "startup-command-cancellation";

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
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg(
                    r#"trap 'exit 130' INT
trap 'exit 143' TERM
trap '
    trap "" HUP INT QUIT TERM
    : > "$MXC_STARTUP_COMMAND_CLEANUP_TEST_DIRECTORY/command-cleanup-begun"
    /bin/sleep 6 || exit 1

    # Reject completion after the executor has exited.
    read -r executor_pid < "$MXC_STARTUP_COMMAND_CLEANUP_TEST_DIRECTORY/executor.pid" || exit 1
    read -r _ _ state _ < "/proc/$executor_pid/stat" || exit 1
    case "$state" in Z|X|x) exit 1 ;; esac
    : > "$MXC_STARTUP_COMMAND_CLEANUP_TEST_DIRECTORY/command-cleanup-complete"
' EXIT
printf '%s\n' "$$" > "$MXC_STARTUP_COMMAND_CLEANUP_TEST_DIRECTORY/command.pid"
: > "$MXC_STARTUP_COMMAND_CLEANUP_TEST_DIRECTORY/command-working"
if [ "$MXC_STARTUP_COMMAND_SIGNAL_AFTER" = command-cleanup-begun ]; then
    exit 1
fi
work_seconds_remaining=45
while [ "$work_seconds_remaining" -gt 0 ]; do
    /bin/sleep 1
    work_seconds_remaining=$((work_seconds_remaining - 1))
done
"#,
                )
                .process_group(0);
            run_startup_tool(command, Duration::from_secs(120)).map(|_| ())
        });
        if let Err(error) = result {
            eprintln!("{error}");
            exit_after_signal_cleanup(1);
        }
        return;
    }

    for signal_after in ["command-working", "command-cleanup-begun"] {
        let fixture = tempfile::tempdir_in(".").expect("create isolated cancellation fixture");
        let directory = fixture
            .path()
            .canonicalize()
            .expect("absolute fixture path");
        let tools = directory.join("bin");
        fs::create_dir(&tools).expect("create fake cleanup tool directory");
        fs::create_dir(directory.join(CONTAINER_NAME)).expect("create fake container directory");
        fs::write(directory.join(CONTAINER_NAME).join("config"), "")
            .expect("write fake container configuration");
        for name in ["lxc-stop", "lxc-destroy"] {
            let path = tools.join(name);
            fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write fake cleanup tool");
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
            .env("MXC_STARTUP_COMMAND_SIGNAL_AFTER", signal_after)
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
        let exit_poll_flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;

        while !directory.join(signal_after).exists() {
            if !matches!(
                waitid(Id::Pid(process_group), exit_poll_flags)
                    .expect("observe isolated executor exit without reaping"),
                WaitStatus::StillAlive
            ) || started.elapsed() >= Duration::from_secs(45)
            {
                let _ = killpg(process_group, Signal::SIGKILL);
                child.wait().expect("reap isolated executor");
                panic!(
                    "startup command did not reach {signal_after} before SIGINT:\n{}",
                    fs::read_to_string(&log_path).expect("read executor log")
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let command_group = Pid::from_raw(
            fs::read_to_string(directory.join("command.pid"))
                .expect("read owned startup command PID")
                .trim()
                .parse::<i32>()
                .expect("owned startup command PID"),
        );
        let signal_result = kill(process_group, Signal::SIGINT);

        loop {
            if !matches!(
                waitid(Id::Pid(process_group), exit_poll_flags)
                    .expect("observe isolated executor exit without reaping"),
                WaitStatus::StillAlive
            ) {
                break;
            }
            if started.elapsed() >= Duration::from_secs(45) {
                let _ = killpg(process_group, Signal::SIGKILL);
                child.wait().expect("reap hung executor");
                panic!(
                    "SIGINT after {signal_after} did not finish startup command cleanup and exit:\n{}",
                    fs::read_to_string(&log_path).expect("read executor log")
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let completed = directory.join("command-cleanup-complete").exists();
        let live_command_processes = || {
            fs::read_dir("/proc")
                .expect("inspect owned startup command processes")
                .filter_map(Result::ok)
                .filter_map(|process| fs::read_to_string(process.path().join("stat")).ok())
                .filter(|stat| {
                    let Some((_, fields)) = stat.rsplit_once(')') else {
                        return false;
                    };
                    let mut fields = fields.split_whitespace();
                    let state = fields.next();
                    let group = fields.nth(1).and_then(|group| group.parse::<i32>().ok());
                    group == Some(command_group.as_raw()) && !matches!(state, Some("Z" | "X" | "x"))
                })
                .collect::<Vec<_>>()
        };
        let live_helpers = live_command_processes();
        let _ = killpg(process_group, Signal::SIGKILL);
        let status = child
            .wait()
            .expect("reap isolated executor after its final signal");
        while !live_command_processes().is_empty() && started.elapsed() < Duration::from_secs(90) {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            signal_result.is_ok() && !status.success() && completed && live_helpers.is_empty(),
            "SIGINT during startup ({signal_after}) must finish the command's six-second EXIT cleanup before \
             executor exit without leaving live owned helpers; signal={signal_result:?}, \
             status={status}, cleanup_completed_before_exit={completed}, \
             live_helpers={live_helpers:?}\n{}",
            fs::read_to_string(log_path).expect("read executor log")
        );
    }
}

#[test]
fn startup_command_preserves_complete_stdout() {
    const FIXTURE_ENV: &str = "MXC_STARTUP_COMMAND_OUTPUT_TEST_DIRECTORY";
    const CONTAINER_NAME: &str = "startup-command-output";

    if let Some(directory) = std::env::var_os(FIXTURE_ENV) {
        let directory = PathBuf::from(directory);
        install().expect("install cleanup in the isolated executor");
        let container = LxcContainer::new(
            CONTAINER_NAME,
            Some(directory.to_str().expect("UTF-8 container directory")),
        );
        let expected = "0123456789abcdef".repeat(2048);
        let mut stdout = Vec::new();
        with_container_startup(&container, || {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "printf '%s' \"$1\"", "startup-stdout", &expected])
                .process_group(0);
            stdout = run_startup_tool(command, Duration::from_secs(10))?.stdout;
            Ok(())
        })
        .expect("complete startup command");

        assert_eq!(
            stdout,
            expected.as_bytes(),
            "a normally completed startup command must return its complete 32 KiB stdout"
        );
        return;
    }

    let fixture = tempfile::tempdir_in(".").expect("create isolated stdout fixture");
    let directory = fixture
        .path()
        .canonicalize()
        .expect("absolute fixture path");
    let tools = directory.join("bin");
    fs::create_dir(&tools).expect("create fake cleanup tool directory");
    fs::create_dir(directory.join(CONTAINER_NAME)).expect("create fake container directory");
    fs::write(directory.join(CONTAINER_NAME).join("config"), "")
        .expect("write fake container configuration");
    for name in ["lxc-stop", "lxc-destroy"] {
        let path = tools.join(name);
        fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write fake cleanup tool");
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
    let exit_poll_flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT;

    while matches!(
        waitid(Id::Pid(process_group), exit_poll_flags)
            .expect("observe isolated executor exit without reaping"),
        WaitStatus::StillAlive
    ) {
        if started.elapsed() >= Duration::from_secs(30) {
            let _ = killpg(process_group, Signal::SIGKILL);
            child.wait().expect("reap hung executor");
            panic!(
                "startup command did not return its stdout within 30 seconds:\n{}",
                fs::read_to_string(&log_path).expect("read executor log")
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = killpg(process_group, Signal::SIGKILL);
    let status = child.wait().expect("reap isolated executor");

    assert!(
        status.success(),
        "startup command did not preserve its complete stdout:\n{}",
        fs::read_to_string(log_path).expect("read executor log")
    );
}
