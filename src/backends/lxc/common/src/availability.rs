// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Total caller-visible budget for the LXC availability probe.
pub const LXC_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(3);

const LXC_COMMAND_TIMEOUT: Duration = Duration::from_millis(2_750);
const LXC_REAP_TIMEOUT: Duration = Duration::from_millis(250);

const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, PartialEq, Eq)]
enum LxcLsOutcome {
    ExitedSuccess,
    ExitedFailure,
    SpawnFailed,
    TimedOut,
}

/// Runs `lxc-ls --version`; only a clean exit counts as available.
pub fn is_lxc_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| available_from(probe_lxc_ls()))
}

fn probe_lxc_ls() -> LxcLsOutcome {
    let child = spawn_probe_command(Command::new("lxc-ls").arg("--version"));
    match child {
        Ok(child) => wait_bounded(child),
        Err(_) => LxcLsOutcome::SpawnFailed,
    }
}

fn spawn_probe_command(command: &mut Command) -> std::io::Result<Child> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    isolate_probe_process_group(command);
    command.spawn()
}

#[cfg(unix)]
fn isolate_probe_process_group(command: &mut Command) {
    // SAFETY: `setsid` is async-signal-safe and runs in the child immediately
    // before exec. It isolates wrapper descendants so timeout cleanup can kill
    // the whole probe process group without affecting the caller.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn isolate_probe_process_group(_command: &mut Command) {}

fn wait_bounded(child: Child) -> LxcLsOutcome {
    wait_bounded_with_deadlines(child, LXC_COMMAND_TIMEOUT, LXC_AVAILABILITY_TIMEOUT)
}

fn wait_bounded_with_deadlines(
    mut child: Child,
    command_timeout: Duration,
    total_timeout: Duration,
) -> LxcLsOutcome {
    let started = Instant::now();
    let command_deadline = started + command_timeout;
    let total_deadline = started + total_timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return LxcLsOutcome::ExitedSuccess,
            Ok(Some(_)) => return LxcLsOutcome::ExitedFailure,
            Ok(None) => {
                if Instant::now() >= command_deadline {
                    kill_process_group(&mut child);
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return LxcLsOutcome::SpawnFailed,
        }
    }

    let reap_deadline = (Instant::now() + LXC_REAP_TIMEOUT).min(total_deadline);
    while Instant::now() < reap_deadline {
        match child.try_wait() {
            Ok(Some(_)) => return LxcLsOutcome::TimedOut,
            Ok(None) => std::thread::sleep(
                POLL_INTERVAL.min(reap_deadline.saturating_duration_since(Instant::now())),
            ),
            Err(_) => {
                handoff_reaper(child);
                return LxcLsOutcome::TimedOut;
            }
        }
    }
    handoff_reaper(child);
    LxcLsOutcome::TimedOut
}

fn kill_process_group(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        // SAFETY: The child was started in its own session/process group via
        // `setsid`, so sending SIGKILL to `-pid` targets only the probe tree.
        let killed_group = unsafe { libc::kill(-pid, libc::SIGKILL) } == 0;
        if !killed_group {
            let _ = child.kill();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

fn handoff_reaper(mut child: Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

fn available_from(outcome: LxcLsOutcome) -> bool {
    matches!(outcome, LxcLsOutcome::ExitedSuccess)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;

    #[test]
    fn only_a_clean_exit_means_available() {
        assert!(available_from(LxcLsOutcome::ExitedSuccess));
        assert!(!available_from(LxcLsOutcome::ExitedFailure));
        assert!(!available_from(LxcLsOutcome::SpawnFailed));
        assert!(!available_from(LxcLsOutcome::TimedOut));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_and_eventually_reaps_the_real_subprocess() {
        let child = spawn_probe_command(Command::new("sh").args(["-c", "sleep 30"]))
            .expect("test shell starts");
        let pid = child.id();
        let started = Instant::now();

        assert_eq!(
            wait_bounded_with_deadlines(
                child,
                Duration::from_millis(40),
                Duration::from_millis(40),
            ),
            LxcLsOutcome::TimedOut
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "bounded timeout took {:?}",
            started.elapsed()
        );
        assert_eventually_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_wrapper_descendants() {
        let pid_file = std::env::temp_dir().join(format!(
            "mxc-lxc-availability-descendant-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&pid_file);
        let script = format!(
            "sleep 30 & echo $! > {}; wait",
            shell_quote(pid_file.to_string_lossy().as_ref())
        );
        let child = spawn_probe_command(Command::new("sh").args(["-c", &script]))
            .expect("test shell starts");
        let started = Instant::now();
        let descendant_pid = read_pid_file(&pid_file);

        assert_eq!(
            wait_bounded_with_deadlines(
                child,
                Duration::from_millis(100),
                Duration::from_millis(250),
            ),
            LxcLsOutcome::TimedOut
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "bounded timeout took {:?}",
            started.elapsed()
        );
        assert_eventually_reaped(descendant_pid);
        let _ = fs::remove_file(pid_file);
    }

    #[cfg(unix)]
    fn assert_eventually_reaped(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while process_exists(pid) && Instant::now() < deadline {
            std::thread::sleep(POLL_INTERVAL);
        }
        assert!(!process_exists(pid), "timed-out child {pid} was not reaped");
    }

    #[cfg(unix)]
    fn process_exists(pid: u32) -> bool {
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    #[cfg(unix)]
    fn read_pid_file(path: &std::path::Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Ok(contents) = fs::read_to_string(path) {
                return contents.trim().parse().expect("descendant pid is numeric");
            }
            assert!(
                Instant::now() < deadline,
                "descendant pid file {} was not written",
                path.display()
            );
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}
