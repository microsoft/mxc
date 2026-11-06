// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Launches `bwrap` from a process-lifetime thread so `--die-with-parent`
//! does not tie the sandbox to a temporary caller thread.

use std::io;
use std::process::{Child, Command};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, PoisonError};
use std::thread;

type SpawnRequest = (Command, Sender<io::Result<Child>>);

static SPAWNER: Mutex<Option<Sender<SpawnRequest>>> = Mutex::new(None);

/// Spawn `command` from the process-lifetime spawner thread.
///
/// Blocks until the spawn completes and returns its result unchanged.
/// Descriptors referenced by `pre_exec` must remain open until this call returns.
pub(crate) fn spawn(command: Command) -> io::Result<Child> {
    let sender = spawner()?;
    let (reply, response) = mpsc::channel();
    if sender.send((command, reply)).is_err() {
        forget_spawner();
        return Err(io::Error::other(
            "Bubblewrap: the spawner thread has exited",
        ));
    }
    response.recv().unwrap_or_else(|_| {
        forget_spawner();
        Err(io::Error::other(
            "Bubblewrap: the spawner thread exited before reporting the spawn result",
        ))
    })
}

fn spawner() -> io::Result<Sender<SpawnRequest>> {
    let mut slot = SPAWNER.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(sender) = slot.as_ref() {
        return Ok(sender.clone());
    }
    let (sender, requests) = mpsc::channel::<SpawnRequest>();
    thread::Builder::new()
        .name("mxc-bwrap-spawner".to_string())
        .spawn(move || {
            // The static keeps a sender alive, so this loop runs until the
            // process exits.
            for (mut command, reply) in requests {
                let result = command.spawn();
                // Release the parent's copies of the child's stdio before the
                // caller resumes, as an inline spawn's scope would.
                drop(command);
                let _ = reply.send(result);
            }
        })
        .map_err(|error| {
            io::Error::other(format!(
                "Bubblewrap: failed to start the spawner thread: {error}"
            ))
        })?;
    *slot = Some(sender.clone());
    Ok(sender)
}

/// Drop a dead spawner so the next spawn starts a fresh thread.
fn forget_spawner() {
    SPAWNER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn spawn_runs_the_command_and_returns_its_child() {
        let mut command = Command::new("sh");
        command
            .args(["-c", "exit 7"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn(command).expect("spawn");
        assert_eq!(child.wait().expect("wait").code(), Some(7));
    }

    #[test]
    fn spawn_reports_launch_errors() {
        let directory = tempfile::tempdir().expect("create temp directory");
        let absent_binary = directory.path().join("mxc-lifetime-spawner-absent-binary");
        let error = spawn(Command::new(absent_binary)).expect_err("missing binary must fail");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
