// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::IsTerminal;

use windows::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

use crate::pseudo_console::PseudoConsole;
use wxc_common::process_util::{create_std_pipes, OwnedHandle};
use wxc_common::sandbox_process::StdioMode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StdioRouting {
    CapturePipes,
    ForwardedHandles,
    SharedConsole,
    PseudoConsole,
}

impl StdioRouting {
    fn uses_pipe_handles(self) -> bool {
        matches!(self, Self::CapturePipes | Self::ForwardedHandles)
    }
}

pub(crate) struct ChildStdioSetup {
    pub(crate) stdin: HANDLE,
    pub(crate) stdout: HANDLE,
    pub(crate) stderr: HANDLE,
    pub(crate) capture_reads: Option<(OwnedHandle, OwnedHandle)>,
    pub(crate) stdin_write: Option<OwnedHandle>,
    pub(crate) pseudo_console: Option<PseudoConsole>,
    child_pipe_ends: Vec<OwnedHandle>,
    routing: StdioRouting,
}

impl ChildStdioSetup {
    pub(crate) fn new(stdio: StdioMode) -> std::io::Result<Self> {
        let routing = select_routing(
            stdio,
            std::io::stdout().is_terminal(),
            std::io::stderr().is_terminal(),
        );
        let pseudo_console = match stdio {
            StdioMode::Pty(size) => Some(PseudoConsole::new(size)?),
            _ => None,
        };

        let mut setup = Self {
            stdin: HANDLE::default(),
            stdout: HANDLE::default(),
            stderr: HANDLE::default(),
            capture_reads: None,
            stdin_write: None,
            pseudo_console,
            child_pipe_ends: Vec::new(),
            routing,
        };

        match routing {
            StdioRouting::CapturePipes => setup.configure_capture_pipes()?,
            StdioRouting::ForwardedHandles => setup.configure_inherited_handles()?,
            StdioRouting::SharedConsole | StdioRouting::PseudoConsole => {}
        }

        Ok(setup)
    }

    pub(crate) fn uses_pipe_handles(&self) -> bool {
        self.routing.uses_pipe_handles()
    }

    pub(crate) fn captures_output(&self) -> bool {
        self.routing == StdioRouting::CapturePipes
    }

    pub(crate) fn child_inherited_pipe_handles(&self) -> [HANDLE; 3] {
        [self.stdin, self.stdout, self.stderr]
    }

    pub(crate) fn finish_launch(&mut self) {
        self.child_pipe_ends.clear();
    }

    fn configure_capture_pipes(&mut self) -> std::io::Result<()> {
        let (stdin_read, stdin_write) = create_std_pipes(false).map_err(std::io::Error::other)?;
        let (stdout_read, stdout_write) = create_std_pipes(true).map_err(std::io::Error::other)?;
        let (stderr_read, stderr_write) = create_std_pipes(true).map_err(std::io::Error::other)?;

        self.stdin = stdin_read.get();
        self.stdout = stdout_write.get();
        self.stderr = stderr_write.get();
        self.child_pipe_ends = vec![stdin_read, stdout_write, stderr_write];
        self.stdin_write = Some(stdin_write);
        self.capture_reads = Some((stdout_read, stderr_read));
        Ok(())
    }

    fn configure_inherited_handles(&mut self) -> std::io::Result<()> {
        self.stdin = get_inheritable_std_handle(STD_INPUT_HANDLE, "STDIN")?;
        self.stdout = get_inheritable_std_handle(STD_OUTPUT_HANDLE, "STDOUT")?;
        self.stderr = get_inheritable_std_handle(STD_ERROR_HANDLE, "STDERR")?;
        Ok(())
    }
}

fn select_routing(
    stdio: StdioMode,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
) -> StdioRouting {
    match stdio {
        StdioMode::Pipes => StdioRouting::CapturePipes,
        StdioMode::Pty(_) => StdioRouting::PseudoConsole,
        StdioMode::Inherit if stdout_is_terminal && stderr_is_terminal => {
            StdioRouting::SharedConsole
        }
        StdioMode::Inherit => StdioRouting::ForwardedHandles,
    }
}

fn get_inheritable_std_handle(
    kind: windows::Win32::System::Console::STD_HANDLE,
    name: &str,
) -> std::io::Result<HANDLE> {
    let handle = unsafe { GetStdHandle(kind) }
        .map_err(|error| std::io::Error::other(format!("GetStdHandle({name}): {error}")))?;
    if handle.is_invalid() || handle == HANDLE::default() {
        return Err(std::io::Error::other(format!(
            "GetStdHandle({name}) returned null/invalid handle"
        )));
    }

    unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .map_err(|error| std::io::Error::other(format!("SetHandleInformation({name}): {error}")))?;
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::{select_routing, StdioRouting};
    use wxc_common::sandbox_process::{PtySize, StdioMode};

    #[test]
    fn selects_explicit_stdio_routing_without_terminal_detection() {
        assert_eq!(
            select_routing(StdioMode::Pipes, true, true),
            StdioRouting::CapturePipes
        );
        assert_eq!(
            select_routing(StdioMode::Pty(PtySize::default()), false, false),
            StdioRouting::PseudoConsole
        );
    }

    #[test]
    fn inherits_console_only_when_both_output_streams_are_terminals() {
        assert_eq!(
            select_routing(StdioMode::Inherit, true, true),
            StdioRouting::SharedConsole
        );
        assert_eq!(
            select_routing(StdioMode::Inherit, false, true),
            StdioRouting::ForwardedHandles
        );
        assert_eq!(
            select_routing(StdioMode::Inherit, true, false),
            StdioRouting::ForwardedHandles
        );
    }
}
