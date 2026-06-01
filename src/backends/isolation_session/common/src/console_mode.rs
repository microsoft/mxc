// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local-console state manipulation for the IsolationSession backend.
//!
//! - [`ConsoleModeRestorer`] — RAII guard that switches the local console
//!   to raw VT mode for the relay duration, restoring the prior modes on
//!   drop.
//! - [`get_local_console_size`] — reads the visible viewport dimensions of
//!   wxc-exec's local console, used to seed the agent's ConPTY size.

use std::sync::atomic::{AtomicIsize, Ordering};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, SetConsoleCtrlHandler,
    SetConsoleMode, CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
    DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::SetEvent;
use windows_core::BOOL;

// ── Local console raw-VT-mode RAII guard ──────────────────────────────────
//
// When wxc-exec relays into an isolation session in interactive mode, there
// are TWO consoles in series: wxc-exec's local console (where the user types)
// and the agent's ConPTY in the isolation session. By default the local
// console is in cooked-line mode with `ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
// ENABLE_PROCESSED_INPUT` — it line-buffers, echoes keystrokes, and processes
// Ctrl-C locally. The agent's ConPTY *also* echoes (because it's a real PTY).
// The two consoles render the same input twice, producing visible artifacts
// (partial echos, doubled prompts, `\r\n` confusion).
//
// Fix: switch the local console to raw VT mode for the relay duration. Only
// the agent's ConPTY does input echo and command processing; the local
// console is a transparent forwarder. On scope exit the original modes are
// restored.

/// RAII guard that switches the local console to raw VT mode. Only meaningful
/// in interactive mode (`InteractiveConsole = true`). When wxc-exec's stdio
/// is not a real console (redirected, piped), `GetConsoleMode` fails and the
/// guard records itself as inactive — both `install` and `Drop` become
/// no-ops, which is the right behavior for the non-TTY case.
pub(super) struct ConsoleModeRestorer {
    h_stdin: HANDLE,
    h_stdout: HANDLE,
    original_stdin_mode: CONSOLE_MODE,
    original_stdout_mode: CONSOLE_MODE,
    active: bool,
}

impl ConsoleModeRestorer {
    /// Save current console modes (for stdin and stdout) and switch to raw
    /// VT mode. Returns the guard; original modes restored on drop.
    ///
    /// Stdin: enable VT input (key-down events translate to VT escape
    /// sequences readable via `ReadFile`) plus window-resize input (a
    /// `WINDOW_BUFFER_SIZE_EVENT` record is queued on every console-window
    /// resize). Both are consumed by [`super::console_relay`] — the VT
    /// bytes forward to the agent's stdin, the resize events drive
    /// `ResizeConsole` on the agent's ConPTY. Disable line-input, echo,
    /// and processed-input so line editing and Ctrl handling happen in
    /// the agent's ConPTY, not in wxc-exec's local console.
    /// Stdout: enable VT processing; disable auto-newline-translation.
    ///
    /// On any failure (handles aren't real consoles, `SetConsoleMode` fails
    /// because the handles are not console-mode handles, etc.), the guard
    /// is constructed inactive — no mode is changed, no restore on drop.
    pub(super) fn install_raw_vt() -> Self {
        let h_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.unwrap_or_default();
        let h_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.unwrap_or_default();

        let mut original_stdin_mode = CONSOLE_MODE(0);
        let mut original_stdout_mode = CONSOLE_MODE(0);

        let stdin_ok = unsafe { GetConsoleMode(h_stdin, &mut original_stdin_mode) }.is_ok();
        let stdout_ok = unsafe { GetConsoleMode(h_stdout, &mut original_stdout_mode) }.is_ok();

        if !stdin_ok || !stdout_ok {
            return Self {
                h_stdin,
                h_stdout,
                original_stdin_mode,
                original_stdout_mode,
                active: false,
            };
        }

        let raw_in = CONSOLE_MODE(
            (original_stdin_mode.0 | ENABLE_VIRTUAL_TERMINAL_INPUT.0 | ENABLE_WINDOW_INPUT.0)
                & !(ENABLE_PROCESSED_INPUT.0 | ENABLE_LINE_INPUT.0 | ENABLE_ECHO_INPUT.0),
        );
        let raw_out = CONSOLE_MODE(
            original_stdout_mode.0
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0
                | DISABLE_NEWLINE_AUTO_RETURN.0,
        );

        let in_set = unsafe { SetConsoleMode(h_stdin, raw_in) }.is_ok();
        if !in_set {
            return Self {
                h_stdin,
                h_stdout,
                original_stdin_mode,
                original_stdout_mode,
                active: false,
            };
        }
        let out_set = unsafe { SetConsoleMode(h_stdout, raw_out) }.is_ok();
        if !out_set {
            // Stdin succeeded; restore it so we don't leave a half-mutated state.
            let _ = unsafe { SetConsoleMode(h_stdin, original_stdin_mode) };
            return Self {
                h_stdin,
                h_stdout,
                original_stdin_mode,
                original_stdout_mode,
                active: false,
            };
        }

        Self {
            h_stdin,
            h_stdout,
            original_stdin_mode,
            original_stdout_mode,
            active: true,
        }
    }
}

impl Drop for ConsoleModeRestorer {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                let _ = SetConsoleMode(self.h_stdin, self.original_stdin_mode);
                let _ = SetConsoleMode(self.h_stdout, self.original_stdout_mode);
            }
        }
    }
}

// ── Console Ctrl handler RAII guard ──────────────────────────────────────
//
// When wxc-exec runs interactively, the local console owns the keyboard. A
// Ctrl-C from the user — or the user clicking the cmd.exe X button — fires
// `CTRL_C_EVENT` / `CTRL_CLOSE_EVENT` on wxc-exec. The OS default for
// `CTRL_CLOSE_EVENT` is to call `ExitProcess` on wxc-exec a short time
// later, which kills the relay threads mid-write and drops the agent's
// final output.
//
// `CtrlHandlerGuard` installs a process-wide handler for the relay
// lifetime that signals the stdin relay's stop event on either event,
// letting the relays drain naturally before scope exit. The handler
// returns TRUE so the OS does not invoke its default behavior; the
// per-process timeout enforced server-side remains the safety net.
//
// Partial scope: the handler stops the relay loops early, but does not
// shortcut `IsoSessionProcess::WaitForExit`, which wraps a blocking wait
// on a kernel handle we cannot multiplex with from the signal context.
// On terminal close we drain partial output cleanly before the server's
// grace period expires.

/// Raw integer payload of the stdin-stop-event HANDLE that the Ctrl
/// handler should signal on a registered ctrl event. `0` is the sentinel
/// for "no guard installed" (the handler treats it as a no-op for
/// signalling and still suppresses the default behavior).
///
/// `AtomicIsize` rather than wrapping the HANDLE directly because HANDLE
/// is `*mut c_void` and not `Send`/`Sync`; we marshal it via its raw
/// integer payload.
static STDIN_STOP_EVENT_RAW: AtomicIsize = AtomicIsize::new(0);

/// Process-wide console-ctrl handler. Win32 callback signature; cannot
/// capture environment, so reads its target from `STDIN_STOP_EVENT_RAW`.
///
/// # Safety
/// Registered with `SetConsoleCtrlHandler`; the OS calls it on a system
/// thread when a ctrl event fires. Only signals the stored event and
/// returns; no other state is touched.
unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> BOOL {
    if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT {
        let raw = STDIN_STOP_EVENT_RAW.load(Ordering::SeqCst);
        if raw != 0 {
            let h = HANDLE(raw as *mut core::ffi::c_void);
            let _ = SetEvent(h);
        }
        BOOL::from(true)
    } else {
        BOOL::from(false)
    }
}

/// RAII guard that installs the process-wide Ctrl handler for the
/// duration of an interactive isolation-session run. The handler signals
/// the stop event provided at install time on `CTRL_C_EVENT` or
/// `CTRL_CLOSE_EVENT`, allowing the stdin relay to exit gracefully rather
/// than being killed by the OS default `ExitProcess`.
///
/// Only one guard is alive at a time in wxc-exec's lifecycle (calls into
/// the manager are sequential per invocation). The static target handle
/// is set at install and cleared at drop.
pub(super) struct CtrlHandlerGuard {
    installed: bool,
}

impl CtrlHandlerGuard {
    /// Install the handler. `stop_event` must outlive the guard — the
    /// caller (`manager::create_process`) holds it in an `OwnedHandle`
    /// that drops after this guard, satisfying the constraint by Drop
    /// ordering. A failure to install is silently swallowed; the guard's
    /// `Drop` becomes a no-op in that case.
    pub(super) fn install(stop_event: HANDLE) -> Self {
        STDIN_STOP_EVENT_RAW.store(stop_event.0 as isize, Ordering::SeqCst);
        let installed = unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), true) }.is_ok();
        if !installed {
            STDIN_STOP_EVENT_RAW.store(0, Ordering::SeqCst);
        }
        Self { installed }
    }
}

impl Drop for CtrlHandlerGuard {
    fn drop(&mut self) {
        if self.installed {
            unsafe {
                let _ = SetConsoleCtrlHandler(Some(ctrl_handler), false);
            }
        }
        STDIN_STOP_EVENT_RAW.store(0, Ordering::SeqCst);
    }
}

/// Returns the dimensions of the local console's visible viewport as
/// `(columns, rows)`, or `None` if stdout is not a real console (redirected,
/// piped, or otherwise not console-backed).
///
/// Reads `srWindow` from `CONSOLE_SCREEN_BUFFER_INFO` — the visible window —
/// rather than `dwSize`, which is the full back-buffer and can be larger.
/// Callers that drive a ConPTY want the viewport.
pub(super) fn get_local_console_size() -> Option<(u16, u16)> {
    let h_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.ok()?;
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    if unsafe { GetConsoleScreenBufferInfo(h_stdout, &mut info) }.is_err() {
        return None;
    }
    let cols = (info.srWindow.Right - info.srWindow.Left + 1).max(0) as u16;
    let rows = (info.srWindow.Bottom - info.srWindow.Top + 1).max(0) as u16;
    if cols == 0 || rows == 0 {
        return None;
    }
    Some((cols, rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
    use windows_core::PCWSTR;

    /// All `CtrlHandlerGuard` / `ctrl_handler` tests must serialize against
    /// each other: they share `STDIN_STOP_EVENT_RAW` and the process-wide
    /// `SetConsoleCtrlHandler` registry. Other tests in the workspace do
    /// not touch these, so a module-local mutex is sufficient.
    static CTRL_HANDLER_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_get_local_console_size_does_not_panic() {
        // `cargo test` runs with stdio as pipes (`None`) on CI; locally a
        // real console is also possible (`Some((cols, rows))` with positive
        // dimensions). Either is acceptable — the contract under test is
        // "no panic, well-formed result".
        if let Some((cols, rows)) = get_local_console_size() {
            assert!(cols > 0);
            assert!(rows > 0);
        }
    }

    #[test]
    fn test_console_mode_restorer_handles_non_console() {
        // `cargo test` typically runs with stdio as pipes, not a real console.
        // Construction must not panic and Drop must run cleanly even when
        // `GetConsoleMode` fails on the non-console handles. The `active`
        // path is exercised by manual smoke testing on a real console.
        let _restorer = ConsoleModeRestorer::install_raw_vt();
        // Drop happens at end of scope.
    }

    #[test]
    fn test_ctrl_handler_guard_install_and_drop_do_not_panic() {
        // Construct + drop the guard with a real event handle. Verifies the
        // install / restore SetConsoleCtrlHandler calls succeed in the test
        // environment (process-wide handler list manipulation works without
        // a console attached) and that the static target is cleared on drop.
        let _lock = CTRL_HANDLER_TEST_LOCK.lock().unwrap();

        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()).unwrap() };

        {
            let _guard = CtrlHandlerGuard::install(event);
            // While the guard is alive, the static target should be set
            // to the event's raw pointer value (non-zero).
            assert_ne!(STDIN_STOP_EVENT_RAW.load(Ordering::SeqCst), 0);
        }

        // After drop, the static must be cleared.
        assert_eq!(STDIN_STOP_EVENT_RAW.load(Ordering::SeqCst), 0);

        unsafe {
            let _ = CloseHandle(event);
        }
    }

    #[test]
    fn test_ctrl_handler_signals_event_on_tracked_signals() {
        // Load-bearing behavior: with a guard installed, dispatching either
        // `CTRL_C_EVENT` or `CTRL_CLOSE_EVENT` to the handler must signal the
        // configured stop event and return TRUE so the OS does not invoke
        // its default behavior (which would `ExitProcess` on close).
        let _lock = CTRL_HANDLER_TEST_LOCK.lock().unwrap();

        let event = unsafe { CreateEventW(None, true, false, PCWSTR::null()).unwrap() };
        let _guard = CtrlHandlerGuard::install(event);

        for signal in [CTRL_C_EVENT, CTRL_CLOSE_EVENT] {
            unsafe {
                ResetEvent(event).unwrap();
            }
            let pre = unsafe { WaitForSingleObject(event, 0) };
            assert_ne!(
                pre, WAIT_OBJECT_0,
                "event should be reset before handler runs (signal {})",
                signal
            );

            let result = unsafe { ctrl_handler(signal) };
            assert!(
                result.as_bool(),
                "handler must return TRUE for tracked signal {}",
                signal
            );

            let post = unsafe { WaitForSingleObject(event, 100) };
            assert_eq!(
                post, WAIT_OBJECT_0,
                "event should be signaled after handler runs (signal {})",
                signal
            );
        }

        drop(_guard);
        unsafe {
            let _ = CloseHandle(event);
        }
    }

    #[test]
    fn test_ctrl_handler_returns_false_for_untracked_signals() {
        // Partial-scope contract: every signal other than `CTRL_C_EVENT` /
        // `CTRL_CLOSE_EVENT` must fall through to the next handler (or the
        // OS default) by returning FALSE.
        let _lock = CTRL_HANDLER_TEST_LOCK.lock().unwrap();

        for signal in [CTRL_BREAK_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT] {
            let result = unsafe { ctrl_handler(signal) };
            assert!(
                !result.as_bool(),
                "handler must return FALSE for untracked signal {}",
                signal
            );
        }
    }

    #[test]
    fn test_ctrl_handler_is_safe_with_no_target() {
        // Defensive: with no guard installed (`STDIN_STOP_EVENT_RAW == 0`),
        // calling the handler with a tracked signal must not crash and
        // must still return TRUE so the OS does not invoke its default
        // behavior. The handler performs no SetEvent in this state.
        let _lock = CTRL_HANDLER_TEST_LOCK.lock().unwrap();

        // Ensure no leftover target from any earlier test that may have
        // executed without the lock (defensive — the lock should prevent it).
        STDIN_STOP_EVENT_RAW.store(0, Ordering::SeqCst);

        for signal in [CTRL_C_EVENT, CTRL_CLOSE_EVENT] {
            let result = unsafe { ctrl_handler(signal) };
            assert!(
                result.as_bool(),
                "handler must return TRUE for signal {} even with no target",
                signal
            );
        }
    }
}
