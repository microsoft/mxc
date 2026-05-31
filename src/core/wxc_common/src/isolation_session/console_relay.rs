// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Console-aware stdin relay for the IsolationSession backend's interactive
//! mode. Unlike the byte-oriented [`super::pipe_relay`] primitives, this
//! relay inspects each `INPUT_RECORD` as it arrives at the local console
//! input handle and dispatches by event type:
//!
//! - Key-down events are forwarded as cooked VT bytes (`ReadFile` on the
//!   console handle, then `WriteFile` to the agent's stdin pipe).
//! - Console-window-resize events are consumed, the current viewport
//!   dimensions are read, and the caller-supplied resize callback is
//!   invoked (used to push the new size into the inner ConPTY).
//! - Key-ups, mouse events, focus changes, and menu events are consumed
//!   and discarded so the input queue keeps draining.
//!
//! The dispatch decision is computed by the pure helper [`classify`] so it
//! can be exhaustively unit-tested against synthetic records without
//! requiring a real console.

use crate::error::WxcError;
use crate::process_util::OwnedHandle;

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
use windows::Win32::System::Console::{
    PeekConsoleInputW, ReadConsoleInputW, INPUT_RECORD, KEY_EVENT, WINDOW_BUFFER_SIZE_EVENT,
};
use windows::Win32::System::Threading::{
    CreateThread, WaitForMultipleObjects, THREAD_CREATION_FLAGS,
};

use super::console_mode::get_local_console_size;

const BUFFER_SIZE: u32 = 4096;

/// Per-record dispatch decision computed by [`classify`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum InputAction {
    /// Key-down event: drain the cooked-VT byte sequence via `ReadFile`
    /// and forward to the agent's stdin.
    ForwardCookedBytes,
    /// Console viewport resized: consume the record, query the current
    /// viewport, invoke the resize callback.
    ResizeViewport,
    /// Key-up, mouse, focus, or menu event: consume the record so the
    /// queue keeps moving, then discard. Nothing is forwarded to the
    /// agent.
    ConsumeAndDiscard,
}

/// Pure function deciding what to do with a peeked input record. Pulled
/// out for exhaustive unit testing against synthetic records.
pub(super) fn classify(record: &INPUT_RECORD) -> InputAction {
    match record.EventType as u32 {
        KEY_EVENT => {
            // SAFETY: the Win32 contract guarantees that when
            // `EventType == KEY_EVENT`, the `KeyEvent` union variant is
            // the active one.
            let is_key_down = unsafe { record.Event.KeyEvent.bKeyDown.as_bool() };
            if is_key_down {
                InputAction::ForwardCookedBytes
            } else {
                InputAction::ConsumeAndDiscard
            }
        }
        WINDOW_BUFFER_SIZE_EVENT => InputAction::ResizeViewport,
        _ => InputAction::ConsumeAndDiscard,
    }
}

/// Parameters for a console-aware relay thread.
///
/// `h_read` is wxc-exec's local console input handle. `h_write` is the
/// pipe handle to the agent process's stdin. `h_stop_event` is a
/// manual-reset event the caller signals to ask the relay to exit. The
/// resize callback is invoked from the relay thread on each
/// `WINDOW_BUFFER_SIZE_EVENT` with the local console's current viewport
/// dimensions.
///
/// # Safety
/// All three handles must remain valid until the relay thread exits, and
/// this struct must outlive the thread (the caller waits on the thread
/// before dropping the struct).
pub(super) struct ConsoleRelayParams {
    pub h_read: HANDLE,
    pub h_write: HANDLE,
    pub h_stop_event: HANDLE,
    pub resize_callback: Box<dyn Fn(u16, u16) + Send + 'static>,
}

/// Thread procedure for the console-aware relay.
///
/// Loops on `WaitForMultipleObjects({h_stop_event, h_read})`. When the
/// console signals input available, peeks at the next record and
/// dispatches per [`classify`]. Exits on stop-event signal, read EOF,
/// write error, peek error, or wait failure.
///
/// # Safety
/// `param` must point to a valid `ConsoleRelayParams` that outlives the
/// thread.
unsafe extern "system" fn console_relay_thread_proc(param: *mut core::ffi::c_void) -> u32 {
    let params = &*(param as *const ConsoleRelayParams);
    let mut buffer = [0u8; BUFFER_SIZE as usize];
    let wait_handles = [params.h_stop_event, params.h_read];

    loop {
        let wait_result = WaitForMultipleObjects(&wait_handles, false, u32::MAX);
        // `WAIT_OBJECT_0 + 1` means `h_read` signalled. Anything else
        // (stop event, WAIT_FAILED, etc.) breaks the loop.
        if wait_result.0 != WAIT_OBJECT_0.0 + 1 {
            break;
        }

        // Peek (without consuming) so we can decide dispatch.
        let mut peek_buf = [INPUT_RECORD::default(); 1];
        let mut peek_count = 0u32;
        if PeekConsoleInputW(params.h_read, &mut peek_buf, &mut peek_count).is_err() {
            break;
        }
        if peek_count == 0 {
            // Wait fired but the queue drained between wait and peek (or
            // an internal consumer drained it). Loop back; the next wait
            // re-blocks until input is actually available.
            continue;
        }

        match classify(&peek_buf[0]) {
            InputAction::ForwardCookedBytes => {
                let mut bytes_read = 0u32;
                if ReadFile(
                    params.h_read,
                    Some(&mut buffer),
                    Some(&mut bytes_read),
                    None,
                )
                .is_err()
                    || bytes_read == 0
                {
                    break;
                }
                let mut bytes_written = 0u32;
                if WriteFile(
                    params.h_write,
                    Some(&buffer[..bytes_read as usize]),
                    Some(&mut bytes_written),
                    None,
                )
                .is_err()
                    || bytes_written != bytes_read
                {
                    break;
                }
                let _ = FlushFileBuffers(params.h_write);
            }
            InputAction::ResizeViewport => {
                // Consume the record so the next iteration sees fresh
                // data. The record's payload carries the *buffer* size,
                // not the visible viewport — query the viewport directly
                // and pass that to the callback.
                let mut discard = [INPUT_RECORD::default(); 1];
                let mut consumed = 0u32;
                let _ = ReadConsoleInputW(params.h_read, &mut discard, &mut consumed);
                if let Some((cols, rows)) = get_local_console_size() {
                    (params.resize_callback)(cols, rows);
                }
            }
            InputAction::ConsumeAndDiscard => {
                let mut discard = [INPUT_RECORD::default(); 1];
                let mut consumed = 0u32;
                let _ = ReadConsoleInputW(params.h_read, &mut discard, &mut consumed);
            }
        }
    }

    0
}

/// Create the console-aware relay thread. Returns the thread HANDLE
/// wrapped in `OwnedHandle`.
///
/// # Safety
/// `params` must remain valid until the thread exits. The caller is
/// responsible for joining (waiting on) the thread before `params` is
/// dropped.
pub(super) unsafe fn create_console_relay_thread(
    params: *mut ConsoleRelayParams,
) -> Result<OwnedHandle, WxcError> {
    let handle = CreateThread(
        None,
        0,
        Some(console_relay_thread_proc),
        Some(params as *const core::ffi::c_void),
        THREAD_CREATION_FLAGS(0),
        None,
    )
    .map_err(|e| {
        WxcError::Process(format!(
            "CreateThread for console-aware relay failed: {}",
            e
        ))
    })?;

    Ok(OwnedHandle::new(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Console::{
        COORD, FOCUS_EVENT, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, MENU_EVENT, MOUSE_EVENT,
        WINDOW_BUFFER_SIZE_RECORD,
    };
    use windows_core::BOOL;

    /// Build a synthetic KEY_EVENT input record. `key_down` selects
    /// key-down (true) or key-up (false).
    fn make_key_event(key_down: bool) -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: windows::Win32::System::Console::INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: BOOL::from(key_down),
                    wRepeatCount: 1,
                    wVirtualKeyCode: 0x41, // 'A'
                    wVirtualScanCode: 0x1E,
                    uChar: KEY_EVENT_RECORD_0 {
                        UnicodeChar: 'a' as u16,
                    },
                    dwControlKeyState: 0,
                },
            },
        }
    }

    fn make_resize_event() -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: WINDOW_BUFFER_SIZE_EVENT as u16,
            Event: windows::Win32::System::Console::INPUT_RECORD_0 {
                WindowBufferSizeEvent: WINDOW_BUFFER_SIZE_RECORD {
                    dwSize: COORD { X: 80, Y: 25 },
                },
            },
        }
    }

    fn make_bare_event(event_type: u32) -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: event_type as u16,
            ..Default::default()
        }
    }

    #[test]
    fn classify_key_down_forwards_cooked_bytes() {
        assert_eq!(
            classify(&make_key_event(true)),
            InputAction::ForwardCookedBytes
        );
    }

    #[test]
    fn classify_key_up_consumes_and_discards() {
        // Key-up events produce no cooked bytes — calling ReadFile would
        // block waiting for the next key-down. Drain via ReadConsoleInputW
        // instead so the queue keeps moving.
        assert_eq!(
            classify(&make_key_event(false)),
            InputAction::ConsumeAndDiscard
        );
    }

    #[test]
    fn classify_window_buffer_size_event_triggers_resize() {
        assert_eq!(classify(&make_resize_event()), InputAction::ResizeViewport);
    }

    #[test]
    fn classify_mouse_event_consumes_and_discards() {
        assert_eq!(
            classify(&make_bare_event(MOUSE_EVENT)),
            InputAction::ConsumeAndDiscard
        );
    }

    #[test]
    fn classify_focus_event_consumes_and_discards() {
        assert_eq!(
            classify(&make_bare_event(FOCUS_EVENT)),
            InputAction::ConsumeAndDiscard
        );
    }

    #[test]
    fn classify_menu_event_consumes_and_discards() {
        assert_eq!(
            classify(&make_bare_event(MENU_EVENT)),
            InputAction::ConsumeAndDiscard
        );
    }

    #[test]
    fn classify_unknown_event_type_consumes_and_discards() {
        // Future event types (or anything stray) must also drain rather
        // than block ReadFile.
        assert_eq!(
            classify(&make_bare_event(0xFFFF)),
            InputAction::ConsumeAndDiscard
        );
    }

    // ── ConsoleRelayParams + create_console_relay_thread ──────────────────
    //
    // The thread proc's per-record dispatch logic is exercised by the
    // `classify_*` tests above. These two tests cover the construction +
    // teardown plumbing that does not require a real console:
    //   - resize-callback type wiring (Box<dyn Fn + Send + 'static>);
    //   - defensive exit on invalid h_read (parallel to
    //     `test_pipe_relay_with_stop_exits_on_invalid_handle`).
    // The actual record dispatch behavior is covered by the manual
    // resize smoke on a real console.

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
    use windows_core::PCWSTR;

    #[test]
    fn test_resize_callback_invocation_via_box() {
        // Construct `ConsoleRelayParams` with a closure that mutates an
        // observable Arc, then invoke the boxed callback directly.
        // Exercises the `Box<dyn Fn(u16, u16) + Send + 'static>` field's
        // type bounds and call-site syntax without needing the relay
        // thread to run. A refactor that breaks Send / 'static / the
        // dyn Fn signature will fail to compile or to run this test.
        let counter = Arc::new(AtomicU32::new(0));
        let counter_for_cb = Arc::clone(&counter);

        let params = ConsoleRelayParams {
            h_read: HANDLE::default(),
            h_write: HANDLE::default(),
            h_stop_event: HANDLE::default(),
            resize_callback: Box::new(move |cols, rows| {
                assert_eq!(cols, 120);
                assert_eq!(rows, 30);
                counter_for_cb.fetch_add(1, Ordering::SeqCst);
            }),
        };

        (params.resize_callback)(120, 30);
        (params.resize_callback)(120, 30);

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "callback should be invokable multiple times"
        );
    }

    #[test]
    fn test_console_relay_exits_on_invalid_handle() {
        // Defensive path: pass a default (invalid) HANDLE for h_read.
        // WaitForMultipleObjects sees the invalid handle and returns
        // WAIT_FAILED → the relay loop breaks → the thread exits
        // cleanly. No panic, no hang. Parallel to
        // `test_pipe_relay_with_stop_exits_on_invalid_handle`.
        let stop_event = unsafe {
            let h = CreateEventW(None, true, false, PCWSTR::null()).unwrap();
            OwnedHandle::new(h)
        };

        let mut params = ConsoleRelayParams {
            h_read: HANDLE::default(),
            h_write: HANDLE::default(),
            h_stop_event: stop_event.get(),
            resize_callback: Box::new(|_, _| {}),
        };
        let relay_thread = unsafe { create_console_relay_thread(&mut params).unwrap() };

        let wait_result = unsafe { WaitForSingleObject(relay_thread.get(), 5000) };
        assert_eq!(
            wait_result, WAIT_OBJECT_0,
            "Relay did not exit on invalid h_read"
        );
    }
}
