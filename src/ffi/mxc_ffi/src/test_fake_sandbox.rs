// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A test-only sandbox whose native wait and output the managed SDK tests hold open.

use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use mxc_sdk::mxc_common::models::SandboxOutputMetadata;
use mxc_sdk::mxc_common::sandbox_process::NativeStdio;
use mxc_sdk::v1::{StreamCloser, WaitResult};

use crate::streaming::{LiveSandbox, MxcSandbox};
use crate::{MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC, MXC_STATUS_SUCCESS};

#[derive(Default)]
struct FakeState {
    exited: bool,
    wait_entered: bool,
    wait_released: bool,
    output_released: bool,
}

#[derive(Default)]
pub struct MxcTestFakeControl {
    state: Mutex<FakeState>,
    changed: Condvar,
}

impl MxcTestFakeControl {
    fn update(&self, change: impl FnOnce(&mut FakeState)) {
        change(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
        self.changed.notify_all();
    }

    fn wait_until(&self, done: impl Fn(&FakeState) -> bool, timeout: Option<Duration>) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let state = match timeout {
            Some(timeout) => {
                self.changed
                    .wait_timeout_while(state, timeout, |s| !done(s))
                    .unwrap_or_else(|e| e.into_inner())
                    .0
            }
            None => self
                .changed
                .wait_while(state, |s| !done(s))
                .unwrap_or_else(|e| e.into_inner()),
        };
        done(&state)
    }
}

struct FakeSandbox {
    control: Arc<MxcTestFakeControl>,
    stdout: Option<HeldOutput>,
    exit_code: i32,
}

/// Reports end-of-file only once the test releases it, like a pipe a
/// descendant process keeps open.
struct HeldOutput(Arc<MxcTestFakeControl>);

impl Read for HeldOutput {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        self.0.wait_until(|s| s.output_released, None);
        Ok(0)
    }
}

impl LiveSandbox for FakeSandbox {
    fn warnings(&self) -> Vec<String> {
        vec!["fake warning".to_string()]
    }

    fn output_metadata(&self) -> Option<SandboxOutputMetadata> {
        None
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        Ok(None)
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        None
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stdout
            .take()
            .map(|output| Box::new(output) as Box<dyn Read + Send>)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        None
    }

    fn stdout_closer(&self) -> Option<StreamCloser> {
        None
    }

    fn stderr_closer(&self) -> Option<StreamCloser> {
        None
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        let exited = self
            .control
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .exited;
        Ok(exited.then_some(self.exit_code))
    }

    fn id(&self) -> u32 {
        7
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.control.update(|s| s.exited = true);
        Ok(())
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.kill()
    }

    fn wait(&mut self) -> std::io::Result<WaitResult> {
        self.control.update(|s| s.wait_entered = true);
        self.control.wait_until(|s| s.wait_released, None);
        Ok(WaitResult::Exited(self.exit_code))
    }
}

/// Create a fake sandbox that exits with `exit_code`, at once if `exited` is
/// nonzero or otherwise when killed. Its stdout, if `held_stdout` is nonzero,
/// stays open until released.
///
/// Free the sandbox with `mxc_sandbox_free` and the control with
/// [`mxc_test_fake_control_free`].
///
/// # Safety
/// `out_sandbox` and `out_control` must be null or writable pointer storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_test_fake_sandbox_new(
    exit_code: i32,
    exited: i32,
    held_stdout: i32,
    out_sandbox: *mut *mut MxcSandbox,
    out_control: *mut *const MxcTestFakeControl,
) -> i32 {
    if out_sandbox.is_null() || out_control.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let control = Arc::new(MxcTestFakeControl::default());
        control.update(|s| s.exited = exited != 0);
        let sandbox = FakeSandbox {
            control: Arc::clone(&control),
            stdout: (held_stdout != 0).then(|| HeldOutput(Arc::clone(&control))),
            exit_code,
        };
        // SAFETY: both out pointers are non-null and writable per the caller contract.
        unsafe {
            *out_sandbox = Box::into_raw(Box::new(MxcSandbox::from_live(Box::new(sandbox))));
            *out_control = Arc::into_raw(control);
        }
        MXC_STATUS_SUCCESS
    }))
    .unwrap_or(MXC_STATUS_PANIC)
}

/// Return 1 once the fake sandbox's native wait has started, or 0 if it has
/// not started within `timeout_ms`.
///
/// # Safety
/// `control` must be a live handle from [`mxc_test_fake_sandbox_new`].
#[no_mangle]
pub unsafe extern "C" fn mxc_test_fake_control_await_wait(
    control: *const MxcTestFakeControl,
    timeout_ms: u32,
) -> i32 {
    // SAFETY: a live handle per the caller contract.
    let control = unsafe { &*control };
    i32::from(control.wait_until(
        |s| s.wait_entered,
        Some(Duration::from_millis(timeout_ms.into())),
    ))
}

/// # Safety
/// `control` must be a live handle from [`mxc_test_fake_sandbox_new`].
#[no_mangle]
pub unsafe extern "C" fn mxc_test_fake_control_release_wait(control: *const MxcTestFakeControl) {
    // SAFETY: a live handle per the caller contract.
    unsafe { &*control }.update(|s| s.wait_released = true);
}

/// # Safety
/// `control` must be a live handle from [`mxc_test_fake_sandbox_new`].
#[no_mangle]
pub unsafe extern "C" fn mxc_test_fake_control_release_output(control: *const MxcTestFakeControl) {
    // SAFETY: a live handle per the caller contract.
    unsafe { &*control }.update(|s| s.output_released = true);
}

/// # Safety
/// `control` must be null or a live handle, freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn mxc_test_fake_control_free(control: *const MxcTestFakeControl) {
    if !control.is_null() {
        // SAFETY: produced by `Arc::into_raw` and not yet freed.
        drop(unsafe { Arc::from_raw(control) });
    }
}
