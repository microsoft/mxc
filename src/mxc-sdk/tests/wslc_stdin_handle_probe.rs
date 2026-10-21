// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pins which stdio handles `WslcGetProcessIOHandle` returns under the pinned
//! WSLc SDK, for each `WslcProcessFlags` and callback combination.
//!
//! `#[ignore]`d because it boots a WSL2 utility VM and uses the create-and-run
//! image store, so no other WSLc run may hold that store. Run it with:
//!
//! ```text
//! cargo test -p mxc-sdk --features wslc --test wslc_stdin_handle_probe -- --ignored --nocapture
//! ```

#![cfg(all(windows, feature = "wslc"))]

use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::FromRawHandle;
use std::ptr;
use std::sync::mpsc;
use std::time::Duration;

use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::string_util::CoTaskMemPWSTR;
use mxc_sdk::wslc_common::container_steps::{
    create_daemon_container, create_daemon_session, load_sdk_checked, start_daemon_container,
    ProcessSettings, SessionSizing, KEEPALIVE_SCRIPT,
};
use mxc_sdk::wslc_common::image::{resolve_image, RegistryAccess, StoreHint};
use mxc_sdk::wslc_common::process_env::EnvScope;
use mxc_sdk::wslc_common::wslc_bindings::{
    WslcContainer, WslcContainerNetworkingMode, WslcContainerStartFlags, WslcProcess,
    WslcProcessCallbacks, WslcProcessFlags, WslcProcessGuard, WslcProcessIOHandle, WslcSdk,
    WslcSession, WslcSignal, BYTE, HANDLE, HRESULT, INT32, PVOID, S_OK,
};

const E_INVALIDARG: HRESULT = 0x8007_0057_u32 as HRESULT;

/// `HRESULT_FROM_WIN32(ERROR_INVALID_STATE)`, returned for a handle a callback already took.
const CONSUMED_BY_CALLBACK: HRESULT = 0x8007_139F_u32 as HRESULT;

const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq)]
struct Hr(HRESULT);

impl fmt::Debug for Hr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0 as u32)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct HandleResults {
    stdin: Hr,
    stdout: Hr,
    stderr: Hr,
}

#[derive(Default)]
struct OpenedHandles {
    stdin: Option<File>,
    stdout: Option<File>,
    _stderr: Option<File>,
}

#[derive(Clone, Copy, Debug)]
enum Callbacks {
    None,
    ExitOnly,
    IoAndExit,
}

unsafe extern "C" fn ignore_output(
    _handle: WslcProcessIOHandle,
    _data: *const BYTE,
    _len: u32,
    _context: PVOID,
) {
}

unsafe extern "C" fn ignore_exit(_code: INT32, _context: PVOID) {}

struct ComApartment;

impl ComApartment {
    fn enter() -> Self {
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

        // SAFETY: `Drop` balances this on the same thread.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        assert!(hr.is_ok(), "CoInitializeEx(MTA) failed: {hr:?}");
        Self
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: balances the `CoInitializeEx` in `enter`, on the same thread.
        unsafe { windows::Win32::System::Com::CoUninitialize() };
    }
}

/// `WslcSdk::load` only looks beside the module calling it, which for a test is
/// `deps/`, while the build script stages the DLL one directory up.
fn stage_sdk_beside_test_binary() {
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("test binary directory");
    let staged = deps
        .parent()
        .expect("profile directory")
        .join("wslcsdk.dll");
    std::fs::copy(&staged, deps.join("wslcsdk.dll")).unwrap_or_else(|e| {
        panic!(
            "copy {} beside the test binary: {e}. Build with --features wslc first.",
            staged.display()
        )
    });
}

/// # Safety
/// `sdk` must hold valid function pointers and COM must be initialised on this thread.
unsafe fn process_settings(
    sdk: &WslcSdk,
    script: &str,
    flags: WslcProcessFlags,
    callbacks: Callbacks,
) -> ProcessSettings {
    let mut settings = ProcessSettings::build_detached(sdk, script, &[], EnvScope::Merge, "")
        .expect("build process settings");

    let table = match callbacks {
        Callbacks::None => None,
        Callbacks::ExitOnly => Some(WslcProcessCallbacks {
            onStdOut: None,
            onStdErr: None,
            onExit: Some(ignore_exit),
        }),
        Callbacks::IoAndExit => Some(WslcProcessCallbacks {
            onStdOut: Some(ignore_output),
            onStdErr: Some(ignore_output),
            onExit: Some(ignore_exit),
        }),
    };
    if let Some(table) = table {
        let hr = sdk.WslcSetProcessSettingsCallbacks(settings.raw_mut(), &table, ptr::null_mut());
        assert_eq!(Hr(hr), Hr(S_OK), "WslcSetProcessSettingsCallbacks");
    }

    let hr = sdk.WslcSetProcessSettingsFlags(settings.raw_mut(), flags);
    assert_eq!(Hr(hr), Hr(S_OK), "WslcSetProcessSettingsFlags({flags:?})");
    settings
}

/// # Safety
/// `sdk` must hold valid function pointers and `process` must be a live handle.
unsafe fn probe(
    sdk: &WslcSdk,
    process: WslcProcess,
    label: &str,
) -> (HandleResults, OpenedHandles) {
    let open = |which: WslcProcessIOHandle, name: &str| {
        let mut handle: HANDLE = ptr::null_mut();
        let hr = sdk.WslcGetProcessIOHandle(process, which, &mut handle);
        println!("[{label}] {name}: {:?}", Hr(hr));
        if hr != S_OK {
            return (Hr(hr), None);
        }
        assert!(
            !handle.is_null(),
            "[{label}] {name} returned S_OK with a null handle"
        );
        (Hr(hr), Some(File::from_raw_handle(handle)))
    };

    let (stdin, stdin_file) = open(WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDIN, "stdin");
    let (stdout, stdout_file) = open(WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDOUT, "stdout");
    let (stderr, stderr_file) = open(WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDERR, "stderr");
    (
        HandleResults {
            stdin,
            stdout,
            stderr,
        },
        OpenedHandles {
            stdin: stdin_file,
            stdout: stdout_file,
            _stderr: stderr_file,
        },
    )
}

/// # Safety
/// `sdk` must hold valid function pointers, `container` must be a live started
/// handle, and COM must be initialised on this thread.
unsafe fn probe_exec(
    sdk: &WslcSdk,
    container: WslcContainer,
    flags: WslcProcessFlags,
    callbacks: Callbacks,
) -> (HandleResults, OpenedHandles, WslcProcessGuard) {
    let label = format!("exec {flags:?} {callbacks:?}");
    let mut settings = process_settings(sdk, "cat", flags, callbacks);

    let mut process: WslcProcess = ptr::null_mut();
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcCreateContainerProcess(
        container,
        settings.raw_mut(),
        &mut process,
        err_msg.as_mut_ptr(),
    );
    assert_eq!(
        Hr(hr),
        Hr(S_OK),
        "[{label}] WslcCreateContainerProcess: {}",
        err_msg.to_string_lossy()
    );
    let process = WslcProcessGuard::from_raw(process, sdk.release_process_fn());
    settings.mark_process_created();

    let (results, handles) = probe(sdk, process.as_raw(), &label);
    (results, handles, process)
}

/// The init process takes a separate SDK path from `WslcCreateContainerProcess`.
///
/// # Safety
/// `sdk` must hold valid function pointers, `session` must be a live handle,
/// and COM must be initialised on this thread.
unsafe fn probe_attached_init(
    sdk: &WslcSdk,
    session: WslcSession,
    flags: WslcProcessFlags,
    logger: &mut Logger,
) -> HandleResults {
    let label = format!("attached init {flags:?}");
    let mut init = process_settings(sdk, "cat", flags, Callbacks::None);
    let container = create_daemon_container(
        sdk,
        session,
        "alpine:latest",
        &[],
        &[],
        WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_NONE,
        false,
        &mut init,
        logger,
    )
    .expect("create attached container");

    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcStartContainer(
        container.as_raw(),
        WslcContainerStartFlags::WSLC_CONTAINER_START_FLAG_ATTACH,
        err_msg.as_mut_ptr(),
    );
    assert_eq!(
        Hr(hr),
        Hr(S_OK),
        "[{label}] WslcStartContainer(ATTACH): {}",
        err_msg.to_string_lossy()
    );
    init.mark_process_created();

    let mut process: WslcProcess = ptr::null_mut();
    let hr = sdk.WslcGetContainerInitProcess(container.as_raw(), &mut process);
    assert_eq!(Hr(hr), Hr(S_OK), "[{label}] WslcGetContainerInitProcess");
    let process = WslcProcessGuard::from_raw(process, sdk.release_process_fn());

    let (results, handles) = probe(sdk, process.as_raw(), &label);
    drop(handles);
    let _ = sdk.WslcStopContainer(
        container.as_raw(),
        WslcSignal::WSLC_SIGNAL_SIGKILL,
        5,
        ptr::null_mut(),
    );
    results
}

fn round_trip(handles: OpenedHandles, payload: &[u8]) -> Vec<u8> {
    let mut stdin = handles.stdin.expect("stdin handle");
    let mut stdout = handles.stdout.expect("stdout handle");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut echoed = Vec::new();
        let _ = tx.send(stdout.read_to_end(&mut echoed).map(|_| echoed));
    });

    stdin.write_all(payload).expect("write stdin");
    drop(stdin);

    rx.recv_timeout(ROUND_TRIP_TIMEOUT)
        .expect("cat did not reach EOF after stdin was closed")
        .expect("read stdout")
}

#[test]
#[ignore = "boots a WSL2 utility VM and needs alpine:latest"]
fn stdin_handle_requires_the_stdin_process_flag() {
    stage_sdk_beside_test_binary();
    let _com = ComApartment::enter();
    let mut logger = Logger::new(Mode::Console);
    let store = StoreHint::CreateAndRun(None);
    let storage = std::env::temp_dir()
        .join("mxc-wslc-sessions")
        .to_string_lossy()
        .to_string();

    let off = WslcProcessFlags::WSLC_PROCESS_FLAG_NONE;
    let on = WslcProcessFlags::WSLC_PROCESS_FLAG_STDIN;
    let available = Hr(S_OK);
    let rejected = Hr(E_INVALIDARG);
    let consumed = Hr(CONSUMED_BY_CALLBACK);

    // SAFETY: COM is initialised on this thread for the whole test, and every
    // guard outlives the SDK calls made against the handle it owns.
    unsafe {
        let sdk = load_sdk_checked(&mut logger).expect("WSLc runtime unavailable");

        let mut unknown_bit =
            ProcessSettings::build_detached(&sdk, "cat", &[], EnvScope::Merge, "")
                .expect("build process settings");
        let hr = sdk.WslcSetProcessSettingsFlags(unknown_bit.raw_mut(), WslcProcessFlags(0x2));
        assert_eq!(Hr(hr), rejected, "an unknown process flag must be rejected");

        let session = create_daemon_session(
            &sdk,
            "mxc-wslc-stdin-probe",
            &storage,
            SessionSizing::default(),
            &mut logger,
        )
        .expect("create session");
        resolve_image(
            &sdk,
            session.as_raw(),
            "alpine:latest",
            None,
            &store,
            RegistryAccess::Allowed,
            "[WSLC][probe]",
            &mut logger,
        )
        .expect("resolve alpine:latest");

        let mut keepalive = process_settings(&sdk, KEEPALIVE_SCRIPT, off, Callbacks::None);
        let container = create_daemon_container(
            &sdk,
            session.as_raw(),
            "alpine:latest",
            &[],
            &[],
            WslcContainerNetworkingMode::WSLC_CONTAINER_NETWORKING_MODE_NONE,
            false,
            &mut keepalive,
            &mut logger,
        )
        .expect("create container");
        keepalive.mark_process_created();
        start_daemon_container(&sdk, container.as_raw(), &mut logger).expect("start container");

        let expectations = [
            (off, Callbacks::None, rejected, available),
            (off, Callbacks::ExitOnly, rejected, consumed),
            (off, Callbacks::IoAndExit, rejected, consumed),
            (on, Callbacks::None, available, available),
            (on, Callbacks::ExitOnly, available, consumed),
            (on, Callbacks::IoAndExit, available, consumed),
        ];
        for (flags, callbacks, stdin, output) in expectations {
            let (results, handles, process) =
                probe_exec(&sdk, container.as_raw(), flags, callbacks);
            assert_eq!(
                results,
                HandleResults {
                    stdin,
                    stdout: output,
                    stderr: output,
                },
                "exec with {flags:?} and {callbacks:?} callbacks"
            );

            if matches!(callbacks, Callbacks::None) && flags == on {
                let payload = b"stdin reaches the container\n";
                assert_eq!(round_trip(handles, payload), payload);
            } else {
                drop(handles);
            }
            sdk.WslcSignalProcess(process.as_raw(), WslcSignal::WSLC_SIGNAL_SIGKILL);
        }

        for (flags, stdin) in [(off, rejected), (on, available)] {
            assert_eq!(
                probe_attached_init(&sdk, session.as_raw(), flags, &mut logger),
                HandleResults {
                    stdin,
                    stdout: available,
                    stderr: available,
                },
                "attached init with {flags:?}"
            );
        }

        let _ = sdk.WslcStopContainer(
            container.as_raw(),
            WslcSignal::WSLC_SIGNAL_SIGKILL,
            5,
            ptr::null_mut(),
        );
    }
}
