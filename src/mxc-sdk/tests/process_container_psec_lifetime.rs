// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows PSEC lifetime probe.
//!
//! These tests drive the `processmodel.dll` process security environment
//! (PSEC) API directly, below the MXC runner, to record what one
//! `HPROCESS_SECURITY_ENVIRONMENT` handle supports:
//!
//! * sequential launches that share the container's temp directory,
//! * concurrent launches against one handle,
//! * `CloseProcessSecurityEnvironment` with a running or terminated child,
//! * creation failures and launch failures.
//!
//! The tests only observe. They never delete a container profile: each
//! scenario closes the handle it created and then waits to see whether the
//! profile directory it learned from the child's `TEMP` disappears. The only
//! files they remove are inside a `tempfile` scratch directory they created.
//!
//! Every observation is printed as a `PSEC-OBSERVATION key=value` line; run
//! with `--nocapture` to keep them. Production PSEC reuse is out of scope:
//! this file does not change how MXC creates or closes environments.
//!
//! Requires a PSEC-capable Windows host, so the tests are `#[ignore]`d.

#![cfg(target_os = "windows")]

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flatbuffers::FlatBufferBuilder;
use mxc_sdk::process_container_common::{
    ProcessSecurityEnvironment, ProcessSecurityEnvironmentApi, SecurityEnvironmentStartupInfo,
    PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
};
use mxc_sdk::process_security_environment_spec::process_security_environment_layout::{
    finish_process_security_environment_buffer, ProcessSecurityEnvironmentT, SchemaVersionT,
};
use windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

const MARKER_FILE: &str = "mxc-psec-lifetime.txt";
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(90);
const PROFILE_REMOVAL_LIMIT: Duration = Duration::from_secs(10);

fn observe(key: &str, value: impl Display) {
    println!("PSEC-OBSERVATION {key}={value}");
}

fn one_line(text: &str) -> String {
    text.replace('\r', "").replace('\n', " | ")
}

// ---------------------------------------------------------------------------
// PSEC specification
// ---------------------------------------------------------------------------

/// Minimal PSEC specification with no capabilities, optionally with
/// read/write paths granted through the broker.
// The generated type is non-exhaustive outside the crate, so fields are assigned.
#[allow(clippy::field_reassign_with_default)]
fn build_spec_version(major: u16, read_write: &[&Path]) -> Vec<u8> {
    let mut spec = ProcessSecurityEnvironmentT::default();
    spec.version = SchemaVersionT { major, minor: 0 };
    if !read_write.is_empty() {
        spec.fs_read_write = Some(
            read_write
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
        );
    }
    let mut builder = FlatBufferBuilder::with_capacity(512);
    let spec = spec.pack(&mut builder);
    finish_process_security_environment_buffer(&mut builder, spec);
    builder.finished_data().to_vec()
}

fn build_spec(read_write: &[&Path]) -> Vec<u8> {
    build_spec_version(1, read_write)
}

fn load_api() -> ProcessSecurityEnvironmentApi {
    ProcessSecurityEnvironmentApi::load().expect("this host must expose the PSEC API")
}

// ---------------------------------------------------------------------------
// Launching and observing a child in an existing environment
// ---------------------------------------------------------------------------

struct Child {
    process: OwnedHandle,
    output: File,
    started: Instant,
}

struct Report {
    exit_code: u32,
    output: String,
}

impl Report {
    fn field(&self, key: &str) -> Option<&str> {
        self.output.lines().find_map(|line| {
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix('='))
                .map(str::trim)
        })
    }

    fn required(&self, key: &str) -> &str {
        self.field(key)
            .unwrap_or_else(|| panic!("child output lacks {key}=; output was:\n{}", self.output))
    }
}

impl Child {
    fn handle(&self) -> HANDLE {
        HANDLE(self.process.as_raw_handle())
    }

    /// Wait up to `timeout`; `None` means the child is still running.
    fn wait(&self, timeout: Duration) -> Option<u32> {
        let milliseconds = u32::try_from(timeout.as_millis()).expect("timeout fits in u32");
        // SAFETY: `self.process` owns a valid process handle.
        let wait = unsafe { WaitForSingleObject(self.handle(), milliseconds) };
        if wait != WAIT_OBJECT_0 {
            return None;
        }
        let mut exit_code = 0u32;
        // SAFETY: the process has signalled exit and the handle is valid.
        unsafe { GetExitCodeProcess(self.handle(), &mut exit_code) }
            .expect("GetExitCodeProcess must succeed for an exited child");
        Some(exit_code)
    }

    fn terminate(&self) {
        // SAFETY: `self.process` owns a valid process handle. Failure means
        // the child already exited, which is the state the caller wants.
        let _ = unsafe { TerminateProcess(self.handle(), 1) };
    }

    /// Wait for exit and read everything the child wrote. A child that does
    /// not exit within `LAUNCH_TIMEOUT` is terminated and reported as a
    /// failure.
    fn collect(mut self) -> Report {
        let Some(exit_code) = self.wait(LAUNCH_TIMEOUT) else {
            self.terminate();
            panic!("child did not exit within {LAUNCH_TIMEOUT:?}");
        };
        observe("child_wall_ms", self.started.elapsed().as_millis());
        let mut output = String::new();
        self.output
            .read_to_string(&mut output)
            .expect("read child output");
        Report { exit_code, output }
    }
}

/// Anonymous pipe whose write end is inheritable and read end is not.
fn create_output_pipe() -> Result<(File, OwnedHandle), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| "SECURITY_ATTRIBUTES size".to_string())?,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    // SAFETY: both out-pointers are valid locals.
    unsafe { CreatePipe(&mut read, &mut write, Some(&attributes), 0) }
        .map_err(|error| format!("CreatePipe failed: {error}"))?;
    // SAFETY: CreatePipe returned two handles that nothing else owns.
    let (read, write) = unsafe {
        (
            OwnedHandle::from_raw_handle(read.0),
            OwnedHandle::from_raw_handle(write.0),
        )
    };
    // SAFETY: `read` is a valid handle owned above.
    unsafe {
        SetHandleInformation(
            HANDLE(read.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAGS(0),
        )
    }
    .map_err(|error| format!("SetHandleInformation failed: {error}"))?;
    Ok((File::from(read), write))
}

/// Environment block for `CREATE_UNICODE_ENVIRONMENT`.
fn environment_block(variables: &[(&str, &str)]) -> Vec<u16> {
    let mut entries: Vec<String> = variables
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    entries.sort_by_key(|entry| entry.to_ascii_uppercase());
    let mut block: Vec<u16> = entries
        .iter()
        .flat_map(|entry| entry.encode_utf16().chain(std::iter::once(0)))
        .collect();
    block.push(0);
    block
}

/// Start `command_line` inside `environment` with stdout and stderr piped
/// back to the caller. The environment is only borrowed: closing it stays
/// with the caller.
fn start(
    environment: HANDLE,
    command_line: &str,
    environment_variables: Option<&[u16]>,
) -> Result<Child, String> {
    let (output, write) = create_output_pipe()?;
    let write_handle = HANDLE(write.as_raw_handle());

    // SAFETY: a zeroed STARTUPINFOW with the fields set below is valid.
    let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup_info.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>())
        .map_err(|_| "STARTUPINFOW size".to_string())?;
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdOutput = write_handle;
    startup_info.hStdError = write_handle;
    let extended = SecurityEnvironmentStartupInfo::new(startup_info, environment, &[write_handle])
        .map_err(|error| error.to_string())?;

    let mut command: Vec<u16> = command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut flags = EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_NO_WINDOW.0;
    if environment_variables.is_some() {
        flags |= CREATE_UNICODE_ENVIRONMENT.0;
    }
    // SAFETY: a zeroed PROCESS_INFORMATION is a valid output buffer.
    let mut process_information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // SAFETY: `command` is mutable and null-terminated, `extended` owns a
    // valid attribute list for a live environment, and the optional
    // environment block is double-null terminated and outlives the call.
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            true,
            PROCESS_CREATION_FLAGS(flags),
            environment_variables.map(|block| block.as_ptr().cast::<c_void>()),
            PCWSTR::null(),
            &extended.startup_info().StartupInfo,
            &mut process_information,
        )
    }
    .map_err(|error| format!("CreateProcessW failed: {error}"))?;

    // SAFETY: both handles came from the successful launch; the thread
    // handle is unused and the process handle moves into `Child`.
    let process = unsafe {
        let _ = CloseHandle(process_information.hThread);
        OwnedHandle::from_raw_handle(process_information.hProcess.0)
    };
    // The child holds its own copy; closing ours lets reads see end of file.
    drop(write);
    Ok(Child {
        process,
        output,
        started: Instant::now(),
    })
}

fn run(environment: HANDLE, script: &str) -> Report {
    start(environment, &powershell(script), None)
        .expect("launch inside the environment")
        .collect()
}

fn powershell(script: &str) -> String {
    assert!(
        !script.contains('"'),
        "script must not contain double quotes"
    );
    let root = std::env::var("SystemRoot").expect("SystemRoot is set on Windows");
    format!(
        "\"{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile \
         -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\""
    )
}

// ---------------------------------------------------------------------------
// Child scripts
// ---------------------------------------------------------------------------

/// Prints the child's view of its temp directory and identity.
const REPORT: &str = "$t=[IO.Path]::GetTempPath(); 'TEMP='+$env:TEMP; 'TMP='+$env:TMP; \
    'LOCALAPPDATA='+$env:LOCALAPPDATA; 'USERPROFILE='+$env:USERPROFILE; 'GETTEMPPATH='+$t; \
    'USERNAME='+[Environment]::UserName; 'SYSTEMROOT='+$env:SystemRoot;";

fn write_marker(token: &str) -> String {
    format!(
        "{REPORT} $m=Join-Path $t '{MARKER_FILE}'; try {{ Set-Content -LiteralPath $m -Value \
         '{token}'; 'WROTE=True' }} catch {{ 'WROTE=False:'+$_.Exception.GetType().Name }};"
    )
}

fn read_marker() -> String {
    format!(
        "{REPORT} $m=Join-Path $t '{MARKER_FILE}'; if (Test-Path -LiteralPath $m) {{ \
         'MARKER='+(Get-Content -LiteralPath $m -Raw).Trim() }} else {{ 'MARKER=MISSING' }};"
    )
}

/// Writes this child's marker, then waits for the peer's marker to appear in
/// the same temp directory. A launch that was serialized behind its peer
/// would time out here.
fn rendezvous(id: &str, peer: &str) -> String {
    format!(
        "{REPORT} $m=Join-Path $t 'mxc-psec-concurrent-{id}.txt'; $p=Join-Path $t \
         'mxc-psec-concurrent-{peer}.txt'; Set-Content -LiteralPath $m -Value '{id}'; \
         $end=(Get-Date).AddSeconds(45); while (-not (Test-Path -LiteralPath $p) -and \
         (Get-Date) -lt $end) {{ Start-Sleep -Milliseconds 200 }}; 'PEER='+(Test-Path \
         -LiteralPath $p);"
    )
}

fn sleep_after_report() -> String {
    format!("{REPORT} Start-Sleep -Seconds 120;")
}

fn unique_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

// ---------------------------------------------------------------------------
// Host-side observation of container profiles
// ---------------------------------------------------------------------------

fn packages_directory() -> PathBuf {
    PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set")).join("Packages")
}

/// Names of the generated `sandbox.*` profile directories on the host.
fn sandbox_profiles() -> BTreeSet<String> {
    std::fs::read_dir(packages_directory())
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.starts_with("sandbox."))
                .collect()
        })
        .unwrap_or_default()
}

/// The `Packages\sandbox.*` directory that contains `temp`.
fn profile_root(temp: &str) -> PathBuf {
    Path::new(temp)
        .ancestors()
        .find(|ancestor| {
            ancestor
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("sandbox."))
        })
        .unwrap_or_else(|| panic!("TEMP {temp} is not under a sandbox.* profile"))
        .to_path_buf()
}

/// How long the path takes to disappear. The polling exists only to tell
/// synchronous cleanup apart from delayed cleanup and from a leak.
fn removal_delay(path: &Path) -> Option<Duration> {
    let started = Instant::now();
    loop {
        if !path.exists() {
            return Some(started.elapsed());
        }
        if started.elapsed() >= PROFILE_REMOVAL_LIMIT {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn observe_removal(label: &str, profile: &Path) -> Option<Duration> {
    observe(&format!("{label}_profile"), profile.display());
    let delay = removal_delay(profile);
    let key = format!("{label}_profile_removed_after_ms");
    match delay {
        Some(delay) => observe(&key, delay.as_millis()),
        None => observe(&key, "NEVER"),
    }
    delay
}

fn icacls(path: &Path) -> String {
    let output = Command::new("icacls")
        .arg(path)
        .output()
        .expect("run icacls");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Number of access entries naming an AppContainer package SID.
fn package_sid_entries(icacls_output: &str) -> usize {
    icacls_output.matches("S-1-15-2-").count()
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// One handle, launches one after another. Launch A writes through the
/// container `TEMP`; launch B, started after A exited and before the handle
/// closed, looks for the file.
#[test]
#[ignore = "requires a PSEC-capable Windows host"]
fn psec_handle_serves_sequential_launches() {
    let api = load_api();
    let scratch = tempfile::tempdir().expect("scratch directory");
    let profiles_before = sandbox_profiles();
    let acl_before = icacls(scratch.path());

    let mut spec = build_spec(&[scratch.path()]);
    let environment = api
        .create(&spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("CreateProcessSecurityEnvironment");
    // The API receives a pointer and a size. Clearing the buffer shows that
    // later launches use the policy captured at creation.
    spec.fill(0);
    let acl_open = icacls(scratch.path());
    observe(
        "profiles_created_by_create",
        sandbox_profiles().difference(&profiles_before).count(),
    );
    observe(
        "scratch_package_sid_entries_before_create",
        package_sid_entries(&acl_before),
    );
    observe(
        "scratch_package_sid_entries_while_open",
        package_sid_entries(&acl_open),
    );

    let token = unique_token();
    let a = run(environment.raw(), &write_marker(&token));
    observe("a_exit", a.exit_code);
    observe("a_output", one_line(&a.output));
    let temp = a.required("TEMP").to_owned();
    let profile = profile_root(&temp);
    observe("a_temp", &temp);
    observe("a_tmp", a.required("TMP"));
    observe("a_get_temp_path", a.required("GETTEMPPATH"));
    observe("a_localappdata", a.required("LOCALAPPDATA"));
    observe("a_wrote", a.required("WROTE"));
    observe(
        "profiles_created_after_first_launch",
        sandbox_profiles().difference(&profiles_before).count(),
    );

    let b = run(environment.raw(), &read_marker());
    observe("b_exit", b.exit_code);
    observe("b_temp", b.required("TEMP"));
    observe("b_get_temp_path", b.required("GETTEMPPATH"));
    observe("b_marker_matches_a", b.required("MARKER") == token);
    observe("b_marker", b.required("MARKER"));

    // Per-launch environment: an explicit TEMP/TMP reaches the child. This is
    // the shape of a host-side TEMP/TMP restoration, and it is separate from
    // the container's own TEMP observed above.
    let scratch_text = scratch.path().to_string_lossy().into_owned();
    let explicit = environment_block(&[
        ("SystemRoot", a.required("SYSTEMROOT")),
        ("LOCALAPPDATA", a.required("LOCALAPPDATA")),
        ("TEMP", &scratch_text),
        ("TMP", &scratch_text),
    ]);
    let c = start(
        environment.raw(),
        &powershell(&write_marker("explicit-env")),
        Some(&explicit),
    )
    .expect("launch with an explicit environment block")
    .collect();
    observe("c_exit", c.exit_code);
    observe("c_output", one_line(&c.output));
    let scratch_marker = scratch.path().join(MARKER_FILE);
    observe("c_marker_in_scratch_on_host", scratch_marker.exists());

    let acl_after_launches = icacls(scratch.path());
    let close_started = Instant::now();
    environment.close();
    observe("close_ms", close_started.elapsed().as_millis());
    let removal = observe_removal("sequential", &profile);
    let acl_after_close = icacls(scratch.path());
    observe(
        "scratch_package_sid_entries_after_close",
        package_sid_entries(&acl_after_close),
    );
    observe("scratch_acl_while_open", one_line(&acl_after_launches));
    observe("scratch_acl_after_close", one_line(&acl_after_close));

    assert_eq!(a.exit_code, 0, "launch A failed:\n{}", a.output);
    assert_eq!(b.exit_code, 0, "launch B failed:\n{}", b.output);
    assert_eq!(c.exit_code, 0, "launch C failed:\n{}", c.output);
    assert_eq!(a.required("WROTE"), "True", "A could not write to its TEMP");
    assert_eq!(
        b.required("TEMP"),
        temp,
        "launches that share one handle must share one container TEMP"
    );
    assert_eq!(
        b.required("MARKER"),
        token,
        "launch B must see the file launch A wrote through the container TEMP"
    );
    assert!(
        scratch_marker.exists(),
        "an explicit TEMP/TMP must reach a launch in a reused environment"
    );
    assert!(
        removal.is_some(),
        "profile {} was still present {PROFILE_REMOVAL_LIMIT:?} after close",
        profile.display()
    );
    assert!(
        package_sid_entries(&acl_after_close) <= package_sid_entries(&acl_before),
        "brokered ACL entries remain on the scratch directory after close:\n{acl_after_close}"
    );
}

/// Two launches started at the same instant against one handle. Each waits
/// inside the container for the other's marker, so the test only passes when
/// both run at the same time and share the container `TEMP`.
#[test]
#[ignore = "requires a PSEC-capable Windows host"]
fn psec_handle_serves_concurrent_launches() {
    let api = load_api();
    let spec = build_spec(&[]);
    let environment = api
        .create(&spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("CreateProcessSecurityEnvironment");
    // The raw handle value crosses threads; the owner stays on this thread.
    let raw = environment.raw().0 as usize;
    let token = unique_token();
    let id_a = format!("a-{token}");
    let id_b = format!("b-{token}");
    let barrier = Barrier::new(2);

    let (child_a, child_b) = thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            start(
                HANDLE(raw as *mut c_void),
                &powershell(&rendezvous(&id_a, &id_b)),
                None,
            )
        });
        let second = scope.spawn(|| {
            barrier.wait();
            start(
                HANDLE(raw as *mut c_void),
                &powershell(&rendezvous(&id_b, &id_a)),
                None,
            )
        });
        (
            first.join().expect("first launch thread"),
            second.join().expect("second launch thread"),
        )
    });
    let a = child_a.expect("concurrent launch A").collect();
    let b = child_b.expect("concurrent launch B").collect();
    observe("concurrent_a_exit", a.exit_code);
    observe("concurrent_b_exit", b.exit_code);
    observe("concurrent_a_temp", a.required("TEMP"));
    observe("concurrent_b_temp", b.required("TEMP"));
    observe("concurrent_a_saw_peer", a.required("PEER"));
    observe("concurrent_b_saw_peer", b.required("PEER"));
    let profile = profile_root(a.required("TEMP"));

    // A second handle with a different policy is a different container.
    let scratch = tempfile::tempdir().expect("scratch directory");
    let other_spec = build_spec(&[scratch.path()]);
    let other = api
        .create(&other_spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("second CreateProcessSecurityEnvironment");
    let other_report = run(other.raw(), REPORT);
    observe("other_handle_temp", other_report.required("TEMP"));
    let other_profile = profile_root(other_report.required("TEMP"));
    observe(
        "other_handle_has_distinct_profile",
        other_profile != profile,
    );
    other.close();
    let other_removal = observe_removal("other_handle", &other_profile);

    environment.close();
    let removal = observe_removal("concurrent", &profile);

    assert_eq!(a.exit_code, 0, "concurrent launch A failed:\n{}", a.output);
    assert_eq!(b.exit_code, 0, "concurrent launch B failed:\n{}", b.output);
    assert_eq!(a.required("PEER"), "True", "A never saw B's marker");
    assert_eq!(b.required("PEER"), "True", "B never saw A's marker");
    assert_eq!(
        a.required("TEMP"),
        b.required("TEMP"),
        "concurrent launches on one handle must share one container TEMP"
    );
    assert_ne!(
        other_profile, profile,
        "handles created from different policies must not share a profile"
    );
    assert!(
        other_removal.is_some(),
        "second handle's profile was not removed"
    );
    assert!(
        removal.is_some(),
        "concurrent handle's profile was not removed"
    );
}

/// `ProcessSecurityEnvironment` is not `Send` because it wraps a raw handle.
/// The close scenario moves exactly one owner into one closing thread.
struct Closer(ProcessSecurityEnvironment);

// SAFETY: the handle has a single owner and is used by one thread at a time.
unsafe impl Send for Closer {}

impl Closer {
    fn close(self) {
        self.0.close();
    }
}

/// Close while a child is still running, then close after the child was
/// terminated. The host terminates only children the test started.
#[test]
#[ignore = "requires a PSEC-capable Windows host"]
fn psec_handle_close_with_running_and_terminated_children() {
    let api = load_api();
    let spec = build_spec(&[]);

    // Close while the child runs.
    let environment = api
        .create(&spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("CreateProcessSecurityEnvironment");
    let probe = run(environment.raw(), REPORT);
    let profile = profile_root(probe.required("TEMP"));
    let sleeper = start(environment.raw(), &powershell(&sleep_after_report()), None)
        .expect("launch long-running child");
    assert!(
        sleeper.wait(Duration::from_millis(500)).is_none(),
        "the long-running child must still run before close"
    );
    let (sender, receiver) = mpsc::channel();
    let closer = Closer(environment);
    let close_thread = thread::spawn(move || {
        let started = Instant::now();
        closer.close();
        let _ = sender.send(started.elapsed());
    });
    let close_returned = match receiver.recv_timeout(Duration::from_secs(15)) {
        Ok(elapsed) => {
            observe("running_child_close_returned_ms", elapsed.as_millis());
            true
        }
        Err(_) => {
            observe("running_child_close_returned_ms", "BLOCKED_15000+");
            sleeper.terminate();
            false
        }
    };
    let child_exit_after_close = sleeper.wait(Duration::from_secs(10));
    match child_exit_after_close {
        Some(code) => observe("running_child_exit_after_close", code),
        None => {
            observe("running_child_exit_after_close", "STILL_RUNNING");
            sleeper.terminate();
        }
    }
    if !close_returned {
        receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("close must return once the child is gone");
    }
    close_thread.join().expect("closing thread");
    let running_removal = observe_removal("running_child", &profile);
    let _ = sleeper.wait(Duration::from_secs(10));

    // Terminate the child, then close.
    let environment = api
        .create(&spec, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("CreateProcessSecurityEnvironment");
    let probe = run(environment.raw(), REPORT);
    let profile = profile_root(probe.required("TEMP"));
    let sleeper = start(environment.raw(), &powershell(&sleep_after_report()), None)
        .expect("launch long-running child");
    assert!(sleeper.wait(Duration::from_millis(500)).is_none());
    sleeper.terminate();
    let terminated_exit = sleeper.wait(Duration::from_secs(10));
    observe("terminated_child_exit", format!("{terminated_exit:?}"));
    let close_started = Instant::now();
    environment.close();
    observe(
        "terminated_child_close_ms",
        close_started.elapsed().as_millis(),
    );
    let terminated_removal = observe_removal("terminated_child", &profile);

    assert!(
        child_exit_after_close.is_some(),
        "the long-running child outlived the environment close"
    );
    assert!(
        running_removal.is_some(),
        "profile was not removed after closing with a running child"
    );
    assert!(terminated_exit.is_some(), "terminated child did not exit");
    assert!(
        terminated_removal.is_some(),
        "profile was not removed after closing with a terminated child"
    );
}

/// Failures must not leave profiles behind or poison a healthy handle.
#[test]
#[ignore = "requires a PSEC-capable Windows host"]
fn psec_failures_leave_no_profile_and_do_not_poison_the_handle() {
    let api = load_api();
    let valid = build_spec(&[]);
    let profiles_before = sandbox_profiles();

    let garbage = api.create(
        b"not a process security environment",
        PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
    );
    observe(
        "garbage_spec_result",
        format!("{:?}", garbage.as_ref().err()),
    );
    let truncated = api.create(
        &valid[..valid.len() / 2],
        PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
    );
    observe(
        "truncated_spec_result",
        format!("{:?}", truncated.as_ref().err()),
    );
    let unsupported = api.create(
        &build_spec_version(99, &[]),
        PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
    );
    observe(
        "unsupported_version_result",
        format!("{:?}", unsupported.as_ref().err()),
    );
    let created_by_failures: Vec<String> = sandbox_profiles()
        .difference(&profiles_before)
        .cloned()
        .collect();
    observe(
        "profiles_created_by_failed_create",
        created_by_failures.len(),
    );

    // A launch that fails inside a healthy environment.
    let environment = api
        .create(&valid, PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE)
        .expect("CreateProcessSecurityEnvironment");
    let missing = start(
        environment.raw(),
        "C:\\mxc-psec-lifetime-missing\\no-such-program.exe",
        None,
    );
    observe(
        "missing_program_result",
        format!("{:?}", missing.as_ref().err()),
    );
    let after_failure = run(environment.raw(), REPORT);
    observe("launch_after_failed_launch_exit", after_failure.exit_code);
    let profile = profile_root(after_failure.required("TEMP"));
    environment.close();
    let removal = observe_removal("after_failed_launch", &profile);

    assert!(garbage.is_err(), "a garbage specification must be rejected");
    assert!(
        truncated.is_err(),
        "a truncated specification must be rejected"
    );
    assert!(
        unsupported.is_err(),
        "an unsupported schema version must be rejected"
    );
    assert!(
        created_by_failures.is_empty(),
        "failed creation left profiles behind: {created_by_failures:?}"
    );
    assert!(missing.is_err(), "a missing program must fail to launch");
    assert_eq!(
        after_failure.exit_code, 0,
        "the handle must still launch after a failed launch:\n{}",
        after_failure.output
    );
    assert!(removal.is_some(), "profile was not removed after close");
}
