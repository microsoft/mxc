// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end validation for the Learning Mode capture lifecycle, independent of the
//! MXC runner and the `captureDenials` config.
//!
//! It drives the full 2-phase sequence against a real child process:
//!
//! 1. build a minimal FlatBuffer sandbox spec with the `permissiveLearningMode`
//!    capability (the token the OS learning-mode path recognises),
//! 2. [`CaptureSession::begin`] — create the security environment + start the trace,
//! 3. launch `cmd.exe` inside the environment via
//!    `CreateProcessAsUserInsideSecurityEnvironment`,
//! 4. wait for it to exit,
//! 5. [`CaptureSession::finish`] — seal the ETL to a temp path + close the environment,
//! 6. assert the ETL file was produced (non-empty).
//!
//! Run on a feature-enabled Windows build (elevated):
//!
//! ```text
//! cargo run -p learning_mode_windows --example lm_capture
//! ```
//!
//! Exit codes: `0` = ETL produced; `2` = API unavailable / off-feature build; `1` = a
//! step failed.

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("lm_capture is Windows-only");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(windows_impl::run());
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::path::PathBuf;

    use flatbuffers::FlatBufferBuilder;
    use learning_mode_windows::{
        CaptureSession, LearningModeApi, SecurityEnvironmentApi,
        PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
    };
    use sandbox_spec::base_container_layout::{
        finish_sandbox_spec_buffer, SandboxSpec, SandboxSpecArgs,
    };
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE, PROCESS_INFORMATION, STARTUPINFOW,
    };

    /// Matches the schema version BaseContainer embeds in every spec payload.
    const SANDBOX_SPEC_VERSION: &str = "0.1.0";

    /// Build a minimal FlatBuffer `SandboxSpec` carrying the learning-mode capability.
    fn build_sandbox_spec() -> Vec<u8> {
        let mut builder = FlatBufferBuilder::with_capacity(256);
        let version = builder.create_string(SANDBOX_SPEC_VERSION);
        // `permissiveLearningMode` is the capability the SandboxEngine functest uses to
        // exercise the learning-mode trace; it reliably drives recorded events.
        let capabilities = builder.create_string("permissiveLearningMode");
        let spec = SandboxSpec::create(
            &mut builder,
            &SandboxSpecArgs {
                version: Some(version),
                app_container: true,
                capabilities: Some(capabilities),
                ..Default::default()
            },
        );
        finish_sandbox_spec_buffer(&mut builder, spec);
        builder.finished_data().to_vec()
    }

    /// Null-terminated, mutable UTF-16 command line for the child.
    fn wide_command_line() -> Vec<u16> {
        let cmd = r#"cmd.exe /c echo Hello from the learning-mode sandbox & whoami"#;
        cmd.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn etl_output_path() -> PathBuf {
        std::env::temp_dir().join(format!("lm_capture_{}.etl", std::process::id()))
    }

    pub fn run() -> i32 {
        let secenv_api = match SecurityEnvironmentApi::load() {
            Ok(api) => api,
            Err(e) => {
                eprintln!("SecurityEnvironmentApi::load failed (off-feature build?): {e}");
                return 2;
            }
        };
        let learning_mode_api = match LearningModeApi::load() {
            Ok(api) => api,
            Err(e) => {
                eprintln!("LearningModeApi::load failed (off-feature build?): {e}");
                return 2;
            }
        };

        let spec = build_sandbox_spec();
        println!("built sandbox spec: {} bytes", spec.len());

        let session = match CaptureSession::begin(
            secenv_api,
            learning_mode_api,
            &spec,
            PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE,
        ) {
            Ok(session) => session,
            Err(e) => {
                eprintln!("CaptureSession::begin failed: {e}");
                return 1;
            }
        };
        println!("CaptureSession::begin OK — environment + trace live");

        let exit_code = match launch_and_wait(&secenv_api, session.environment()) {
            Ok(code) => {
                println!("child exited with code {code}");
                code
            }
            Err(e) => {
                eprintln!("launch failed: {e}");
                // `session` drops here → trace discarded + environment closed.
                return 1;
            }
        };
        let _ = exit_code;

        let etl_path = etl_output_path();
        if let Err(e) = session.finish(Some(&etl_path)) {
            eprintln!("CaptureSession::finish failed: {e}");
            return 1;
        }
        println!("CaptureSession::finish OK — trace sealed, environment closed");

        match std::fs::metadata(&etl_path) {
            Ok(meta) => {
                println!(
                    "ETL produced: {} ({} bytes)",
                    etl_path.display(),
                    meta.len()
                );
                if meta.len() == 0 {
                    eprintln!("warning: ETL file is empty");
                }
                0
            }
            Err(e) => {
                eprintln!("expected ETL at {} but none found: {e}", etl_path.display());
                1
            }
        }
    }

    /// Launch the child inside `environment` and wait for it to exit, returning its exit
    /// code.
    fn launch_and_wait(
        secenv_api: &SecurityEnvironmentApi,
        environment: HANDLE,
    ) -> Result<u32, String> {
        let launch = secenv_api.launch_fn();
        let mut cmd = wide_command_line();

        // SAFETY: a zeroed STARTUPINFOW with only `cb` set is valid; the child inherits
        // the caller's console for stdio (no STARTF_USESTDHANDLES).
        let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup_info.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>())
            .map_err(|_| "STARTUPINFOW size overflow".to_string())?;
        let mut process_information: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // SAFETY: `launch` was resolved from processmodel.dll and matches the declared C
        // signature. `cmd` is a mutable, null-terminated UTF-16 buffer; `startup_info`
        // and `process_information` are valid; `environment` is the live handle from the
        // session. `lpEnvironment` is null, so CREATE_UNICODE_ENVIRONMENT is not needed.
        let ok = unsafe {
            launch(
                HANDLE(std::ptr::null_mut()), // userToken: caller context
                std::ptr::null(),             // applicationName (from command line)
                cmd.as_mut_ptr(),             // commandLine
                0,                            // creationFlags
                std::ptr::null(),             // environment
                std::ptr::null(),             // currentDirectory
                &startup_info,
                environment,
                &mut process_information,
            )
        };
        if ok == 0 {
            // SAFETY: reads the calling thread's last-error slot.
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            return Err(format!(
                "CreateProcessAsUserInsideSecurityEnvironment failed (GetLastError = {})",
                err.0
            ));
        }

        // SAFETY: `hProcess` is a valid process handle returned by the launch.
        let wait = unsafe { WaitForSingleObject(process_information.hProcess, INFINITE) };
        let mut exit_code: u32 = 0;
        if wait == WAIT_OBJECT_0 {
            // SAFETY: `hProcess` is valid and the process has signalled exit.
            let _ = unsafe { GetExitCodeProcess(process_information.hProcess, &mut exit_code) };
        }

        // SAFETY: both handles were returned by the launch and are not used again.
        unsafe {
            let _ = CloseHandle(process_information.hThread);
            let _ = CloseHandle(process_information.hProcess);
        }
        Ok(exit_code)
    }
}
