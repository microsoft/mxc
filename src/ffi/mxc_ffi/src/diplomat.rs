// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Experimental Diplomat surface over the safe [`mxc_sdk`] API.
//!
//! This is deliberately separate from the legacy `mxc_*` ABI in `lib.rs` so
//! generated clients can be evaluated without changing the co-versioned C#
//! SDK. It has one-shot, streaming, and state-aware APIs; every operation
//! delegates to the safe `mxc_sdk` facade.

#[diplomat::bridge]
pub mod ffi {
    use std::fmt::{self, Write};
    use std::io::{Read, Write as IoWrite};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Mutex, MutexGuard, TryLockError};

    use diplomat_runtime::DiplomatWrite;
    use mxc_sdk::{
        available_backends, exec_attached, exec_sandbox, platform_support, run,
        run_state_aware_json, spawn_sandbox, Error, ErrorCode, Output, Sandbox, WaitOutcome,
    };

    /// Entry point for the generated MXC bindings.
    ///
    /// Methods are static because this object has no per-client state. The
    /// generated bindings still own its opaque handle and dispose it normally.
    #[derive(Debug)]
    #[diplomat::attr(dotnet, manually_disposable)]
    #[diplomat::opaque]
    pub struct MxcDiplomat;

    /// An owned MXC version value.
    #[derive(Debug)]
    #[diplomat::attr(dotnet, manually_disposable)]
    #[diplomat::opaque]
    pub struct MxcDiplomatVersion {
        value: String,
    }

    /// An owned host-discovery snapshot.
    #[derive(Debug)]
    #[diplomat::attr(dotnet, manually_disposable)]
    #[diplomat::opaque]
    pub struct MxcDiplomatDiscovery {
        available_backends_json: String,
        platform_support_json: String,
    }

    /// Captured result from a completed sandbox run.
    #[derive(Debug)]
    #[diplomat::attr(dotnet, manually_disposable)]
    #[diplomat::opaque]
    pub struct MxcDiplomatRunResult {
        exit_code: i32,
        timed_out: bool,
        stdout: String,
        stderr: String,
        output_metadata_json: String,
        has_output_metadata: bool,
        warnings_json: String,
    }

    /// A non-blocking completion snapshot for a live sandbox.
    #[derive(Debug)]
    pub struct MxcDiplomatPollResult {
        /// Whether the sandbox process remains active.
        pub is_running: bool,
        /// Whether the process was terminated after its configured timeout.
        pub timed_out: bool,
        /// The process exit code, or `-1` after timeout. Undefined while running.
        pub exit_code: i32,
    }

    /// A terminal completion result for a live or attached sandbox process.
    #[derive(Debug)]
    pub struct MxcDiplomatWaitResult {
        /// Whether MXC terminated the process after its configured timeout.
        pub timed_out: bool,
        /// The process exit code, or `-1` after timeout.
        pub exit_code: i32,
    }

    /// An owned state-aware response envelope.
    #[derive(Debug)]
    #[diplomat::attr(dotnet, manually_disposable)]
    #[diplomat::opaque]
    pub struct MxcDiplomatStateAwareEnvelope {
        response_json: String,
    }

    /// A synchronized live sandbox handle.
    ///
    /// Each `take_*` operation consumes the matching SDK stream exactly once.
    /// The mutex prevents concurrent managed calls from creating aliased
    /// mutable access to the underlying SDK handle.
    #[diplomat::opaque_mut]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct MxcDiplomatSandbox {
        inner: Mutex<Sandbox>,
    }

    /// A synchronized, owned stdin handle. Dropping it closes stdin.
    #[diplomat::opaque_mut]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct MxcDiplomatInputStream {
        inner: Mutex<Box<dyn IoWrite + Send>>,
    }

    /// A synchronized, owned stdout or stderr handle.
    #[diplomat::opaque_mut]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct MxcDiplomatOutputStream {
        inner: Mutex<Box<dyn Read + Send>>,
    }

    /// The stable error category returned by the Diplomat prototype.
    #[derive(Debug, PartialEq, Eq)]
    pub enum MxcDiplomatErrorCode {
        MalformedRequest,
        UnsupportedContainment,
        UnsupportedPhase,
        BackendUnavailable,
        MalformedId,
        StaleId,
        NotProvisioned,
        NotStarted,
        AlreadyStarted,
        AlreadyStopped,
        PolicyValidation,
        BackendError,
        Panic,
    }

    /// A failure from parsing or executing a binding request.
    #[derive(Debug)]
    #[diplomat::attr(dotnet, manually_disposable)]
    #[diplomat::opaque]
    pub struct MxcDiplomatError {
        code: MxcDiplomatErrorCode,
        message: String,
        operation: String,
        has_operation: bool,
        native_code: String,
        has_native_code: bool,
        remediation: String,
        has_remediation: bool,
    }

    impl MxcDiplomat {
        /// Return the version of the loaded native MXC library.
        pub fn version() -> Result<Box<MxcDiplomatVersion>, Box<MxcDiplomatError>> {
            protect(|| {
                Ok(Box::new(MxcDiplomatVersion {
                    value: env!("CARGO_PKG_VERSION").to_string(),
                }))
            })
        }

        /// Snapshot the host's available backends and the safe SDK's support.
        ///
        /// The JSON payloads preserve the existing discovery contract used by
        /// the hand-written ABI while Diplomat owns their string memory.
        pub fn discover() -> Result<Box<MxcDiplomatDiscovery>, Box<MxcDiplomatError>> {
            protect(|| {
                let available_backends_json =
                    serde_json::to_string(&available_backends()).map_err(serialization_error)?;
                let platform_support_json =
                    serde_json::to_string(&platform_support()).map_err(serialization_error)?;
                Ok(Box::new(MxcDiplomatDiscovery {
                    available_backends_json,
                    platform_support_json,
                }))
            })
        }

        /// Run a complete existing binding request to completion.
        ///
        /// `request_json` has exactly the same schema as `mxc_run_request`.
        /// The safe Rust SDK constructs and executes the request; this bridge
        /// only turns its values into generated opaque binding objects.
        pub fn run(request_json: &str) -> Result<Box<MxcDiplomatRunResult>, Box<MxcDiplomatError>> {
            protect(|| {
                let request = crate::request::build_request_from_json(request_json)
                    .map_err(error_from_sdk)?;
                let output = run(request).map_err(error_from_sdk)?;
                MxcDiplomatRunResult::from_output(output).map(Box::new)
            })
        }

        /// Spawn a complete existing binding request with piped stdio.
        ///
        /// The returned sandbox owns its process and can hand each standard
        /// stream out at most once.
        pub fn spawn(request_json: &str) -> Result<Box<MxcDiplomatSandbox>, Box<MxcDiplomatError>> {
            protect(|| {
                let request = crate::request::build_request_from_json(request_json)
                    .map_err(error_from_sdk)?;
                spawn_sandbox(request)
                    .map(MxcDiplomatSandbox::new)
                    .map(Box::new)
                    .map_err(error_from_sdk)
            })
        }

        /// Run a `provision` state-aware envelope request.
        pub fn provision(
            request_json: &str,
            dry_run: bool,
            experimental: bool,
        ) -> Result<Box<MxcDiplomatStateAwareEnvelope>, Box<MxcDiplomatError>> {
            state_aware_envelope("provision", request_json, dry_run, experimental)
        }

        /// Run a `start` state-aware envelope request.
        pub fn start(
            request_json: &str,
            dry_run: bool,
            experimental: bool,
        ) -> Result<Box<MxcDiplomatStateAwareEnvelope>, Box<MxcDiplomatError>> {
            state_aware_envelope("start", request_json, dry_run, experimental)
        }

        /// Run a `stop` state-aware envelope request.
        pub fn stop(
            request_json: &str,
            dry_run: bool,
            experimental: bool,
        ) -> Result<Box<MxcDiplomatStateAwareEnvelope>, Box<MxcDiplomatError>> {
            state_aware_envelope("stop", request_json, dry_run, experimental)
        }

        /// Run a `deprovision` state-aware envelope request.
        pub fn deprovision(
            request_json: &str,
            dry_run: bool,
            experimental: bool,
        ) -> Result<Box<MxcDiplomatStateAwareEnvelope>, Box<MxcDiplomatError>> {
            state_aware_envelope("deprovision", request_json, dry_run, experimental)
        }

        /// Run a state-aware `exec` request with live piped stdio.
        pub fn exec(
            request_json: &str,
            experimental: bool,
        ) -> Result<Box<MxcDiplomatSandbox>, Box<MxcDiplomatError>> {
            protect(|| {
                exec_sandbox(request_json, experimental)
                    .map(MxcDiplomatSandbox::new)
                    .map(Box::new)
                    .map_err(error_from_sdk)
            })
        }

        /// Run a state-aware `exec` request attached to this process's stdio.
        ///
        /// The host must expose terminal stdin and stdout. Diplomat only
        /// transports the request and typed terminal outcome; it does not proxy
        /// interactive streams.
        pub fn exec_attached(
            request_json: &str,
            experimental: bool,
        ) -> Result<MxcDiplomatWaitResult, Box<MxcDiplomatError>> {
            protect(|| {
                exec_attached(request_json, experimental)
                    .map(MxcDiplomatWaitResult::from_outcome)
                    .map_err(error_from_sdk)
            })
        }
    }

    impl MxcDiplomatVersion {
        /// Return the version as a managed string.
        pub fn value(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.value)
        }
    }

    impl MxcDiplomatDiscovery {
        /// Return the existing `AvailableBackend[]` JSON payload.
        pub fn available_backends_json(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.available_backends_json)
        }

        /// Return the existing `PlatformSupport` JSON payload.
        pub fn platform_support_json(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.platform_support_json)
        }
    }

    impl MxcDiplomatRunResult {
        fn from_output(output: Output) -> Result<Self, Box<MxcDiplomatError>> {
            let (exit_code, timed_out) = match output.outcome {
                WaitOutcome::Exited(code) => (code, false),
                WaitOutcome::TimedOut => (-1, true),
            };
            let output_metadata_json = output
                .output_metadata
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(serialization_error)?;
            let warnings_json =
                serde_json::to_string(&output.warnings).map_err(serialization_error)?;

            Ok(Self {
                exit_code,
                timed_out,
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                has_output_metadata: output_metadata_json.is_some(),
                output_metadata_json: output_metadata_json.unwrap_or_default(),
                warnings_json,
            })
        }

        /// Return the process exit code, or `-1` when `timed_out` is true.
        pub fn exit_code(&self) -> i32 {
            self.exit_code
        }

        /// Return whether MXC terminated the run after its configured timeout.
        pub fn timed_out(&self) -> bool {
            self.timed_out
        }

        /// Return captured standard output, decoded as UTF-8 with replacement.
        pub fn stdout(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.stdout)
        }

        /// Return captured standard error, decoded as UTF-8 with replacement.
        pub fn stderr(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.stderr)
        }

        /// Return whether an output-metadata payload is available.
        pub fn has_output_metadata(&self) -> bool {
            self.has_output_metadata
        }

        /// Return output metadata JSON, or an empty string when absent.
        pub fn output_metadata_json(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.output_metadata_json)
        }

        /// Return the captured policy warnings as a JSON array.
        pub fn warnings_json(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.warnings_json)
        }
    }

    impl MxcDiplomatStateAwareEnvelope {
        /// Return the SDK response envelope as JSON.
        pub fn response_json(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.response_json)
        }
    }

    impl fmt::Debug for MxcDiplomatSandbox {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MxcDiplomatSandbox(..)")
        }
    }

    impl MxcDiplomatSandbox {
        fn new(inner: Sandbox) -> Self {
            Self {
                inner: Mutex::new(inner),
            }
        }

        fn try_lock(&self) -> Result<MutexGuard<'_, Sandbox>, Box<MxcDiplomatError>> {
            match self.inner.try_lock() {
                Ok(sandbox) => Ok(sandbox),
                Err(TryLockError::WouldBlock) => Err(busy_lock_error("sandbox handle")),
                Err(TryLockError::Poisoned(_)) => Err(poisoned_lock_error("sandbox handle")),
            }
        }

        /// Take the stdin handle, returning `None` if it is unavailable or was
        /// already taken.
        pub fn take_stdin(
            &self,
        ) -> Result<Option<Box<MxcDiplomatInputStream>>, Box<MxcDiplomatError>> {
            protect(|| {
                let mut sandbox = self.try_lock()?;
                Ok(sandbox.take_stdin().map(|inner| {
                    Box::new(MxcDiplomatInputStream {
                        inner: Mutex::new(inner),
                    })
                }))
            })
        }

        /// Take the stdout handle, returning `None` if it is unavailable or was
        /// already taken.
        pub fn take_stdout(
            &self,
        ) -> Result<Option<Box<MxcDiplomatOutputStream>>, Box<MxcDiplomatError>> {
            protect(|| {
                let mut sandbox = self.try_lock()?;
                Ok(sandbox.take_stdout().map(|inner| {
                    Box::new(MxcDiplomatOutputStream {
                        inner: Mutex::new(inner),
                    })
                }))
            })
        }

        /// Take the stderr handle, returning `None` if it is unavailable or was
        /// already taken.
        pub fn take_stderr(
            &self,
        ) -> Result<Option<Box<MxcDiplomatOutputStream>>, Box<MxcDiplomatError>> {
            protect(|| {
                let mut sandbox = self.try_lock()?;
                Ok(sandbox.take_stderr().map(|inner| {
                    Box::new(MxcDiplomatOutputStream {
                        inner: Mutex::new(inner),
                    })
                }))
            })
        }

        /// Return a non-blocking snapshot of the sandbox process.
        pub fn try_wait(&self) -> Result<MxcDiplomatPollResult, Box<MxcDiplomatError>> {
            protect(|| {
                let mut sandbox = self.try_lock()?;
                poll_result_from_sdk(sandbox.try_wait())
            })
        }

        /// Wait for the sandbox process to finish.
        pub fn wait(&self) -> Result<MxcDiplomatWaitResult, Box<MxcDiplomatError>> {
            protect(|| {
                let mut sandbox = self.try_lock()?;
                sandbox
                    .wait()
                    .map(MxcDiplomatWaitResult::from_outcome)
                    .map_err(|error| io_error("waiting for sandbox", error))
            })
        }

        /// Kill the sandbox process and its process tree.
        pub fn kill(&self) -> Result<(), Box<MxcDiplomatError>> {
            protect(|| {
                let mut sandbox = self.try_lock()?;
                sandbox
                    .kill()
                    .map_err(|error| io_error("killing sandbox", error))
            })
        }
    }

    impl fmt::Debug for MxcDiplomatInputStream {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MxcDiplomatInputStream(..)")
        }
    }

    impl MxcDiplomatInputStream {
        /// Write bytes to the sandbox stdin stream.
        ///
        /// The returned count may be lower than the input length.
        pub fn write(&self, bytes: &[u8]) -> Result<u64, Box<MxcDiplomatError>> {
            protect(|| {
                let mut stream = self
                    .inner
                    .lock()
                    .map_err(|_| poisoned_lock_error("sandbox stdin stream"))?;
                stream
                    .write(bytes)
                    .map(|count| count as u64)
                    .map_err(|error| io_error("writing sandbox stdin", error))
            })
        }

        /// Flush buffered bytes to the sandbox stdin stream.
        pub fn flush(&self) -> Result<(), Box<MxcDiplomatError>> {
            protect(|| {
                let mut stream = self
                    .inner
                    .lock()
                    .map_err(|_| poisoned_lock_error("sandbox stdin stream"))?;
                stream
                    .flush()
                    .map_err(|error| io_error("flushing sandbox stdin", error))
            })
        }
    }

    impl fmt::Debug for MxcDiplomatOutputStream {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("MxcDiplomatOutputStream(..)")
        }
    }

    impl MxcDiplomatOutputStream {
        /// Read bytes from a sandbox stdout or stderr stream.
        ///
        /// A returned count of zero signals end-of-stream.
        pub fn read(&self, bytes: &mut [u8]) -> Result<u64, Box<MxcDiplomatError>> {
            protect(|| {
                let mut stream = self
                    .inner
                    .lock()
                    .map_err(|_| poisoned_lock_error("sandbox output stream"))?;
                stream
                    .read(bytes)
                    .map(|count| count as u64)
                    .map_err(|error| io_error("reading sandbox output", error))
            })
        }
    }

    impl MxcDiplomatWaitResult {
        fn from_outcome(outcome: WaitOutcome) -> Self {
            match outcome {
                WaitOutcome::Exited(exit_code) => Self {
                    timed_out: false,
                    exit_code,
                },
                WaitOutcome::TimedOut => Self {
                    timed_out: true,
                    exit_code: -1,
                },
            }
        }
    }

    impl MxcDiplomatError {
        fn from_sdk(error: Error) -> Self {
            let has_operation = error.operation.is_some();
            let has_native_code = error.native_code.is_some();
            let has_remediation = error.remediation.is_some();
            Self {
                code: error_code_from_sdk(error.code),
                message: error.message,
                operation: error.operation.unwrap_or_default(),
                has_operation,
                native_code: error.native_code.unwrap_or_default(),
                has_native_code,
                remediation: error.remediation.unwrap_or_default(),
                has_remediation,
            }
        }

        fn panic() -> Self {
            Self {
                code: MxcDiplomatErrorCode::Panic,
                message: "the mxc engine panicked".to_string(),
                operation: String::new(),
                has_operation: false,
                native_code: String::new(),
                has_native_code: false,
                remediation: String::new(),
                has_remediation: false,
            }
        }

        /// Return the machine-readable failure category.
        pub fn code(&self) -> MxcDiplomatErrorCode {
            self.code
        }

        /// Return the human-readable failure message.
        pub fn message(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.message)
        }

        /// Return whether the SDK identified a failing platform operation.
        pub fn has_operation(&self) -> bool {
            self.has_operation
        }

        /// Return the failing platform operation, or an empty string when absent.
        pub fn operation(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.operation)
        }

        /// Return whether the SDK identified a platform status code.
        pub fn has_native_code(&self) -> bool {
            self.has_native_code
        }

        /// Return the platform status code, or an empty string when absent.
        pub fn native_code(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.native_code)
        }

        /// Return whether the SDK supplied an actionable remediation.
        pub fn has_remediation(&self) -> bool {
            self.has_remediation
        }

        /// Return the remediation text, or an empty string when absent.
        pub fn remediation(&self, write: &mut DiplomatWrite) -> Result<(), ()> {
            write_text(write, &self.remediation)
        }
    }

    fn state_aware_envelope(
        expected_phase: &str,
        request_json: &str,
        dry_run: bool,
        experimental: bool,
    ) -> Result<Box<MxcDiplomatStateAwareEnvelope>, Box<MxcDiplomatError>> {
        protect(|| {
            require_state_aware_phase(expected_phase, request_json)?;
            run_state_aware_json(request_json, dry_run, experimental)
                .map(|response_json| Box::new(MxcDiplomatStateAwareEnvelope { response_json }))
                .map_err(error_from_sdk)
        })
    }

    fn require_state_aware_phase(
        expected_phase: &str,
        request_json: &str,
    ) -> Result<(), Box<MxcDiplomatError>> {
        let request: serde_json::Value = serde_json::from_str(request_json).map_err(|error| {
            error_from_sdk(Error::new(
                ErrorCode::MalformedRequest,
                format!("failed to parse state-aware request JSON: {error}"),
            ))
        })?;
        let actual_phase = request.get("phase").and_then(serde_json::Value::as_str);
        if actual_phase == Some(expected_phase) {
            Ok(())
        } else {
            Err(error_from_sdk(Error::new(
                ErrorCode::MalformedRequest,
                format!(
                    "expected state-aware {expected_phase:?} request, found phase {}",
                    actual_phase.unwrap_or("<missing>")
                ),
            )))
        }
    }

    fn poll_result_from_sdk(
        result: std::io::Result<Option<i32>>,
    ) -> Result<MxcDiplomatPollResult, Box<MxcDiplomatError>> {
        match result {
            Ok(Some(exit_code)) => Ok(MxcDiplomatPollResult {
                is_running: false,
                timed_out: false,
                exit_code,
            }),
            Ok(None) => Ok(MxcDiplomatPollResult {
                is_running: true,
                timed_out: false,
                exit_code: 0,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                Ok(MxcDiplomatPollResult {
                    is_running: false,
                    timed_out: true,
                    exit_code: -1,
                })
            }
            Err(error) => Err(io_error("polling sandbox", error)),
        }
    }

    fn io_error(operation: &str, error: std::io::Error) -> Box<MxcDiplomatError> {
        let mut sdk_error = Error::new(
            ErrorCode::BackendError,
            format!("{operation} failed: {error}"),
        );
        sdk_error.operation = Some(operation.to_string());
        error_from_sdk(sdk_error)
    }

    fn poisoned_lock_error(handle: &str) -> Box<MxcDiplomatError> {
        let mut sdk_error = Error::new(
            ErrorCode::BackendError,
            format!("{handle} lock was poisoned by a prior panic"),
        );
        sdk_error.operation = Some("Diplomat handle synchronization".to_string());
        error_from_sdk(sdk_error)
    }

    fn busy_lock_error(handle: &str) -> Box<MxcDiplomatError> {
        let mut sdk_error = Error::new(
            ErrorCode::BackendError,
            format!(
                "{handle} is busy with another operation; wait for it to finish before retrying"
            ),
        );
        sdk_error.operation = Some("Diplomat handle synchronization".to_string());
        error_from_sdk(sdk_error)
    }

    fn protect<T>(
        work: impl FnOnce() -> Result<T, Box<MxcDiplomatError>>,
    ) -> Result<T, Box<MxcDiplomatError>> {
        catch_unwind(AssertUnwindSafe(work))
            .unwrap_or_else(|_| Err(Box::new(MxcDiplomatError::panic())))
    }

    fn error_from_sdk(error: Error) -> Box<MxcDiplomatError> {
        Box::new(MxcDiplomatError::from_sdk(error))
    }

    fn serialization_error(error: serde_json::Error) -> Box<MxcDiplomatError> {
        error_from_sdk(Error::new(
            ErrorCode::BackendError,
            format!("failed to serialize MXC bridge output: {error}"),
        ))
    }

    fn write_text(write: &mut DiplomatWrite, text: &str) -> Result<(), ()> {
        write.write_str(text).map_err(|_| ())
    }

    fn error_code_from_sdk(code: ErrorCode) -> MxcDiplomatErrorCode {
        match code {
            ErrorCode::MalformedRequest => MxcDiplomatErrorCode::MalformedRequest,
            ErrorCode::UnsupportedContainment => MxcDiplomatErrorCode::UnsupportedContainment,
            ErrorCode::UnsupportedPhase => MxcDiplomatErrorCode::UnsupportedPhase,
            ErrorCode::BackendUnavailable => MxcDiplomatErrorCode::BackendUnavailable,
            ErrorCode::MalformedId => MxcDiplomatErrorCode::MalformedId,
            ErrorCode::StaleId => MxcDiplomatErrorCode::StaleId,
            ErrorCode::NotProvisioned => MxcDiplomatErrorCode::NotProvisioned,
            ErrorCode::NotStarted => MxcDiplomatErrorCode::NotStarted,
            ErrorCode::AlreadyStarted => MxcDiplomatErrorCode::AlreadyStarted,
            ErrorCode::AlreadyStopped => MxcDiplomatErrorCode::AlreadyStopped,
            ErrorCode::PolicyValidation => MxcDiplomatErrorCode::PolicyValidation,
            ErrorCode::BackendError => MxcDiplomatErrorCode::BackendError,
        }
    }
}

#[cfg(test)]
mod tests {
    use diplomat_runtime::rust_interop::RustWriteVec;

    use super::ffi::{MxcDiplomat, MxcDiplomatErrorCode};

    fn read_text(
        write: impl FnOnce(&mut diplomat_runtime::DiplomatWrite) -> Result<(), ()>,
    ) -> String {
        let mut buffer = RustWriteVec::with_capacity(0);
        // SAFETY: `buffer` is the sole owner of its DiplomatWrite instance.
        write(unsafe { buffer.borrow_mut() }).expect("writing bridge text should succeed");
        String::from_utf8(buffer.borrow().as_bytes().to_vec()).expect("bridge text is UTF-8")
    }

    #[test]
    fn version_is_owned_and_matches_the_native_crate() {
        let version = MxcDiplomat::version().expect("version should not fail");
        assert_eq!(
            read_text(|write| version.value(write)),
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn discovery_preserves_the_existing_json_contracts() {
        let discovery = MxcDiplomat::discover().expect("discovery should not fail");
        let backends: serde_json::Value =
            serde_json::from_str(&read_text(|write| discovery.available_backends_json(write)))
                .expect("backend JSON");
        let support: serde_json::Value =
            serde_json::from_str(&read_text(|write| discovery.platform_support_json(write)))
                .expect("support JSON");

        assert!(backends.is_array());
        assert!(support.get("isSupported").is_some());
        assert!(support.get("availableMethods").is_some());
    }

    #[test]
    fn malformed_request_uses_an_opaque_typed_error() {
        let error = MxcDiplomat::run(r#"{"policy":{"version":""},"command":"echo hi"}"#)
            .expect_err("an empty policy version should fail before execution");

        assert_eq!(error.code(), MxcDiplomatErrorCode::MalformedRequest);
        assert_eq!(
            read_text(|write| error.message(write)),
            "Policy version is required"
        );
        assert!(!error.has_operation());
        assert!(!error.has_native_code());
        assert!(!error.has_remediation());
    }

    #[test]
    fn malformed_spawn_uses_the_existing_request_contract() {
        let error = MxcDiplomat::spawn(r#"{"policy":{"version":""},"command":"echo hi"}"#)
            .expect_err("an empty policy version should fail before spawning");

        assert_eq!(error.code(), MxcDiplomatErrorCode::MalformedRequest);
        assert_eq!(
            read_text(|write| error.message(write)),
            "Policy version is required"
        );
    }

    #[test]
    fn malformed_state_aware_request_returns_a_typed_error() {
        let error = MxcDiplomat::provision("{", false, false)
            .expect_err("invalid state-aware JSON should not reach a backend");

        assert_eq!(error.code(), MxcDiplomatErrorCode::MalformedRequest);
        assert!(read_text(|write| error.message(write))
            .contains("failed to parse state-aware request JSON"));
    }

    #[test]
    fn state_aware_phase_mismatch_is_rejected_before_execution() {
        let error = MxcDiplomat::provision(r#"{"phase":"start"}"#, false, false)
            .expect_err("a provision entry point must not run a start request");

        assert_eq!(error.code(), MxcDiplomatErrorCode::MalformedRequest);
        assert_eq!(
            read_text(|write| error.message(write)),
            "expected state-aware \"provision\" request, found phase start"
        );
    }
}
