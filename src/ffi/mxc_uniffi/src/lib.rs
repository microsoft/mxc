// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! UniFFI projection of the safe [`mxc_sdk`] API.
//!
//! UniFFI generates the native ABI metadata, TypeScript API, and C# API from
//! this object model. This crate owns only language-neutral value conversion,
//! process-handle synchronization, and panic containment.

use std::fmt;
use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use futures_channel::oneshot;
use mxc_sdk::{
    available_backends, build_request_from_json, exec_attached, exec_sandbox, platform_support,
    run as sdk_run, run_state_aware_json, spawn_sandbox, Error, Output, Sandbox, WaitOutcome,
};

const STREAM_CHUNK_BYTES: usize = 64 * 1024;
const HANDLE_SYNC_OPERATION: &str = "UniFFI handle synchronization";

type BindingResult<T> = Result<T, Arc<BindingError>>;

/// A structured MXC failure projected into every generated SDK.
#[derive(Debug, uniffi::Object)]
#[uniffi::export(Debug, Display)]
pub struct BindingError {
    code: String,
    message: String,
    operation: Option<String>,
    native_code: Option<String>,
    remediation: Option<String>,
}

#[uniffi::export]
impl BindingError {
    /// Returns the stable snake-case error code.
    pub fn code(&self) -> String {
        self.code.clone()
    }

    /// Returns the human-readable failure message.
    pub fn message(&self) -> String {
        self.message.clone()
    }

    /// Returns the native operation that failed, when available.
    pub fn operation(&self) -> Option<String> {
        self.operation.clone()
    }

    /// Returns the native status code, when available.
    pub fn native_code(&self) -> Option<String> {
        self.native_code.clone()
    }

    /// Returns an actionable remediation hint, when available.
    pub fn remediation(&self) -> Option<String> {
        self.remediation.clone()
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(operation) = &self.operation {
            write!(formatter, " [{operation}")?;
            if let Some(native_code) = &self.native_code {
                write!(formatter, " {native_code}")?;
            }
            write!(formatter, "]")?;
        }
        Ok(())
    }
}

impl std::error::Error for BindingError {}

impl From<Error> for BindingError {
    fn from(error: Error) -> Self {
        Self {
            code: error.code.as_str().to_string(),
            message: error.message,
            operation: error.operation,
            native_code: error.native_code,
            remediation: error.remediation,
        }
    }
}

/// Host discovery values returned together from one native snapshot.
#[derive(Debug, uniffi::Record)]
pub struct Discovery {
    /// JSON array of all backends available on this host.
    pub available_backends_json: String,
    /// JSON object describing the backends callable through `mxc-sdk`.
    pub platform_support_json: String,
}

/// Captured output from a completed sandbox run.
#[derive(Debug, uniffi::Record)]
pub struct RunResult {
    /// Process exit code, or `-1` after a timeout.
    pub exit_code: i32,
    /// Whether the configured script timeout elapsed.
    pub timed_out: bool,
    /// Bytes written to stdout.
    pub stdout: Vec<u8>,
    /// Bytes written to stderr.
    pub stderr: Vec<u8>,
    /// Policy and backend warnings.
    pub warnings: Vec<String>,
    /// Optional structured output metadata serialized as JSON.
    pub output_metadata_json: Option<String>,
}

/// Non-blocking completion state for a live sandbox.
#[derive(Debug, uniffi::Record)]
pub struct PollResult {
    /// Whether the sandbox process remains active.
    pub is_running: bool,
    /// Process exit code when the process has completed.
    pub exit_code: Option<i32>,
}

/// Terminal completion state for a live sandbox.
#[derive(Debug, uniffi::Record)]
pub struct WaitResult {
    /// Process exit code, or `-1` after a timeout.
    pub exit_code: i32,
    /// Whether the configured script timeout elapsed.
    pub timed_out: bool,
}

/// A synchronized live sandbox process.
#[derive(uniffi::Object)]
pub struct BindingSandbox {
    inner: Mutex<Sandbox>,
}

impl fmt::Debug for BindingSandbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingSandbox")
            .finish_non_exhaustive()
    }
}

/// An owned stdin stream.
#[derive(uniffi::Object)]
pub struct BindingInput {
    inner: Mutex<Box<dyn Write + Send>>,
}

impl fmt::Debug for BindingInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingInput")
            .finish_non_exhaustive()
    }
}

/// An owned stdout or stderr stream.
#[derive(uniffi::Object)]
pub struct BindingOutput {
    inner: Mutex<Box<dyn Read + Send>>,
}

impl fmt::Debug for BindingOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingOutput")
            .finish_non_exhaustive()
    }
}

/// Returns the version of the loaded native MXC library.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Returns one host discovery snapshot.
#[uniffi::export]
pub fn discover() -> BindingResult<Discovery> {
    protect(|| {
        Ok(Discovery {
            available_backends_json: serde_json::to_string(&available_backends())
                .map_err(serialization_error)?,
            platform_support_json: serde_json::to_string(&platform_support())
                .map_err(serialization_error)?,
        })
    })
}

/// Runs a sandbox to completion on the calling thread.
#[uniffi::export]
pub fn run_sync(request_json: String) -> BindingResult<RunResult> {
    protect(|| run_impl(&request_json))
}

/// Runs a sandbox to completion without blocking the foreign runtime thread.
#[uniffi::export]
pub async fn run(request_json: String) -> BindingResult<RunResult> {
    blocking(move || run_impl(&request_json)).await
}

/// Spawns a live sandbox process on the calling thread.
#[uniffi::export]
pub fn spawn_sync(request_json: String) -> BindingResult<Arc<BindingSandbox>> {
    protect(|| spawn_impl(&request_json))
}

/// Spawns a live sandbox process without blocking the foreign runtime thread.
#[uniffi::export]
pub async fn spawn(request_json: String) -> BindingResult<Arc<BindingSandbox>> {
    blocking(move || spawn_impl(&request_json)).await
}

/// Executes a state-aware phase and returns its response envelope JSON.
#[uniffi::export]
pub fn state_aware_sync(
    request_json: String,
    dry_run: bool,
    experimental: bool,
) -> BindingResult<String> {
    protect(|| state_aware_impl(&request_json, dry_run, experimental))
}

/// Executes a state-aware phase without blocking the foreign runtime thread.
#[uniffi::export]
pub async fn state_aware(
    request_json: String,
    dry_run: bool,
    experimental: bool,
) -> BindingResult<String> {
    blocking(move || state_aware_impl(&request_json, dry_run, experimental)).await
}

/// Executes a state-aware command with live streams on the calling thread.
#[uniffi::export]
pub fn exec_sync(request_json: String, experimental: bool) -> BindingResult<Arc<BindingSandbox>> {
    protect(|| exec_impl(&request_json, experimental))
}

/// Executes a state-aware command with live streams off the runtime thread.
#[uniffi::export]
pub async fn exec(request_json: String, experimental: bool) -> BindingResult<Arc<BindingSandbox>> {
    blocking(move || exec_impl(&request_json, experimental)).await
}

/// Executes a state-aware command on the caller's terminal.
#[uniffi::export]
pub fn exec_attached_sync(request_json: String, experimental: bool) -> BindingResult<WaitResult> {
    protect(|| exec_attached_impl(&request_json, experimental))
}

/// Executes an attached state-aware command off the foreign runtime thread.
#[uniffi::export]
pub async fn exec_attached_async(
    request_json: String,
    experimental: bool,
) -> BindingResult<WaitResult> {
    blocking(move || exec_attached_impl(&request_json, experimental)).await
}

#[uniffi::export]
impl BindingSandbox {
    /// Returns the native process identifier.
    pub fn id(&self) -> BindingResult<u32> {
        protect(|| Ok(lock_sandbox(&self.inner)?.id()))
    }

    /// Returns policy and backend warnings as JSON.
    pub fn warnings_json(&self) -> BindingResult<String> {
        protect(|| {
            let sandbox = lock_sandbox(&self.inner)?;
            serde_json::to_string(sandbox.warnings()).map_err(serialization_error)
        })
    }

    /// Takes stdin exactly once.
    pub fn take_stdin(&self) -> BindingResult<Option<Arc<BindingInput>>> {
        protect(|| {
            Ok(lock_sandbox(&self.inner)?.take_stdin().map(|inner| {
                Arc::new(BindingInput {
                    inner: Mutex::new(inner),
                })
            }))
        })
    }

    /// Takes stdout exactly once.
    pub fn take_stdout(&self) -> BindingResult<Option<Arc<BindingOutput>>> {
        protect(|| {
            Ok(lock_sandbox(&self.inner)?.take_stdout().map(|inner| {
                Arc::new(BindingOutput {
                    inner: Mutex::new(inner),
                })
            }))
        })
    }

    /// Takes stderr exactly once.
    pub fn take_stderr(&self) -> BindingResult<Option<Arc<BindingOutput>>> {
        protect(|| {
            Ok(lock_sandbox(&self.inner)?.take_stderr().map(|inner| {
                Arc::new(BindingOutput {
                    inner: Mutex::new(inner),
                })
            }))
        })
    }

    /// Checks for process completion without blocking.
    pub fn try_wait(&self) -> BindingResult<PollResult> {
        protect(|| {
            let exit_code = lock_sandbox(&self.inner)?.try_wait().map_err(wait_error)?;
            Ok(PollResult {
                is_running: exit_code.is_none(),
                exit_code,
            })
        })
    }

    /// Waits for process completion on the calling thread.
    pub fn wait_sync(&self) -> BindingResult<WaitResult> {
        protect(|| wait_impl(self))
    }

    /// Waits for process completion without blocking the foreign runtime thread.
    pub async fn wait(self: Arc<Self>) -> BindingResult<WaitResult> {
        blocking(move || wait_impl(&self)).await
    }

    /// Requests process termination on the calling thread.
    pub fn kill_sync(&self) -> BindingResult<()> {
        protect(|| kill_impl(self))
    }

    /// Requests process termination without blocking the foreign runtime thread.
    pub async fn kill(self: Arc<Self>) -> BindingResult<()> {
        blocking(move || kill_impl(&self)).await
    }

    /// Returns structured output metadata after terminal completion.
    pub fn output_metadata_json(&self) -> BindingResult<Option<String>> {
        protect(|| {
            let sandbox = lock_sandbox(&self.inner)?;
            sandbox
                .output_metadata()
                .map(serde_json::to_string)
                .transpose()
                .map_err(serialization_error)
        })
    }
}

#[uniffi::export]
impl BindingInput {
    /// Writes bytes to stdin on the calling thread.
    pub fn write_sync(&self, data: Vec<u8>) -> BindingResult<u64> {
        protect(|| write_impl(self, &data))
    }

    /// Writes bytes to stdin without blocking the foreign runtime thread.
    pub async fn write(self: Arc<Self>, data: Vec<u8>) -> BindingResult<u64> {
        blocking(move || write_impl(&self, &data)).await
    }

    /// Flushes stdin on the calling thread.
    pub fn flush_sync(&self) -> BindingResult<()> {
        protect(|| flush_impl(self))
    }

    /// Flushes stdin without blocking the foreign runtime thread.
    pub async fn flush(self: Arc<Self>) -> BindingResult<()> {
        blocking(move || flush_impl(&self)).await
    }
}

#[uniffi::export]
impl BindingOutput {
    /// Reads at most 64 KiB on the calling thread.
    pub fn read_sync(&self) -> BindingResult<Vec<u8>> {
        protect(|| read_impl(self))
    }

    /// Reads at most 64 KiB without blocking the foreign runtime thread.
    pub async fn read(self: Arc<Self>) -> BindingResult<Vec<u8>> {
        blocking(move || read_impl(&self)).await
    }
}

fn run_impl(request_json: &str) -> BindingResult<RunResult> {
    let request = build_request_from_json(request_json).map_err(binding_error)?;
    sdk_run(request).map_err(binding_error).and_then(run_result)
}

fn spawn_impl(request_json: &str) -> BindingResult<Arc<BindingSandbox>> {
    let request = build_request_from_json(request_json).map_err(binding_error)?;
    spawn_sandbox(request)
        .map(|inner| {
            Arc::new(BindingSandbox {
                inner: Mutex::new(inner),
            })
        })
        .map_err(binding_error)
}

fn state_aware_impl(
    request_json: &str,
    dry_run: bool,
    experimental: bool,
) -> BindingResult<String> {
    run_state_aware_json(request_json, dry_run, experimental).map_err(binding_error)
}

fn exec_impl(request_json: &str, experimental: bool) -> BindingResult<Arc<BindingSandbox>> {
    exec_sandbox(request_json, experimental)
        .map(|inner| {
            Arc::new(BindingSandbox {
                inner: Mutex::new(inner),
            })
        })
        .map_err(binding_error)
}

fn exec_attached_impl(request_json: &str, experimental: bool) -> BindingResult<WaitResult> {
    exec_attached(request_json, experimental)
        .map(wait_result)
        .map_err(binding_error)
}

fn run_result(output: Output) -> BindingResult<RunResult> {
    let output_metadata_json = output
        .output_metadata
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(serialization_error)?;
    let result = wait_result(output.outcome);
    Ok(RunResult {
        exit_code: result.exit_code,
        timed_out: result.timed_out,
        stdout: output.stdout,
        stderr: output.stderr,
        warnings: output.warnings,
        output_metadata_json,
    })
}

fn wait_impl(sandbox: &BindingSandbox) -> BindingResult<WaitResult> {
    lock_sandbox(&sandbox.inner)?
        .wait()
        .map(wait_result)
        .map_err(wait_error)
}

fn kill_impl(sandbox: &BindingSandbox) -> BindingResult<()> {
    lock_sandbox(&sandbox.inner)?
        .kill()
        .map_err(|error| io_error("killing the sandbox process failed", error))
}

fn write_impl(input: &BindingInput, data: &[u8]) -> BindingResult<u64> {
    let written = lock_handle(&input.inner)?
        .write(data)
        .map_err(|error| io_error("writing sandbox stdin failed", error))?;
    u64::try_from(written).map_err(|_| {
        local_error(
            "backend_error",
            "written byte count does not fit in the generated SDK result",
        )
    })
}

fn flush_impl(input: &BindingInput) -> BindingResult<()> {
    lock_handle(&input.inner)?
        .flush()
        .map_err(|error| io_error("flushing sandbox stdin failed", error))
}

fn read_impl(output: &BindingOutput) -> BindingResult<Vec<u8>> {
    let mut buffer = vec![0; STREAM_CHUNK_BYTES];
    let read = lock_handle(&output.inner)?
        .read(&mut buffer)
        .map_err(|error| io_error("reading sandbox output failed", error))?;
    buffer.truncate(read);
    Ok(buffer)
}

fn wait_result(outcome: WaitOutcome) -> WaitResult {
    match outcome {
        WaitOutcome::Exited(exit_code) => WaitResult {
            exit_code,
            timed_out: false,
        },
        WaitOutcome::TimedOut => WaitResult {
            exit_code: -1,
            timed_out: true,
        },
    }
}

fn lock_sandbox(inner: &Mutex<Sandbox>) -> BindingResult<MutexGuard<'_, Sandbox>> {
    lock_handle(inner)
}

fn lock_handle<T>(inner: &Mutex<T>) -> BindingResult<MutexGuard<'_, T>> {
    match inner.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(Arc::new(BindingError {
            code: "backend_error".to_string(),
            message: "handle is busy with another operation; wait before retrying".to_string(),
            operation: Some(HANDLE_SYNC_OPERATION.to_string()),
            native_code: None,
            remediation: None,
        })),
        Err(TryLockError::Poisoned(_)) => Err(local_error(
            "backend_error",
            "handle synchronization was poisoned by a previous panic",
        )),
    }
}

fn wait_error(error: std::io::Error) -> Arc<BindingError> {
    io_error("waiting for the sandbox process failed", error)
}

fn io_error(message: &str, error: std::io::Error) -> Arc<BindingError> {
    Arc::new(BindingError {
        code: "backend_error".to_string(),
        message: format!("{message}: {error}"),
        operation: None,
        native_code: error.raw_os_error().map(|code| code.to_string()),
        remediation: None,
    })
}

fn serialization_error(error: serde_json::Error) -> Arc<BindingError> {
    local_error(
        "backend_error",
        format!("serializing generated SDK result failed: {error}"),
    )
}

fn binding_error(error: Error) -> Arc<BindingError> {
    Arc::new(error.into())
}

fn local_error(code: &str, message: impl Into<String>) -> Arc<BindingError> {
    Arc::new(BindingError {
        code: code.to_string(),
        message: message.into(),
        operation: None,
        native_code: None,
        remediation: None,
    })
}

fn protect<T>(operation: impl FnOnce() -> BindingResult<T>) -> BindingResult<T> {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => Err(local_error(
            "panic",
            "the native MXC library panicked while processing the request",
        )),
    }
}

async fn blocking<T, F>(operation: F) -> BindingResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> BindingResult<T> + Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    std::thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(operation));
        let _ = sender.send(result);
    });

    match receiver.await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(local_error(
            "panic",
            "the native MXC library panicked while processing the request",
        )),
        Err(_) => Err(local_error(
            "backend_error",
            "the native MXC worker ended before returning a result",
        )),
    }
}

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_request_keeps_structured_error() {
        let error = run_sync("{".to_string()).expect_err("request must fail");

        assert_eq!(error.code(), "malformed_request");
        assert!(!error.message().is_empty());
    }

    #[test]
    fn discovery_serializes_both_snapshots() {
        let result = discover().expect("host discovery should serialize");

        assert!(result.available_backends_json.starts_with('['));
        assert!(result.platform_support_json.starts_with('{'));
    }
}
