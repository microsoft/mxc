# Rust V1.Dev exact-JSON API

Public entrypoint: `mxc_sdk::v1::dev`. All methods accept one complete,
caller-authored exact-version JSON document and execute through the
in-process engine. No method stamps a version, reserializes the request, or
takes a second container ID. Invalid versions, unknown fields, and malformed
JSON are rejected by the exact contract parser.

`JsonOptions { experimental: bool }` authorizes an experimental backend
independently of the authored version. `PtyJsonOptions` also carries
`size: MxcPtySize` (24 rows by 80 columns by default). The full request,
including its version, phase, and any container ID, is a single JSON string.
Result and process types are the existing `mxc_sdk::v1` types.

`run_json` and `run_in_container_json` return byte-preserving
`ExecutionResult` values; a nonzero workload exit or timeout is an outcome,
not an API error. Pipe and PTY spawns return owned `MxcProcess` and
`MxcPtyProcess` handles. Existing-container execution does not deprovision
the caller-owned container. The phase-specific lifecycle and validation
methods require the matching `phase` in the JSON before dispatch; validation
uses native dry-run behavior. They return the complete native response
envelope as a `String`, including backend-specific metadata.

```rust
pub fn run_json(json: &str, options: JsonOptions) -> Result<ExecutionResult, Error>;
pub fn spawn_json(json: &str, options: JsonOptions) -> Result<MxcProcess, Error>;
pub fn spawn_with_pty_json(json: &str, options: PtyJsonOptions)
    -> Result<MxcPtyProcess, Error>;

pub fn run_in_container_json(json: &str, options: JsonOptions)
    -> Result<ExecutionResult, Error>;
pub fn spawn_in_container_json(json: &str, options: JsonOptions) -> Result<MxcProcess, Error>;
pub fn spawn_in_container_with_pty_json(json: &str, options: PtyJsonOptions)
    -> Result<MxcPtyProcess, Error>;

pub fn provision_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn start_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn stop_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn deprovision_container_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_provision_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_start_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_stop_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_deprovision_json(json: &str, options: JsonOptions) -> Result<String, Error>;
pub fn validate_process_json(json: &str, options: JsonOptions) -> Result<String, Error>;
```

Capture uses pipe-backed execution: a backend without piped execution
rejects this mode with `UnsupportedContainment` even when experimental
access is authorized. PTY and state-aware support also depend on the
selected backend and host. Unsupported modes fail rather than switching to
another I/O mode.
