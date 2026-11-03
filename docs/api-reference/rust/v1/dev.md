# Rust V1.Dev exact-JSON API

> **Audience:** MXC consumers

Public entrypoint: `mxc_sdk::v1::dev`. Methods pass complete MXC request JSON
unchanged to the in-process engine. The JSON supplies the contract `version`,
`phase`, and container ID where applicable. MXC rejects unregistered versions,
unknown fields, and malformed JSON.

`JsonOptions { experimental: bool }` authorizes experimental backends
independently of the JSON version. `PtyJsonOptions` also carries
`size: MxcPtySize` (24 rows by 80 columns by default).
Result and process types belong to `mxc_sdk::v1`.

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

`run_json` uses pipe-backed execution or backend-owned capture. On Windows x64,
MicroVM supports captured create-and-run execution, live stdout and stderr
through `spawn_json`, and persistent provision, start, exec, stop, and
deprovision operations through the JSON lifecycle functions above. MicroVM
does not provide writable stdin or PTY execution. It requires a build with the
`microvm` Cargo feature, experimental authorization, and the signed NVX bundle
and host prerequisites described in the
[MicroVM guide](https://github.com/microsoft/mxc/blob/main/docs/backends/nvx/nvx.md).
When the platform or build does not include MicroVM, `run_json` returns
`BackendUnavailable`, `spawn_json` returns `UnsupportedContainment`, and the
JSON lifecycle functions return `UnsupportedPhase`. On a supported Windows x64
build, missing bundle or host runtime prerequisites return
`BackendUnavailable`.

MicroVM `run_json` and `run_in_container_json` enforce a 67,108,864-byte
combined stdout and stderr capture limit. Lifecycle capture overflow terminates
and releases only the running exec, leaving the provisioned container usable.
`spawn_json` and `spawn_in_container_json` return caller-controlled live
streams and do not apply this capture limit.

Lifecycle calls explicitly close their native host and report close failures.
If provision succeeded before close failed, the returned `Error` retains
`details.nvxRecovery.sandboxId` and a `"provisioned"` recovery state. The
container remains caller-owned; use that ID to continue or deprovision instead
of retrying provision. Treat the ID as sensitive. See the
[MicroVM cleanup guide](https://github.com/microsoft/mxc/blob/main/docs/backends/nvx/nvx.md#output-timeout-and-cleanup).

Pipe and PTY spawns and existing-container capture require the selected
backend's corresponding I/O and lifecycle support. Unsupported modes fail
rather than switching to another I/O mode.
