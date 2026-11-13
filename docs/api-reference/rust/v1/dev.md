# Rust V1.Dev exact-JSON API

> **Audience:** MXC consumers

Public entrypoint: `mxc_sdk::v1::dev`. Methods pass complete MXC request JSON
unchanged to the in-process engine. The JSON supplies the contract `version`,
`phase`, and container ID where applicable. MXC rejects unregistered versions,
unknown fields, and malformed JSON.

`JsonOptions { experimental: bool }` authorizes experimental backends
independently of the JSON version. `PtyJsonOptions` also carries
`size: MxcPtySize` (24 rows by 80 columns by default).
`SpawnExtendedJsonOptions` carries `experimental` and `stdio: SpawnStdio`;
like `SpawnExtendedOptions`, it is `#[non_exhaustive]`.
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
pub fn spawn_with_extended_options_json(json: &str, options: SpawnExtendedJsonOptions)
    -> Result<MxcProcess, Error>;

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

`run_json` uses pipe-backed execution or backend-owned capture. MicroVM supports
captured and live stdout/stderr and the JSON lifecycle functions above, but
not writable stdin or PTY. It requires Windows x64, the `microvm` Cargo feature,
experimental authorization, and the signed NVX bundle. Without platform/build
support, `run_json` returns `BackendUnavailable`, `spawn_json` returns
`UnsupportedContainment`, and lifecycle functions return `UnsupportedPhase`.
Missing runtime prerequisites on a supported build return `BackendUnavailable`.
See the [MicroVM guide](https://github.com/microsoft/mxc/blob/main/docs/backends/nvx/nvx.md)
for the 64 MiB capture limit, caller-owned streams, and sensitive
`Error.details.nvxRecovery` information when provision succeeds but cleanup fails.

Pipe and PTY spawns and existing-container capture require the selected
backend's corresponding I/O and lifecycle support. Unsupported modes fail
rather than switching to another I/O mode. `spawn_with_extended_options_json`
with `SpawnStdio::Inherit` attaches the workload to the calling process's
stdin, stdout, and stderr and supports ProcessContainer, Bubblewrap, and Seatbelt.
