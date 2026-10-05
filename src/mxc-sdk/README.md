# `mxc-sdk`

`mxc-sdk` is the Rust library for authoring MXC container requests and executing
them in-process through the native engine. The versioned public API is under
`mxc_sdk::v1`. `ContainerRequest` owns the command and shared filesystem,
network, and UI restrictions; its typed containment value selects and
configures the backend.

## Run to completion and spawn

Build a `ContainerRequest` directly, then choose captured output with `run` or
live pipes with `spawn`:

```rust,no_run
use mxc_sdk::v1::{self, ContainerRequest, FilesystemPolicy, WaitResult};

let request = ContainerRequest {
    timeout_ms: Some(10_000),
    filesystem: Some(FilesystemPolicy {
        readonly_paths: vec!["/usr".into()],
        ..Default::default()
    }),
    ..ContainerRequest::new("echo hello")
};

let output = v1::run(request, Default::default())?;
assert_eq!(output.outcome, WaitResult::Exited(0));
println!("{}", String::from_utf8_lossy(&output.stdout));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`spawn` returns an `MxcProcess` with separate standard streams, wait and
termination methods. `run` captures stdout and stderr and returns an
`ExecutionResult` with its `WaitResult`, warnings, and optional output metadata. Both use the
same in-process native engine; neither launches an MXC executor binary.
Captured execution drains both streams concurrently. Output-read failures are
returned as errors; timeouts cancel outstanding reads and return the partial
output with `WaitResult::TimedOut`.

Creation takes `RunOptions`, `SpawnOptions`, or `SpawnWithPtyOptions` after
the request. `SpawnWithPtyOptions.size` carries initial dimensions and defaults
to 24 rows by 80 columns. `experimental` authorizes native experimental
features without changing the SDK-owned wire contract.

Set the request's typed `Containment` when a specific backend is required.
Shared restrictions remain on `ContainerRequest`; backend-specific settings
are carried by the selected containment variant. These types are documented in
the [SDK API reference](https://github.com/microsoft/mxc/blob/main/docs/reference/README.md).

`UiPolicy.disable` defaults to `true`; clipboard and input-injection
permissions are authored separately.

The request is a public-field model: set `command`, `working_directory`,
`environment`, `inherit_default_environment`, `timeout_ms`, and the optional
filesystem, network, UI, and containment policies directly. `environment:
None` uses the backend default, while `Some(Vec::new())` requests an explicitly
empty environment. Set `inherit_default_environment` to layer supplied entries
over backend defaults. Native validation remains responsible for determining
whether that environment can be launched by the selected backend.

Runtime network settings are nested under `network.runtime_config`, alongside
directional policy. For existing-container execution, `ExecutionRequest.network`
is a runtime-only `ProcessNetworkPolicy`; it cannot change provision-time
policy.

## Lifecycle API

Typed lifecycle operations are available under `v1`. `ProvisionRequest`
selects the backend; the returned opaque `ContainerId` is supplied to later
phases. `ExecutionRequest` carries the workload and process settings.

```rust,no_run
use mxc_sdk::v1::{
    self, ExecutionRequest, ProvisionRequest,
};

let provisioned = v1::container::provision_container(
    ProvisionRequest::wslc(Some("alpine:latest".into()), None),
    Default::default(),
)?;
let id = provisioned.container_id;

v1::container::start_container(&id, Default::default())?;
let output = v1::container::run_in_container(
    &id,
    ExecutionRequest {
        network: Some(mxc_sdk::v1::ProcessNetworkPolicy {
            runtime_config: Some(mxc_sdk::v1::NetworkRuntimeConfig {
                network_proxy: Some("http://proxy.example:8080".into()),
            }),
        }),
        ..ExecutionRequest::new("echo hello")
    },
    Default::default(),
)?;
println!("{}", String::from_utf8_lossy(&output.stdout));
v1::container::stop_container(&id, Default::default())?;
v1::container::deprovision_container(&id, Default::default())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `v1::container::spawn_in_container` for live piped execution.
`v1::container::spawn_in_container_with_pty` returns an `MxcPtyProcess` for a caller-driven
terminal; PTY support is currently available for IsolationSession.
Attached execution is not exposed by the Rust SDK. Lifecycle operations and
existing-container execution are synchronous in Rust. Backend support and phase-specific requirements are described in the
[IsolationSession](https://github.com/microsoft/mxc/blob/main/docs/isolation-session/state-aware-rust.md) and
[WSLC](https://github.com/microsoft/mxc/blob/main/docs/wsl/wslc-state-aware.md) guides.

Lifecycle calls use distinct `ProvisionOptions`, `StartOptions`, `StopOptions`,
and `DeprovisionOptions`. Existing-container execution uses
`SpawnInContainerOptions`, `RunInContainerOptions`, or
`SpawnInContainerWithPtyOptions`. Set its `size` field for initial dimensions;
it defaults to 24 rows by 80 columns. Invocation telemetry overrides request
telemetry when supplied. Native `validate_provision`, `validate_start`,
`validate_stop`, `validate_deprovision`, and `validate_process` use those
operation options and return no execution output.

## Public V1 types

| Purpose | Rust type |
| --- | --- |
| Creation workload and cross-backend restrictions | `v1::ContainerRequest` |
| Persistent container identity | `v1::ContainerId` |
| Persistent container provision input | `v1::ProvisionRequest` |
| Backend authoring configuration | `v1::configs::ProcessContainerConfig`, `LxcConfig`, `SeatbeltConfig`, `WslcConfig` |
| Existing-container workload | `v1::ExecutionRequest` |
| Live process with standard pipes | `v1::MxcProcess` |
| Live process with a terminal | `v1::MxcPtyProcess` |
| Terminal dimensions | `v1::MxcPtySize` |
| Captured execution | `v1::ExecutionResult` |
| Terminal process outcome | `v1::WaitResult` |

`v1::spawn_with_pty` creates a container with a caller-controlled terminal.
One-shot PTY support is available for IsolationSession on Windows, Bubblewrap
and LXC on Linux, and Seatbelt direct execution on macOS. LXC requires root.
Seatbelt rejects PTY mode with `guiAccess` or legacy `launchMethod: "open"`.
`wait()` requests canonical-mode terminal EOF for untaken input; raw-mode
applications must use their own completion protocol. Untaken merged output is
drained and discarded without waiting indefinitely for descendants that keep
the terminal open. Ordinary `spawn` continues to use separate pipes.
For host discovery, use
`mxc_sdk::v1::platform_support` and `mxc_sdk::v1::available_backends`. Errors are
returned as `mxc_sdk::v1::Error` with an `ErrorCode`.
Telemetry and policy helpers are also under `v1`. The
[launch-choice table](../../../docs/reference/rust/v1/api.md#choosing-a-launch-operation)
compares captured, piped, and terminal execution.

## Build features and backend support

Backend availability depends on the target OS, host configuration, and crate
features. WSLC and IsolationSession support require their respective build
features. See the backend documentation under
[`docs/`](https://github.com/microsoft/mxc/tree/main/docs) for
host prerequisites and enforcement details.

Creation telemetry is supplied through `telemetry: Option<TelemetryConfig>` on `RunOptions`,
`SpawnOptions`, or `SpawnWithPtyOptions`, not on `ContainerRequest`. Omission
leaves telemetry disabled; `TelemetryConfig { enabled: Some(false) }`
explicitly disables it. Opt-in remains
subject to MXC's persisted user consent and administrative policy.

Filesystem discovery helpers and their result/options types live under
`mxc_sdk::v1::policy::filesystem`. They take `environment: Option<&[(String, String)]>`;
`None` snapshots the process environment and `Some(&[])` is explicitly empty.
`available_tools_policy` additionally takes `ToolsPolicyOptions`; use
`Default::default()` for ordinary discovery or
`container_type: Some(ToolsPolicyContainerType::ProcessContainer)` to exclude
directories with ALL APPLICATION PACKAGES access on Windows. ACL inspection is
bounded to five seconds per directory; failures retain the directory and use
the configured diagnostic sink. `user_profile_policy` discovers standard
per-user tool locations, and `temporary_files_policy` returns existing
temporary storage without creating directories.

## Internal modules and executor binaries

Backend implementations, shared runtime support, backend dispatch, and host
probing are internal modules of this published crate. The crate root exposes
only the versioned public SDK and explicitly hidden compatibility surfaces used
by the retained MXC binaries and FFI boundary.

The `wxc-exec`, `lxc-exec`, and `mxc-exec-mac` packages remain thin process
entry points that depend on `mxc-sdk`. The Windows Sandbox guest and daemon,
plus the WSLC daemon when the `wslc` feature is enabled, are published as
`mxc-sdk` binary targets so their implementation and packaged assets remain
part of the same release unit.

Cargo builds the `[[bin]]` targets declared in `Cargo.toml` as part of the
package. They can also be selected directly:

```text
cargo build --manifest-path src/Cargo.toml -p mxc-sdk --release --bin wxc-windows-sandbox-daemon
cargo build --manifest-path src/Cargo.toml -p mxc-sdk --release --bin wxc-windows-sandbox-guest
cargo build --manifest-path src/Cargo.toml -p mxc-sdk --release --features wslc --bin wxc-wslc-daemon
```

`required-features = ["wslc"]` prevents Cargo from building the WSLC daemon
unless WSLC support is enabled. The crate build script prepares package assets
and Windows version resources; repository build scripts and CI copy, sign, and
publish the resulting executables from the Cargo target directory.
