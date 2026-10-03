# `mxc-sdk`

`mxc-sdk` is the Rust library for authoring MXC container requests and executing
them in-process through the native engine. The versioned public API is under
`mxc_sdk::v1`. All request and policy types in this API use the owned V1
contract rather than exposing the wire-version selector.

## One-shot execution

Build a request from a `ContainerPolicy` and command, then choose captured
output with `run` or live pipes with `spawn`:

```rust,no_run
use mxc_sdk::v1::{self, ContainerPolicy, WaitOutcome};

let mut policy = ContainerPolicy::default();
policy.timeout_ms = Some(10_000);
let request = v1::build_request(&policy, "echo hello", None)?;

let output = v1::run(request)?;
assert_eq!(output.outcome, WaitOutcome::Exited(0));
println!("{}", String::from_utf8_lossy(&output.stdout));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`spawn` returns an `MxcProcess` with separate standard streams, wait and
termination methods. `run` captures stdout and stderr and returns an `Output`
with its `WaitOutcome`, warnings, and optional output metadata. Both use the
same in-process native engine; neither launches an MXC executor binary.

Use `build_request_with_containment` when a specific backend is required.
Policy, backend configuration, and request types are documented in the
[`v1` API](src/lib.rs) and the [container policy guide](../../../docs/schema.md).
The request includes the command; its working directory and environment can be
adjusted before execution.

## Existing containers

Typed state-aware operations are available under `v1`. `ProvisionRequest`
selects the backend; the returned opaque `ContainerId` is supplied to later
phases. `ExecRequest` carries the workload and process settings.

```rust,no_run
use mxc_sdk::v1::{
    self, ExecRequest, OperationOptions, ProvisionRequest,
};

let options = OperationOptions::default();
let provisioned = v1::container::provision_sandbox(
    ProvisionRequest::wslc(Some("alpine:latest".into()), None),
    options,
)?;
let id = provisioned.container_id;

v1::container::start_sandbox(&id, options)?;
let output = v1::run_in_container(
    &id,
    ExecRequest::new("echo hello"),
    options,
)?;
println!("{}", String::from_utf8_lossy(&output.stdout));
v1::container::stop_sandbox(&id, options)?;
v1::container::deprovision_sandbox(&id, options)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `spawn_in_container` or `exec_in_sandbox` for live piped exec. Lifecycle
operations and state-aware exec are synchronous in Rust. Backend support and
phase-specific requirements are described in the
[IsolationSession](../../../docs/isolation-session/state-aware-rust.md) and
[WSLC](../../../docs/wsl/wslc-state-aware.md) guides.

## Public V1 types

| Purpose | Rust type |
| --- | --- |
| Container restrictions | `v1::ContainerPolicy` |
| One-shot workload | `v1::ContainerRequest` |
| Persistent container identity | `v1::ContainerId` |
| Existing-container workload | `v1::ExecRequest` |
| Live process with standard pipes | `v1::MxcProcess` |
| Captured execution | `v1::Output` |
| Terminal process outcome | `v1::WaitOutcome` |

The public API does not include terminal/PTY operations. For host discovery,
use `mxc_sdk::platform_support` and `mxc_sdk::available_backends`. Errors are
returned as `mxc_sdk::Error` with an `ErrorCode`.

## Build features and backend support

Backend availability depends on the target OS, host configuration, and crate
features. WSLC and IsolationSession support require their respective build
features. See the backend documentation under [`docs/`](../../../docs/) for
host prerequisites and enforcement details.

Telemetry is disabled unless the individual request opts in, and remains
subject to MXC's persisted user consent and administrative policy.
