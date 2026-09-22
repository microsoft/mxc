# PR #1219: Moving Lifecycle Selection Out of JSON

## Summary

PR #1219 changes how callers select a sandbox lifecycle action such as `provision`, `start`, `exec`, `stop`, or `deprovision`.

Before this PR, the action and sandbox ID were included in the JSON:

```json
{
  "version": "0.9.0-alpha",
  "phase": "exec",
  "sandboxId": "iso:123",
  "process": {
    "commandLine": "cmd.exe /c echo hello"
  }
}
```

After this PR, the caller selects the action by calling the matching SDK method. The sandbox ID is a method argument. The JSON contains the settings needed for that call:

```rust
sandbox::exec(
    &sandbox_id,
    r#"{
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "cmd.exe /c echo hello"
        }
    }"#,
    true,
)
```

The command-line equivalent uses `--operation exec` and `--sandbox-id`.

## Why the PR Deletes So Much Code

The `0.9.0-alpha` schema previously had separate request types for each lifecycle action. Those types repeated many of the same fields and added extra JSON layers such as:

```text
experimental.<backend>.provision
```

The PR removes those separate schema types, their generated output, and many tests and fixtures that existed only to test the repeated shapes.

Backend-specific provision settings now live directly under the backend section. For example:

```json
{
  "version": "0.9.0-alpha",
  "containment": "isolation_session",
  "network": {
    "egress": { "default": "allow" },
    "ingress": {
      "default": "allow",
      "hostLoopback": "allow"
    }
  },
  "experimental": {
    "isolation_session": {
      "appId": "example"
    }
  }
}
```

This is why the PR has far more deletions than additions: most of the deleted code represented the same settings repeated across separate lifecycle JSON types.

## What Happens Inside MXC

MXC still builds the same two-part internal request:

```text
ParsedStateAwareRequest
├── ExecutionRequest
└── StateAwareOperation
```

`ExecutionRequest` contains the parsed process settings, policy, telemetry settings, and execution flags.

`StateAwareOperation` says which lifecycle action is being performed:

```rust
pub enum StateAwareOperation {
    Provision(StateAwareProvision),
    Start { sandbox_id: String },
    Exec { sandbox_id: String },
    Stop { sandbox_id: String },
    Deprovision { sandbox_id: String },
}
```

Before the PR, MXC created `StateAwareOperation` by reading `phase` and `sandboxId` from JSON. After the PR, MXC creates it from the SDK method or command-line arguments.

The internal result is the same. Only the source of the action and sandbox ID changes.

## C# Provision Control Flow

The public C# call already used a dedicated provision method, so caller code
does not change in this example.

**Before PR #1219:**

```csharp
var provisioned = MxcLifecycle.ProvisionSandbox(
    StateAwareContainment.IsolationSession,
    new IsolationSessionProvisionOptions(new StateAwareNetworkPolicy
    {
        Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
        Ingress = new NetworkIngressPolicy
        {
            Default = NetworkAction.Allow,
            HostLoopback = NetworkAction.Allow,
        },
    }));

SandboxId sandboxId = provisioned.SandboxId;
```

**After PR #1219:**

```csharp
var provisioned = MxcLifecycle.ProvisionSandbox(
    StateAwareContainment.IsolationSession,
    new IsolationSessionProvisionOptions(new StateAwareNetworkPolicy
    {
        Egress = new NetworkEgressPolicy { Default = NetworkAction.Allow },
        Ingress = new NetworkIngressPolicy
        {
            Default = NetworkAction.Allow,
            HostLoopback = NetworkAction.Allow,
        },
    }));

SandboxId sandboxId = provisioned.SandboxId;
```

The difference is below the public C# method. Before the PR,
`BuildProvisionEnvelope` wrote `"phase": "provision"` into the JSON. After the
PR, `RunEnvelopePhase` passes `ProvisionOperation` as a separate native
argument, and the JSON no longer contains `phase`.

```text
C# application
    |
    v
MxcLifecycle.ProvisionSandbox(containment, options) (sdk/dotnet/Microsoft.Mxc.Sdk/MxcLifecycle.cs:63)
    |
    |-- builds configuration JSON
    |-- passes ProvisionOperation separately
    |   (RunEnvelopePhase, MxcLifecycle.cs:697)
    v
mxc_ffi: mxc_state_aware(JSON, Provision, no sandbox ID) (src/ffi/mxc_ffi/src/state_aware.rs:140)
    |
    | state_aware_inner maps the integer to LifecycleOperation::Provision
    | (state_aware.rs:173)
    v
mxc-sdk: run_lifecycle_operation (src/core/mxc-sdk/src/lib.rs:208)
    |
    v
mxc_engine: run_state_aware_operation_json (src/core/mxc_engine/src/state_aware.rs:458)
    |
    v
Parser builds ParsedStateAwareRequest (src/core/wxc_common/src/config_parser.rs:635, 2099, 2123)
    |
    +-- ExecutionRequest
    |     process, policy, telemetry, and flags parsed from JSON
    |
    +-- StateAwareOperation::Provision(...)
          action supplied by the Provision API call
    |
    |
    |  PR BEHAVIOR CHANGES END HERE
    |  ----------------------------------------------
    |  Existing routing, binding, and dispatch below
    v
mxc_engine::run_state_aware (src/core/mxc_engine/src/state_aware.rs:158)
    |
    v
Typed WSLC backend binding: bind_wslc (src/core/wxc_common/src/state_aware_binding.rs:202)
    |
    v
Dispatcher matches Provision: dispatch_state_aware (src/core/wxc_common/src/state_aware_dispatch.rs:99)
    |
    v
backend.provision(&request, config) (src/core/wxc_common/src/state_aware_dispatch.rs:111)
```

`StateAwareOperation` and `ExecutionRequest` are built alongside each other; one
does not turn into the other. The operation tells the dispatcher which backend
method to call. The `ExecutionRequest` supplies the common settings passed to
that method. The PR changes how `ParsedStateAwareRequest` is produced, but it
does not change the existing backend routing, typed binding, production
dispatcher, `StatefulSandboxBackend` trait, or backend method calls below that
point. The dispatcher file has test updates only.

Line numbers above refer to PR commit `0d53d7f8`.

## Dispatcher and Backend Interfaces Are Unchanged

The dispatcher continues to split the parsed request into the common `ExecutionRequest` and the selected operation:

```rust
let (request, operation) = bound.into_parts();

match operation {
    BoundStateAwareOperation::Provision(config) => {
        backend.validate_provision(&request, config.as_ref())?;
        let result = backend.provision(&request, config)?;
    }
    BoundStateAwareOperation::Exec { sandbox_id, config } => {
        backend.validate_exec(&sandbox_id, &request, config.as_ref())?;
        let handle = backend.exec(&sandbox_id, &request, config, stdio)?;
    }
    // start, stop, and deprovision follow the same pattern
}
```

This code remains in:

```text
src/core/wxc_common/src/state_aware_dispatch.rs
```

The `StatefulSandboxBackend` trait is also unchanged. Backends still implement:

```rust
provision(&ExecutionRequest, provision_config)
start(&sandbox_id, &ExecutionRequest, start_config)
exec(&sandbox_id, &ExecutionRequest, exec_config, stdio)
stop(&sandbox_id, &ExecutionRequest, stop_config)
deprovision(&sandbox_id, &ExecutionRequest, deprovision_config)
```

There was never a phase field inside `ExecutionRequest`. The backend knows the action because the dispatcher calls the corresponding trait method.

Each lifecycle call gets its own `ExecutionRequest`. For example, a provision call gets an `ExecutionRequest` built from the provision settings, while a later exec call gets a new `ExecutionRequest` built from the exec settings.

## Compatibility Impact

Callers that put `phase` or `sandboxId` in JSON must change:

- Use the matching SDK lifecycle method, or `--operation` on the command line.
- Pass the sandbox ID as a method argument or with `--sandbox-id`.
- Remove the `phase` and `sandboxId` fields from JSON.
- Move provision settings out of the old per-phase JSON layer.

The backend implementations do not need to learn a new dispatch model. They continue receiving the same common request and typed per-action configuration through the same `StatefulSandboxBackend` methods.

## Main Design Point

The PR changes the public input format, not the backend execution design:

```text
Before:
JSON chooses action → parser builds operation → dispatcher calls backend method

After:
SDK/CLI chooses action → engine builds operation → dispatcher calls backend method
```

Everything from the dispatcher onward remains substantially the same.
