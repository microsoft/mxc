# MXC Sandbox Lifecycle API

MXC exposes five explicit sandbox lifecycle operations:

| Operation | Input identity | Purpose |
|---|---|---|
| `provision` | `containment` in config | Allocate a sandbox and return its opaque ID |
| `start` | Sandbox ID argument | Start a provisioned sandbox |
| `exec` | Sandbox ID argument plus `process.commandLine` | Run a workload in a started sandbox |
| `stop` | Sandbox ID argument | Stop the sandbox while retaining its provisioned state |
| `deprovision` | Sandbox ID argument | Release the sandbox |

The operation and sandbox ID are API or command-line arguments. They are not
properties in the 0.9 configuration document. The legacy top-level `phase` and
`sandboxId` properties are rejected.

## Configuration contract

Lifecycle calls use the same closed, operation-neutral `0.9.0-alpha` request
shape as one-shot execution. The schema makes `process` optional because it
cannot know which operation the caller selected out of band.

Operation-specific validation applies these requirements:

| Operation | `containment` | Sandbox ID argument | `process.commandLine` |
|---|---|---|---|
| `provision` | Required | Rejected | Rejected |
| `start` | Rejected | Required | Rejected |
| `exec` | Rejected | Required | Required |
| `stop` | Rejected | Required | Rejected |
| `deprovision` | Rejected | Required | Rejected |

One-shot execution also requires `process.commandLine`.

Provision-only backend settings are direct members of
`experimental.<backend>`:

```json
{
  "version": "0.9.0-alpha",
  "containment": "wslc",
  "filesystem": {
    "readwritePaths": ["C:\\work"]
  },
  "network": {
    "egress": { "default": "deny" },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  },
  "experimental": {
    "wslc": {
      "image": "alpine:latest",
      "imageTarPath": "C:\\images\\alpine.tar"
    }
  }
}
```

IsolationSession uses the same direct shape:

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
      "appId": "PFN:Contoso.App_8wekyb3d8bbwe"
    }
  }
}
```

Start, stop, and deprovision normally use:

```json
{
  "version": "0.9.0-alpha"
}
```

Exec carries the command:

```json
{
  "version": "0.9.0-alpha",
  "process": {
    "commandLine": "echo hello"
  }
}
```

## Executor CLI

`wxc-exec.exe` selects lifecycle behavior with `--operation`:

```powershell
wxc-exec.exe --experimental --operation provision provision.json
wxc-exec.exe --experimental --operation start --sandbox-id wslc:... operation.json
wxc-exec.exe --experimental --operation exec --sandbox-id wslc:... exec.json
wxc-exec.exe --experimental --operation stop --sandbox-id wslc:... operation.json
wxc-exec.exe --experimental --operation deprovision --sandbox-id wslc:... operation.json
```

For exec, trailing command arguments override `process.commandLine` using the
same quoting rules as one-shot execution:

```powershell
wxc-exec.exe --experimental --operation exec --sandbox-id wslc:... exec.json -- sh -lc "id"
```

Non-exec operations reject trailing command arguments. Provision rejects
`--sandbox-id`; all later operations require it.

Non-exec operations write one JSON response envelope to stdout:

```json
{ "result": { "sandboxId": "wslc:..." } }
```

or:

```json
{ "error": { "code": "malformed_request", "message": "..." } }
```

Exec preserves the selected streaming or attached stdio behavior.

## SDK surfaces

### Rust

```rust,no_run
use mxc_sdk::sandbox;

let provisioned = sandbox::provision(provision_json, true)?;
let sandbox_id = extract_sandbox_id(&provisioned);

sandbox::start(&sandbox_id, r#"{"version":"0.9.0-alpha"}"#, true)?;
let process = sandbox::exec(
    &sandbox_id,
    r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hello"}}"#,
    true,
)?;
sandbox::stop(&sandbox_id, r#"{"version":"0.9.0-alpha"}"#, true)?;
sandbox::deprovision(&sandbox_id, r#"{"version":"0.9.0-alpha"}"#, true)?;
# let _ = process;
# fn extract_sandbox_id(_: &str) -> String { String::new() }
# Ok::<(), mxc_sdk::Error>(())
```

`sandbox::exec_attached` is the terminal-attached exec variant.

### TypeScript

```typescript
const provisioned = await provisionSandbox('wslc', {
  image: 'alpine:latest',
  network: {
    egress: { default: 'deny' },
    ingress: { default: 'deny', hostLoopback: 'deny' },
  },
}, { experimental: true });

await startSandbox(provisioned.sandboxId, undefined, { experimental: true });
await execInSandboxAsync(
  provisioned.sandboxId,
  { process: { commandLine: 'echo hello' } },
  { experimental: true },
);
await stopSandbox(provisioned.sandboxId, undefined, { experimental: true });
await deprovisionSandbox(provisioned.sandboxId, undefined, { experimental: true });
```

### .NET

```csharp
var provisioned = MxcLifecycle.ProvisionSandbox(
    StateAwareContainment.Wslc,
    new WslcProvisionOptions { Image = "alpine:latest" });

MxcLifecycle.StartSandbox(provisioned.SandboxId);
var result = await MxcLifecycle.ExecInSandboxAsync(
    provisioned.SandboxId,
    "echo hello");
MxcLifecycle.StopSandbox(provisioned.SandboxId);
MxcLifecycle.DeprovisionSandbox(provisioned.SandboxId);
```

## Routing and identifiers

Provision routes from `containment`. Later operations route from the sandbox ID
prefix:

| Prefix | Backend |
|---|---|
| `iso:` | IsolationSession |
| `wsb:` | Windows Sandbox |
| `wslc:` | WSL Container |

The remainder of the ID is backend-owned and opaque. Callers must persist and
forward the complete value without parsing or modifying it.

## Backend contract

Backends implement `StatefulSandboxBackend` with typed associated
configuration for each operation. The parser:

1. Parses the exact operation-neutral 0.9 document.
2. Combines it with the out-of-band operation and sandbox ID.
3. Rejects fields that the selected operation cannot honor.
4. Produces `StateAwareInput` and binds it to the selected backend.
5. Runs backend validation before execution or dry-run success.

Backends retain their own lifecycle state. MXC does not persist a registry of
sandboxes between calls.

## Error model

Lifecycle errors use the shared `MxcError` codes, including
`malformed_request`, `unsupported_containment`, `unsupported_phase`,
`backend_unavailable`, `malformed_id`, `stale_id`, `not_provisioned`,
`not_started`, `already_started`, `policy_validation`, and `backend_error`.

Structural and operation-specific validation occurs before backend work.
Malformed or unknown sandbox ID prefixes fail before dispatch. Experimental
backends still require explicit opt-in.
