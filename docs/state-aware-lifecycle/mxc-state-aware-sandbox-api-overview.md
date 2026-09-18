# MXC Sandbox Lifecycle API Overview

MXC supports persistent sandbox lifecycles through five explicit operations:
`provision`, `start`, `exec`, `stop`, and `deprovision`.

The operation is selected by the SDK method or by
`wxc-exec --operation <operation>`. Sandbox identity is passed as a method
argument or with `--sandbox-id <id>`. Neither value is stored in configuration
JSON.

## Request model

All lifecycle operations use the operation-neutral `0.9.0-alpha` config shape.
The schema permits `process` to be omitted so provision, start, stop, and
deprovision can use the same document shape. One-shot execution and lifecycle
exec require `process.commandLine` during operation-specific validation.

- Provision requires `containment` and rejects a sandbox ID.
- Start, exec, stop, and deprovision require a sandbox ID and derive the backend
  from its prefix.
- Exec requires `process.commandLine`.
- Start, stop, and deprovision reject process and policy fields they cannot
  honor.
- Legacy JSON fields `phase` and `sandboxId` are rejected.

Provision settings live directly under the backend object:

```json
{
  "version": "0.9.0-alpha",
  "containment": "wslc",
  "experimental": {
    "wslc": {
      "image": "alpine:latest"
    }
  }
}
```

An exec config contains the process but not the operation or ID:

```json
{
  "version": "0.9.0-alpha",
  "process": {
    "commandLine": "echo hello"
  }
}
```

## Public APIs

The TypeScript SDK exposes `provisionSandbox`, `startSandbox`,
`execInSandbox`, `execInSandboxAsync`, `stopSandbox`, and
`deprovisionSandbox`.

The Rust SDK exposes `sandbox::provision`, `sandbox::start`, `sandbox::exec`,
`sandbox::exec_attached`, `sandbox::stop`, and `sandbox::deprovision`.

The .NET SDK exposes the corresponding `MxcLifecycle` methods.

`provision` returns an opaque `SandboxId`. Callers persist that ID and pass it
to subsequent operations. MXC routes recognized prefixes to the appropriate
backend:

| Prefix | Backend |
|---|---|
| `iso:` | IsolationSession |
| `wsb:` | Windows Sandbox |
| `wslc:` | WSL Container |

## Command-line example

```powershell
wxc-exec.exe --experimental --operation provision provision.json
wxc-exec.exe --experimental --operation start --sandbox-id wslc:... operation.json
wxc-exec.exe --experimental --operation exec --sandbox-id wslc:... exec.json
wxc-exec.exe --experimental --operation stop --sandbox-id wslc:... operation.json
wxc-exec.exe --experimental --operation deprovision --sandbox-id wslc:... operation.json
```

See [MXC Sandbox Lifecycle API](mxc-state-aware-sandbox-api.md) for the complete
contract and examples.
