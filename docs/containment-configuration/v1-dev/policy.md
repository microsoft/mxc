# MXC Containment Policy (V1 development: 1.1.0-alpha)

> **Audience:** MXC consumers and developers

`1.1.0-alpha` is the **mutable development** policy contract. It retains
the restrictions of the published
[1.0.0 policy](../1.0.0/policy.md) and adds development-only backend surfaces.
The [V1 SDKs](../README.md#authoring-a-policy) still target published `1.0.0`;
raw configuration selects this development contract.

## Shared policy

The development contract retains the canonical [1.0.0 policy](../1.0.0/policy.md):
one-shot requests require a non-empty `process.commandLine`; the common
`filesystem`, directional `network`, `runtimeConfig.networkProxy`, `ui`,
`fallback`, `lifecycle`, and `process` fields keep their meanings. The exact
development contract defines its JSON fields; `--experimental` separately
authorizes backend execution. As in 1.0.0, the default `containment` selects
the host-native `process` backend, and WSLC uses bridged networking for its
cooperative proxy. The selected backend may apply, reject, or ignore an
accepted field; check its guide and the
[UI policy guidance](../../schema.md#ui-policy) before relying on enforcement.

## Development-only request surfaces

| Surface | What the exact contract accepts |
|---|---|
| One-shot `vm` | Abstract VM intent, resolving to `windows_sandbox` on Windows. |
| One-shot `windows_sandbox` | Explicit Windows Sandbox selection; optional `windowsSandbox` compatibility settings. See its [backend policy limits](../../backends/windows-sandbox/windows-sandbox.md#policy-support). |
| One-shot `microvm` | NanVix MicroVM selection. See the [NanVix guide](../../backends/nanvix/nanvix.md) for enforceable policy. |
| One-shot `hyperlight` | Hyperlight selection with optional `hyperlight.runtime` guest choice. See its [backend guide](../../backends/hyperlight/hyperlight-backend.md) for supported policy. |
| `windows_sandbox` state-aware | Closed `provision`, `start`, `exec`, `stop`, and `deprovision` lifecycle roots; filesystem policy is supplied at provision and is immutable thereafter. |
| `wslc` state-aware `provision` | Optional `wslc.provision.portMappings` forwards host-loopback TCP ports to this container; it requires bridged networking. See the [WSLC lifecycle guide](../../backends/wslc/wslc-state-aware.md#port-mappings). |
| `test` | Development-only placeholder for exercising feature plumbing. |

The published IsolationSession and WSLC lifecycle operations remain available,
subject to their phase-specific policy checks. For lifecycle semantics, see
the [consumer lifecycle guide](../../container-lifecycle.md); backend guides
cover phase-specific policy support. Raw JSON callers can consult the
[wire contract](../../development/architecture/container-lifecycle.md#7-wire-contract).

The WSLC port-mapping field belongs to this development contract's
state-aware provision request. The typed V1 SDKs target published `1.0.0`.
Mappings use unique host ports from 1 through 65535, container ports from
1 through 65535, and TCP; they are installed at `start` and listen on host
loopback.

**Contract acceptance and execution authorization are separate.** Selecting MicroVM,
Hyperlight, or Windows Sandbox (including the `vm` intent on Windows) requires
the runtime `--experimental` option (or the equivalent raw API option).
Backend validation still checks policy and host support before execution. See
[versioning](../../development/architecture/versioning.md#experimental-flag).

## Raw JSON authoring

Raw requests must declare `"version": "1.1.0-alpha"` and match the mutable
[development schema](../../../schemas/dev/mxc-config.schema.1.1.0-alpha.json).
Its accepted shape can change before publication; the current SDK V1 target
remains `1.0.0`. For example, one-shot Windows Sandbox execution:

```json
{
  "version": "1.1.0-alpha",
  "containment": "windows_sandbox",
  "process": {
    "commandLine": "powershell -NoProfile -Command \"Write-Output 'hello'\"",
    "timeout": 60000
  }
}
```

Windows Sandbox state-aware provision can supply a filesystem grant:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "windows_sandbox",
  "filesystem": { "readonlyPaths": ["C:\\inputs"] }
}
```

For WSLC port forwarding, provision with an explicit bridged network posture
and the development version:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "wslc",
  "network": {
    "egress": { "default": "allow" },
    "ingress": { "default": "allow", "hostLoopback": "allow" }
  },
  "wslc": {
    "provision": {
      "portMappings": [{ "windowsPort": 8080, "containerPort": 80 }]
    }
  }
}
```

Later phases use the returned `sandboxId`; `exec` also supplies `process`.
