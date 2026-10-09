# MXC Containment Policy Spec v1.0.0

> **Audience:** MXC consumers

`1.0.0` is the current **stable** containment policy contract. High-level
[Rust](../../api-reference/rust/v1/README.md),
[.NET](../../api-reference/dotnet/v1/README.md), and
[Node](../../api-reference/node/v1/README.md) V1 SDK APIs select this contract
automatically. Its published
[schema](../../../schemas/stable/mxc-config.schema.1.0.0.json) is immutable.

## Policy behavior

| Section | Policy and configuration |
|---|---|
| `filesystem` | `readwritePaths`, `readonlyPaths`, and `deniedPaths` specify path grants and denials; each backend also provides its documented baseline access. |
| `network.egress` | `default` (`allow` or `deny`) and direct `allow`/`deny` rules with IP/CIDR destinations and optional protocol/port selectors. Deny wins over allow; the default is `deny`. |
| `network.ingress` | `default` controls private-network inbound traffic; `hostLoopback` controls bidirectional host-loopback traffic. Both independently deny by default. |
| `runtimeConfig.networkProxy` | Runtime HTTP/S proxy setting. ProcessContainer, Bubblewrap, and Seatbelt use deny-default egress with empty direct rule lists. WSLC requires bridged networking (all three directional defaults `allow`) and uses a cooperative proxy. See the [WSLC network guide](../../backends/wslc/wsl-container-getting-started.md#network-proxy-cooperative-unprivileged). |
| `ui` | `disable: true`, `clipboard: "none"`, and `injection: false` are the defaults; the selected backend's guide describes its UI enforcement. |
| `fallback.allowDaclMutation` | Consents to the host-DACL filesystem fallback; defaults to `true`. |
| `lifecycle` | `destroyOnExit` and `preservePolicy` govern cleanup. |
| `process` | Optional `cwd`, `env`, `inheritDefaultEnv`, and `timeout` (milliseconds). The backend environment applies when `env` is absent; supplied `env` (including `[]`) replaces it, and `inheritDefaultEnv: true` layers supplied entries over it. |

Backend-specific fields, for example `processContainer.filesystem.enumeratePaths`
or `wslc.image`, go in the corresponding backend section. Exact-contract
acceptance defines the request shape; the selected backend may apply, reject,
or ignore an accepted field. Check its guide and the
[UI policy guidance](../../schema.md#ui-policy) to confirm enforcement before
relying on a restriction.

## Directional network policy

The defaults for egress, private-network ingress, and host loopback are all
`deny`. `ingress.hostLoopback` resolves independently of `ingress.default`.
Direct egress rules match numeric IP/CIDR destinations (`to`) and optional
protocol and destination-port selectors (`ports`). Destination filtering
uses numeric IP/CIDR rules; application-layer filtering belongs to the
caller-managed proxy. The default `to` matches both IP families, and the
default `ports` matches all protocols and ports. Supplied arrays contain
at least one selector. `to[].except` excludes contained CIDRs;
`ports[].protocol` accepts `tcp`, `udp`, `icmp`, or `any`. `port` is 1–65535;
`endPort` is an inclusive range end that requires `port` and must be greater
than or equal to it. ICMP selectors use the protocol alone. Explicit deny
rules take precedence over allow rules.

For example, this *direct-egress* request allows TCP/443 to the illustrative
`192.0.2.0/24` range except `192.0.2.7`, and denies everything else. The
example command prints a message to illustrate the policy shape.

```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "process": { "commandLine": "cmd.exe /c echo direct-egress policy" },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{
        "to": [{ "cidr": "192.0.2.0/24", "except": ["192.0.2.7/32"] }],
        "ports": [{ "protocol": "tcp", "port": 443 }]
      }]
    },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

Each backend enforces a supported subset of the shared network policy:

| Backend | Supported posture | Requirements |
|---|---|---|
| [ProcessContainer](../../backends/process-container/networking.md) | PSEC-capable hosts enforce direct CIDR/port rules and loopback proxy endpoints; AppContainer maps direction defaults to capabilities. | Proxy use requires `ingress.default: "allow"`. Identity-scoped proxies set `processContainer.network.allowedProxyPeer` and `hostLoopback: "deny"`; identity-less host proxies use `hostLoopback: "allow"` (a weaker development/testing posture). |
| [Bubblewrap](../../backends/bwrap/bubblewrap-backend.md) | Direct CIDR/port rules in a private network namespace, or a caller-managed loopback proxy. | Set `ingress.default` and `hostLoopback` to `deny`. |
| [LXC](../../backends/lxc/lxc-backend.md) | Direct CIDR/port rules for ordinary IP traffic. | Set private-network ingress and host loopback to `deny`. Attached workloads retain `CAP_NET_RAW`, so `AF_PACKET` traffic bypasses the namespace `OUTPUT` chain; these rules are not a confinement guarantee for untrusted workloads. |
| [Seatbelt](../../backends/seatbelt/seatbelt-backend.md) | Default egress actions or a loopback proxy endpoint. | `hostLoopback: "allow"` requires `ingress.default: "allow"`; its guide describes the limits of inbound enforcement. |
| [WSLC](../../backends/wslc/wsl-container-getting-started.md#network-configuration) | Isolated all-`deny`, or bridged all-`allow` networking with an optional cooperative HTTP/S proxy. | The proxy sets workload environment variables; direct sockets follow the bridged posture. |
| [IsolationSession](../../schema.md#isolationsession-unrestricted-networking-09) | Unrestricted networking. | Explicitly set all three direction defaults to `allow`. |

Choose either direct rules or a runtime proxy as the connectivity model.
In proxy mode, the caller-managed proxy owns destination filtering; the
backend guide describes its raw-socket enforcement and host requirements.

## State-aware policy

This version supports IsolationSession and WSLC lifecycle operations.
IsolationSession uses unrestricted networking: one-shot and provision
requests explicitly set egress, ingress, and host loopback to `allow`.
See the [container lifecycle guide](../../container-lifecycle.md)
for the public API and phase order, and the backend guides for phase-specific
policy support. Raw JSON callers can consult the
[wire contract](../../development/architecture/container-lifecycle.md#7-wire-contract).

## Changes from 0.9.0-alpha

The [0.9 contract](../0.9.0/policy.md) and 1.0 contract share their canonical
field and value spellings and their one-shot, IsolationSession, and WSLC
request families. Version 1.0 uses the canonical `processcontainer` /
`processContainer` and `seatbelt` spellings; 0.9 also accepts
`appcontainer` / `appContainer` and `macos_sandbox` aliases. For `vm`,
`microvm`, `hyperlight`, and Windows Sandbox requests, use the
[development contract](../v1-dev/policy.md).

## Typed SDK authoring

The V1 SDKs author policy as typed request data and select exact `1.0.0`
internally. For example, Node uses `command`, `filesystem`, and `network`
properties, and the SDK supplies the exact `version` and `process.commandLine`:

```typescript
import { run, type ContainerRequest } from '@microsoft/mxc-sdk/v1';

const request: ContainerRequest = {
  command: process.platform === 'win32'
    ? 'cmd.exe /c echo hello'
    : '/bin/sh -c "echo hello"',
  containment: { type: 'process' },
  filesystem: { readonlyPaths: [process.cwd()] },
  workingDirectory: process.cwd(),
  network: {
    egress: { default: 'deny' },
    ingress: { default: 'deny', hostLoopback: 'deny' },
  },
};
const result = await run(request);
console.log(result.stdout);
```

`process` selects the host-native process backend. The working directory is
granted read-only here; replace it with paths appropriate for your workload.
See the [Rust](../../api-reference/rust/v1/types.md),
[.NET](../../api-reference/dotnet/v1/types.md), and
[Node](../../api-reference/node/v1/types.md) V1 references for each language's
policy types and operation signatures.

## Raw JSON authoring

Raw one-shot requests require `"version": "1.0.0"` and a non-empty
`process.commandLine`. The default `containment` selects the abstract `process`
intent: `processcontainer` on Windows, `bubblewrap` on Linux, and `seatbelt`
on macOS. The closed selections are `process`, `processcontainer`, `lxc`,
`bubblewrap`, `seatbelt`, `isolation_session`, and `wslc`. Supply backend
settings under the section matching the selected backend.

```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "process": { "commandLine": "cmd.exe /c echo hello" },
  "filesystem": { "readonlyPaths": ["C:\\inputs"] },
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

State-aware requests select a closed `provision`, `start`, `exec`, `stop`, or
`deprovision` root with `phase`. Provision specifies
`containment`; later phases use the returned `sandboxId`. Exec also
requires `process`.
