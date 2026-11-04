# Containment policy language: 0.9.0-alpha

**Status:** Published, immutable contract; minimum supported version.
Use `"version": "0.9.0-alpha"` in MXC request JSON. The [exact JSON
schema](../../../schemas/stable/mxc-config.schema.0.9.0-alpha.json) is the
machine-readable field reference. This document describes both create-and-run
requests and container lifecycle operations without requiring another guide.
The version includes the `-alpha` suffix: `"0.9.0"` is not registered.

The request is a closed JSON object: unknown fields and unsupported fields for
the selected phase are rejected. `$schema` (a string for editor validation) and
`_comment` (a human-readable annotation) are allowed at the top level. JSON
does not permit comments. A valid shape does **not** guarantee that a backend
can enforce it; unsupported policy fails at backend validation before sandbox
creation. Experimental backend authorization is separate from the version.

## Create-and-run requests

Omit `phase` and `sandboxId` to create a sandbox, execute a process, and complete
the run in one request. Both `version` and `process.commandLine` are required;
`commandLine` must be non-empty:

```json
{
  "version": "0.9.0-alpha",
  "containment": "process",
  "process": { "commandLine": "echo hello" }
}
```

Replace the illustrative command with an executable available in the selected
sandbox.

| Top-level field | Meaning |
|---|---|
| `version` | Required exact string `0.9.0-alpha`. |
| `process` | Required command and optional execution settings (below). |
| `containment` | Optional backend selection; defaults to the host's native process sandbox. |
| `containerId` | Optional externally assigned container ID; use distinct IDs for concurrent Windows policy mutations. |
| `filesystem`, `network`, `ui` | Cross-cutting policy sections (below). An omitted section is not proof that every backend enforces a restriction. |
| `runtimeConfig` | Runtime settings, including a caller-managed network proxy. |
| `lifecycle` | Optional `destroyOnExit` (default `true`) and `preservePolicy` (default `false`) booleans. |
| `fallback` | Optional `allowDaclMutation` boolean accepted for compatibility and ignored. Windows ProcessContainer uses native PSEC only. |
| `telemetry` | Optional `enabled` boolean. On Windows, emission also requires MXC-owned user consent and a permitting administrative policy. |
| `processContainer`, `appContainer`, `lxc`, `seatbelt`, `macos_sandbox`, `wslc` | Backend-specific settings; only the section matching the selected backend is accepted. The two legacy spellings are 0.9 aliases (see below). |

### Process and filesystem

| Field | Type and meaning |
|---|---|
| `process.commandLine` | Required non-empty string; command to run. |
| `process.cwd` | Optional string; explicit working directory. An unusable path fails rather than falling back. If omitted, each backend chooses its own usable default, not necessarily the caller's directory. MicroVM-style backends are not available in this contract. |
| `process.timeout` | Optional integer milliseconds, `0` to `4294967295`; `0` means no timeout. |
| `process.env` | Optional array of `KEY=VALUE` strings. Omitted uses the backend default; supplied entries replace it unless `inheritDefaultEnv` is `true`. |
| `process.inheritDefaultEnv` | Optional boolean (default `false`); layers supplied `env` entries over the backend default, with caller entries winning. |
| `filesystem.readwritePaths` | Optional array of paths granted read/write access. |
| `filesystem.readonlyPaths` | Optional array of paths granted read access. |
| `filesystem.deniedPaths` | Optional array of denied paths. Enforcement and interactions with grants are backend-specific. |

With `env: []` and `inheritDefaultEnv: false`, the request asks for an empty
environment. Windows ProcessContainer refuses a supplied environment missing
`SYSTEMROOT` or `LOCALAPPDATA`; IsolationSession cannot replace its user's
default environment and requires `inheritDefaultEnv: true` for supplied `env`.
Path strings use the selected host/backend's path conventions.

### Network and UI

Network policy is directional. Omitted `network`, `network.egress`, or
`network.egress.default` resolves to egress `"deny"`. Both
`network.ingress.default` and `network.ingress.hostLoopback` independently
default to `"deny"`. Actions are `"allow"` or `"deny"`:

```json
{
  "version": "0.9.0-alpha",
  "process": { "commandLine": "echo hello" },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{
        "to": [{ "cidr": "203.0.113.0/24" }],
        "ports": [{ "protocol": "tcp", "port": 443 }]
      }]
    },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

`egress.allow` and `egress.deny` are optional arrays of rules; deny wins over
allow. Each rule can specify `to` (numeric IPv4/IPv6 `cidr` entries with
optional `except` CIDR arrays) and `ports` (entries with optional `protocol`:
`tcp`, `udp`, `icmp`, or `any`; optional `port` from 1 to 65535 and optional
inclusive `endPort`, which requires `port`). An `icmp` selector cannot
specify `port` or `endPort`. An omitted `to` matches both IP families;
omitted `ports` matches all ports; omitted protocol means `any`. Rules are
direct network policy, not hostname filtering.

`runtimeConfig.networkProxy` is an optional HTTP/S proxy URL for a
caller-managed endpoint. Outside WSLc, its URL must use `localhost`,
`127.0.0.1`, or `[::1]` (a backend may support fewer of these). For WSLc
`exec`, the proxy must be reachable from the guest; the host's loopback
address is not reachable by using `localhost` inside the guest; `exec`
inherits the provisioned network posture. On other backends that accept a
proxy, `network.egress.default` must resolve to `"deny"`, and
`egress.allow` and `egress.deny` must have no rules. The proxy is responsible
for destination filtering. Backend enforcement of traffic to the proxy
differs: a cooperative proxy setting alone is not a guarantee that arbitrary
direct sockets are blocked. For ProcessContainer, a proxy requires
`network.ingress.default: "allow"`. An identity-scoped loopback proxy uses
non-blank `processContainer.network.allowedProxyPeer` with
`hostLoopback: "deny"`; omitting that peer requires `hostLoopback: "allow"`
and opens both host-loopback directions.

`ui.disable` (boolean, default `true`) disables UI; `ui.clipboard` defaults
to `"none"` and accepts `"none"`, `"read"`, `"write"`, or `"all"`;
`ui.injection` (boolean, default `false`) controls synthetic input. Windows
ProcessContainer and macOS Seatbelt implement UI policy. IsolationSession and
WSLc reject a supplied `ui` section and do not enforce its defaults when it
is absent. Do not assume another backend enforces an omitted UI policy.

### Backend selection and settings

`"process"` resolves to ProcessContainer on Windows, Bubblewrap on Linux, or
Seatbelt on macOS. This contract also accepts the explicit values
`"processcontainer"`, `"lxc"`, `"bubblewrap"`, `"seatbelt"`,
`"isolation_session"`, and `"wslc"`. On 0.9 only, `"appcontainer"` aliases
`"processcontainer"` and `"macos_sandbox"` aliases `"seatbelt"`; the matching
settings sections may be spelled `appContainer` and `macos_sandbox`
respectively. Do not supply both spellings of either section. VM, MicroVM,
Hyperlight, and Windows Sandbox are **not** selections in this contract.
Backend availability depends on the platform, build, and host capabilities.

| Section | Supported fields and important constraints |
|---|---|
| `processContainer` (or `appContainer`) | `leastPrivilege` (boolean), `capabilities` (array of single capability names, no commas), `learningMode` (boolean), `captureDenials` (`mode`: `block` or `allow`, default `block`; optional `outputPath` and `retainEtl`), `filesystem.enumeratePaths` (array of paths), `network.allowedProxyPeer` (proxy peer identity), and `ui` (below). `enumeratePaths` needs host support and cannot combine with `leastPrivilege`. `captureDenials.mode: "allow"` permits and records otherwise denied access. |
| `processContainer.ui` | Optional `isolation` (`container`, `desktop`, `handles`, `atoms`), `desktopSystemControl` and `ime` booleans, and `systemSettings` (`none`, `parameters`, `display`, `all`). |
| `lxc` | `distribution` and `release` strings, both required if this section is present. |
| `seatbelt` (or `macos_sandbox`) | Optional `profileOverride` (raw profile), `guiAccess`, `nestedPty`, `keychainAccess` (booleans), and `extraMachLookups` (string array). |
| `wslc` | Optional `image`, `imageTarPath`, `storagePath`, `targetOs` (strings), `cpuCount` and `memoryMb` (non-negative integers), `gpu` (boolean), and `portMappings` (array of `windowsPort` / `containerPort`, 1-65535, optional `protocol`: TCP only). These are create-and-run settings. |

For Seatbelt, `profileOverride` replaces the generated profile, so
`filesystem`, `network`, and `ui` restrictions in the request are not
incorporated; see the [Seatbelt backend guide](../../backends/seatbelt/seatbelt-backend.md)
for details.

WSLc networking supports only all-deny isolated or all-allow bridged
`egress.default` / `ingress.default` / `ingress.hostLoopback` postures; it
rejects mixed postures and per-destination rules. IsolationSession cannot
restrict networking: its request must explicitly set **all three** actions to
`"allow"` and cannot carry rules or a proxy. An empty or absent `network`
section is rejected for IsolationSession. Unsupported filesystem, network, or
UI policies are rejected by the selected backend, not silently applied.

## Container lifecycle operations

Set `phase` to `provision`, `start`, `exec`, `stop`, or `deprovision`. These
operations exist for **IsolationSession and WSLc only** in this contract.
`provision` requires `containment` and must omit `sandboxId`; subsequent
phases require the ID returned by provision (`iso:...` or `wslc:...`) and
infer the backend from its prefix. Every phase requires `version`; all admit
optional `$schema`, `_comment`, and `telemetry.enabled`.

| Phase | Allowed request fields besides the common fields |
|---|---|
| `provision` / `isolation_session` | Required all-allow `network`; optional `isolationSession.provision.appId` (string). No filesystem, UI, or proxy. |
| `provision` / `wslc` | Optional `filesystem`, `network`, and `wslc.provision.image` / `imageTarPath`. Provision port mappings are **not** available in 0.9. |
| `start`, `stop`, `deprovision` | Required `sandboxId`; no process or policy sections. |
| `exec` | Required `sandboxId` and `process` (non-empty `commandLine`); optional `network` and `runtimeConfig` in the JSON shape. Both backends reject supplied network policy at exec and inherit the provision posture. IsolationSession rejects a proxy; WSLc accepts an exec proxy. |

Example IsolationSession provision, acknowledging its unrestricted network:

```json
{
  "version": "0.9.0-alpha",
  "phase": "provision",
  "containment": "isolation_session",
  "network": {
    "egress": { "default": "allow" },
    "ingress": { "default": "allow", "hostLoopback": "allow" }
  }
}
```

An `exec` request after provision and start looks like this (replace the ID
with the returned one):

```json
{
  "version": "0.9.0-alpha",
  "phase": "exec",
  "sandboxId": "iso:0123456789abcdef0123456789abcdef",
  "process": { "commandLine": "echo hello" }
}
```

When calling the executor directly, pass routing fields via `--operation` and
`--container-id` instead of putting `phase` and `sandboxId` in the JSON file;
the executor inserts them before parsing. JSON library/FFI calls include
those fields as shown above.
