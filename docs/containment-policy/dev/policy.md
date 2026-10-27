# Containment policy language: development (1.1.0-alpha)

**Status:** Mutable development contract; may change before publication.
Use `"version": "1.1.0-alpha"` in MXC request JSON. The [generated JSON
schema](../../../schemas/dev/mxc-config.schema.1.1.0-alpha.json) is the
machine-readable field reference. This guide describes create-and-run requests
and container lifecycle operations independently of other documents.
High-level v1 SDK APIs still target published `1.0.0`; to use development-only
fields or backends, submit an exact development JSON request. Selecting the
version does not authorize an experimental backend; that requires a separate
runtime opt-in (for example, `--experimental` in the executor).

The request is a closed JSON object: unknown fields and unsupported fields for
the selected phase are rejected. `$schema` (a string for editor validation) and
`_comment` (a human-readable annotation) are allowed at the top level. JSON
does not permit comments. A schema-valid request may still be rejected if the
selected backend or host cannot enforce it.

## Create-and-run requests

Omit `phase` and `sandboxId` to create a sandbox, execute a process, and complete
the run in one request. Both `version` and `process.commandLine` are required;
`commandLine` must be non-empty:

```json
{
  "version": "1.1.0-alpha",
  "containment": "process",
  "process": { "commandLine": "echo hello" }
}
```

Replace the illustrative command with an executable available in the selected
sandbox.

| Top-level field | Meaning |
|---|---|
| `version` | Required exact string `1.1.0-alpha`. |
| `process` | Required command and optional execution settings (below). |
| `containment` | Optional backend selection; defaults to the host's native process sandbox. |
| `containerId` | Optional externally assigned container ID; use distinct IDs for concurrent Windows policy mutations. |
| `filesystem`, `network`, `ui` | Cross-cutting policy sections (below). An omitted section is not proof that every backend enforces a restriction. |
| `runtimeConfig` | Runtime settings, including a caller-managed network proxy. |
| `lifecycle` | Optional `destroyOnExit` (default `true`) and `preservePolicy` (default `false`) booleans. |
| `fallback` | Optional `allowDaclMutation` boolean accepted for 1.x compatibility and ignored. Removing this accepted field requires a new major contract. |
| `telemetry` | Optional `enabled` boolean. On Windows, emission also requires MXC-owned user consent and a permitting administrative policy. |
| `processContainer`, `lxc`, `seatbelt`, `wslc`, `windowsSandbox`, `hyperlight` | Backend-specific settings; only the section matching the selected backend is accepted. |
| `test` | Optional development-only placeholder with an optional string `message`; it has no policy enforcement effect. |

### Process and filesystem

| Field | Type and meaning |
|---|---|
| `process.commandLine` | Required non-empty string; command to run (guest source code for Hyperlight, a guest shell command for NVX MicroVM). |
| `process.cwd` | Optional string; explicit working directory. An unusable path fails rather than falling back. If omitted, each backend chooses its own usable default, not necessarily the caller's directory. Hyperlight rejects an explicit working directory; MicroVM uses a guest path, as described in the [NVX guide](../../backends/nvx/nvx.md#working-directory-and-environment). |
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
Hyperlight checks denied paths against its mounted grants. See the
[NVX capability table](../../backends/nvx/nvx.md#supported-operations-and-policy)
for MicroVM filesystem and environment support. Path strings use the selected
host/backend's conventions.

### Network and UI

Network policy is directional. Omitted `network`, `network.egress`, or
`network.egress.default` resolves to egress `"deny"`. Both
`network.ingress.default` and `network.ingress.hostLoopback` independently
default to `"deny"`. Actions are `"allow"` or `"deny"`:

```json
{
  "version": "1.1.0-alpha",
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
Seatbelt on macOS. `"vm"` resolves to Windows Sandbox on Windows. Explicit
values are `"processcontainer"`, `"lxc"`, `"bubblewrap"`, `"seatbelt"`,
`"windows_sandbox"`, `"microvm"`, `"hyperlight"`, `"isolation_session"`,
and `"wslc"`. The old `appcontainer` / `appContainer` and `macos_sandbox`
spellings are not accepted. Windows Sandbox, MicroVM, and Hyperlight require
experimental authorization and suitable host/build support.

| Section | Supported fields and important constraints |
|---|---|
| `processContainer` | `leastPrivilege` (boolean), `capabilities` (array of single capability names, no commas), `learningMode` (boolean), `captureDenials` (`mode`: `block` or `allow`, default `block`; optional `outputPath` and `retainEtl`), `filesystem.enumeratePaths` (array of paths), `network.allowedProxyPeer` (proxy peer identity), and `ui` (below). `enumeratePaths` needs host support and cannot combine with `leastPrivilege`. `captureDenials.mode: "allow"` permits and records otherwise denied access. |
| `processContainer.ui` | Optional `isolation` (`container`, `desktop`, `handles`, `atoms`), `desktopSystemControl` and `ime` booleans, and `systemSettings` (`none`, `parameters`, `display`, `all`). |
| `lxc` | `distribution` and `release` strings, both required if this section is present. |
| `seatbelt` | Optional `profileOverride` (raw profile), `guiAccess`, `nestedPty`, `keychainAccess` (booleans), and `extraMachLookups` (string array). |
| `wslc` | Optional `image`, `imageTarPath`, `storagePath`, `targetOs` (strings), `cpuCount` and `memoryMb` (non-negative integers), `gpu` (boolean), and `portMappings` (array of `windowsPort` / `containerPort`, 1-65535, optional `protocol`: TCP only). These are create-and-run settings. |
| `windowsSandbox` | Optional `idleTimeoutMs` (non-negative integer milliseconds), legacy `idleTimeout` (non-negative integer), and `daemonPipeName` (string). Compatibility fields, not live controls of the current execution path. |
| `hyperlight` | Optional `runtime`: `agent` (default), `python`, `python-shell`, `node`, `bash`, or `dotnet-jit`. The command line supplies source for that guest runtime. |

For Seatbelt, `profileOverride` replaces the generated profile, so
`filesystem`, `network`, and `ui` restrictions in the request are not
incorporated; see the [Seatbelt backend guide](../../backends/seatbelt/seatbelt-backend.md)
for details.

WSLc networking supports only all-deny isolated or all-allow bridged
`egress.default` / `ingress.default` / `ingress.hostLoopback` postures; it
rejects mixed postures and per-destination rules. IsolationSession cannot
restrict networking: its request must explicitly set **all three** actions to
`"allow"` and cannot carry rules or a proxy. An empty or absent `network`
section is rejected for IsolationSession. MicroVM networking support is
described in the [NVX capability table](../../backends/nvx/nvx.md#supported-operations-and-policy).
Hyperlight rejects a supplied `network` section. Windows Sandbox
create-and-run execution blocks networking when
`network` is omitted; it rejects supplied `network.egress` or
`network.ingress` sections (even empty or deny-only), host filters, and
proxies. Backend support is not implied by a field appearing in this
development contract.

## Container lifecycle operations

Set `phase` to `provision`, `start`, `exec`, `stop`, or `deprovision`. These
operations exist for **IsolationSession, WSLc, and Windows Sandbox** in this
contract. `provision` requires a concrete `containment` and must omit
`sandboxId`; subsequent phases require the ID returned by provision
(`iso:...`, `wslc:...`, or `wsb:...`) and infer the backend from its prefix.
WSLc also supports `provision-session` and `deprovision-session`, which require
`containment: "wslc"` and carry no `sandboxId`. Every phase requires `version`;
all admit optional `$schema`, `_comment`, and `telemetry.enabled`.

| Phase | Allowed request fields besides the common fields |
|---|---|
| `provision` / `isolation_session` | Required all-allow `network`; optional `isolationSession.provision.appId` (string). No filesystem, UI, or proxy. |
| `provision-session` / `wslc` | Optional `wslc.provisionSession.cpuCount`, `memoryMb`, and `gpu`; no process, filesystem, network, or UI policy. |
| `provision` / `wslc` | Optional `filesystem`, `network`, and `wslc.provision.image`, `imageTarPath`, `portMappings`, or `sessionId`. Port mappings require all-allow bridged networking; CPU/memory/GPU sizing belongs to the session, not the sandbox. No storage-path override. |
| `provision` / `windows_sandbox` | Optional `filesystem` only. No network, UI, proxy, or backend-specific settings; provision stores the immutable filesystem policy. Requires experimental authorization. |
| `start`, `stop`, `deprovision` | Required `sandboxId`; no process or policy sections. |
| `exec` | Required `sandboxId` and `process` (non-empty `commandLine`); optional `network` and `runtimeConfig` in the JSON shape. All three backends reject supplied network policy at exec and inherit their provision posture. IsolationSession and Windows Sandbox reject a proxy; WSLc accepts an exec proxy. |
| `deprovision-session` / `wslc` | Required `sessionId`; no process, filesystem, network, UI, or backend configuration. |

### WSLc sessions

A session is one WSL2 utility VM shared by the sandboxes placed in it.
`provision-session` sets VM sizing; it does not create a sandbox:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision-session",
  "containment": "wslc",
  "wslc": {
    "provisionSession": { "cpuCount": 2, "memoryMb": 4096, "gpu": false }
  }
}
```

| Sizing field | Meaning |
|---|---|
| `cpuCount` | Optional non-negative integer, up to `4294967295`; a positive value cannot exceed the host's logical processor count. Omitted or `0` uses the SDK default. |
| `memoryMb` | Optional non-negative integer; the backend rejects values above `4294967295`. A ceiling, not a reservation, so it may exceed installed host RAM. Omitted or `0` uses the SDK default. |
| `gpu` | Optional boolean, default `false`; enables GPU passthrough when supported by the host runtime. |

Success returns `{"result":{"sessionId":"wslcsess:0123456789abcdef0123456789abcdef"}}`.
The ID shown here is illustrative: use the returned value, which has exactly
32 lowercase hexadecimal digits after `wslcsess:`, in later requests.
Treat it as an opaque bearer capability and keep it out of logs.

Place a sandbox in that session with `wslc.provision.sessionId`:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "wslc",
  "wslc": {
    "provision": {
      "image": "alpine:latest",
      "sessionId": "wslcsess:0123456789abcdef0123456789abcdef"
    }
  }
}
```

The VM's CPU, memory, and GPU settings apply to every sandbox in the session,
not as per-sandbox quotas. Omitting `sessionId` joins the implicit shared
session, preserving existing behavior. An isolated provision needs its image
already cached in the selected session's store or supplied as `imageTarPath`.

After deprovisioning every sandbox in the session, release it:

```json
{
  "version": "1.1.0-alpha",
  "phase": "deprovision-session",
  "containment": "wslc",
  "sessionId": "wslcsess:0123456789abcdef0123456789abcdef"
}
```

Release returns `{"result":{}}`. A session still holding sandboxes or work
is refused rather than cascading deletion; the implicit session cannot be
released explicitly. Unused sessions can expire before explicit release.
Malformed IDs return `malformed_id`; a valid ID that no longer names a
session returns `not_provisioned`.

A dry run validates either session request without contacting the daemon,
minting an ID, creating a VM or store, or reserving capacity, and returns
`{"result":{}}`. Neither session phase is available through typed SDK V1,
which still targets contract `1.0.0`.

### Sandbox examples

Example WSLc provision with a container-specific TCP port mapping:

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
      "image": "alpine:latest",
      "portMappings": [{ "windowsPort": 8080, "containerPort": 80 }]
    }
  }
}
```

Port mappings use non-zero ports from 1 to 65535, optionally specify
`"protocol": "tcp"`, and reject duplicate `windowsPort` entries. They are
installed when the container starts; a busy host port fails `start`.
For Windows Sandbox, a complete provision request is:

```json
{
  "version": "1.1.0-alpha",
  "phase": "provision",
  "containment": "windows_sandbox",
  "filesystem": { "readonlyPaths": ["C:\\data"] }
}
```

The mapped `C:\data` directory must already exist on the host.

An `exec` request after provision and start looks like this (replace the ID
with the returned one):

```json
{
  "version": "1.1.0-alpha",
  "phase": "exec",
  "sandboxId": "wsb:abcd1234",
  "process": { "commandLine": "echo hello" }
}
```

When calling the executor directly, pass `phase` via `--operation`, `sandboxId`
via `--container-id`, and a release's `sessionId` via `--session-id` instead
of putting those fields in the JSON file; the executor inserts them before
parsing. Placement's nested `wslc.provision.sessionId` stays in JSON.
JSON library/FFI calls include routing fields as shown above.
