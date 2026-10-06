
## Configuration Schema

> **Audience:** MXC consumers and developers

MXC uses a JSON configuration file. The current stable schema is at
[`schemas/stable/mxc-config.schema.1.0.0.json`](../schemas/stable/mxc-config.schema.1.0.0.json).
For development, the exact schema at
[`schemas/dev/mxc-config.schema.1.1.0-alpha.json`](../schemas/dev/mxc-config.schema.1.1.0-alpha.json)
includes experimental features and may change without notice.

Editors that support JSON Schema will provide autocomplete and validation when
you add a `"$schema"` reference to your config file. Use the stable schema for
production configs and the dev schema when working on experimental features:

```json
// Production
"$schema": "./schemas/stable/mxc-config.schema.1.0.0.json"

// Development (experimental features)
"$schema": "./schemas/dev/mxc-config.schema.1.1.0-alpha.json"
```

### Directional networking (supported contracts)

Supported contracts from `0.9.0-alpha` use explicit egress and ingress policy
and put the loopback proxy endpoint in runtime configuration:

```json
{
    "version": "0.9.0-alpha",
    "network": {
        "egress": {
            "default": "deny",
            "allow": [{
                "to": [{ "cidr": "140.82.112.0/20" }],
                "ports": [{ "protocol": "tcp", "port": 443 }]
            }]
        },
        "ingress": {
            "default": "deny",
            "hostLoopback": "deny"
        }
    }
}
```

Direct egress rules and `runtimeConfig.networkProxy` select different
connectivity models and cannot be combined. Direct mode applies numeric CIDR,
protocol, and port rules where the backend supports them. A runtime proxy
names a caller-managed HTTP/S endpoint; the proxy owns any destination
filtering. Whether MXC can restrict raw-socket traffic to that endpoint
depends on the backend; see its guide. When `network`, `network.egress`, or
`network.egress.default` is omitted, `egress.default` resolves to `deny`.
Both ingress controls also default to `deny` when omitted. `hostLoopback`
resolves independently of `ingress.default`, so host-loopback access must
be requested explicitly.
A ProcessContainer proxy requires `ingress.default: "allow"`. Identity-scoped
proxies set a non-blank `allowedProxyPeer` and keep `hostLoopback: "deny"`;
identity-less host proxies omit `allowedProxyPeer` and require
`hostLoopback: "allow"`. The identity-less route is a weaker development/testing
deployment: it opens both host-loopback directions without restricting access
to a named proxy peer. It does not enforce a proxy-only host-loopback exception.

```json
{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "network": {
        "egress": { "default": "deny" },
        "ingress": {
            "default": "allow",
            "hostLoopback": "deny"
        }
    },
    "runtimeConfig": {
        "networkProxy": "http://127.0.0.1:8080"
    },
    "processContainer": {
        "network": {
            "allowedProxyPeer": "Contoso.Proxy_123"
        }
    }
}
```

The `defaultPolicy`, `enforcementMode`, `allowLocalNetwork`, `allowedHosts`,
`blockedHosts`, and `network.proxy` fields belonged to retired contracts.
No supported exact contract accepts them. Migrate existing policies to
directional fields and `runtimeConfig.networkProxy` rather than changing
the version string alone.

### IsolationSession unrestricted networking (0.9)

IsolationSession cannot restrict networking. Exact v0.9 requests must describe
that actual posture through the standard directional network fields:

```json
{
    "version": "0.9.0-alpha",
    "phase": "provision",
    "containment": "isolation_session",
    "network": {
        "egress": { "default": "allow" },
        "ingress": {
            "default": "allow",
            "hostLoopback": "allow"
        }
    }
}
```

All three directional values must be explicitly `allow`; omission defaults to
deny. Legacy network fields, rules, mixed postures, and proxies are rejected.
An absent or empty `network` object is rejected. Exact v0.9 IsolationSession
does not require an experimental execution opt-in.
Every complete request that carries a process requires a non-empty
`process.commandLine`. The Windows native CLI may accept a template without
that field when the command is supplied after `--`; `wxc-exec.exe` inserts or
replaces `process.commandLine` before schema and typed request validation. That
entry-point transform does not make the unmodified template a complete request
that can be executed independently.

### Full Schema

```json
{
    "version": "1.0.0",                    // Exact schema version. Minimum supported: "0.9.0-alpha"; current stable: "1.0.0".
    "containerId": "my-container",         // Externally assigned container ID
    "containment": "processcontainer",     // Backend (see table below)

    "lifecycle": {
        "destroyOnExit": true,             // Destroy container after execution
        "preservePolicy": false            // Retain container policies after exit if applicable
    },

    "process": {
        "commandLine": "python app.py",    // Required: command to execute
        "cwd": "C:\\workspace",            // Working directory (optional; when omitted each
                                           //  backend substitutes a granted directory rather
                                           //  than inheriting the launcher's — see
                                           //  "Working Directory" below)
        "env": ["MY_VAR=value"],           // Omitted: backend default; supplied: used verbatim
        "inheritDefaultEnv": true,         // Layer env on the backend default (0.9.0-alpha)
        "timeout": 30000                   // Timeout in ms (0 = no timeout)
    },

    "filesystem": {
        "readwritePaths": ["C:\\temp"],     // Read-write access
        "readonlyPaths": ["C:\\data"],      // Read-only access
        "deniedPaths": ["C:\\Windows"]      // Blocked paths
    },

    "fallback": {
        "allowDaclMutation": true          // Allow Tier 3 DACL fallback (default true)
    },

    "network": {
        "egress": {
            "default": "deny",
            "allow": [{
                "to": [{ "cidr": "203.0.113.0/24" }],
                "ports": [{ "protocol": "tcp", "port": 443 }]
            }],
            "deny": [{
                "to": [{ "cidr": "203.0.113.7/32" }],
                "ports": [{ "protocol": "tcp", "port": 443 }]
            }]
        },
        "ingress": {
            "default": "deny",
            "hostLoopback": "deny"
        }
    },

    "ui": {
        "disable": true,                   // Disable all UI access (default true)
        "clipboard": "none",               // "none", "read", "write", or "all"
        "injection": false                 // Allow synthetic input injection
    },

    "processContainer": {                  // Process-based container-specific
        "leastPrivilege": false,
        "capabilities": ["internetClient"],
        "filesystem": {
            "enumeratePaths": ["C:\\tools"] // Query/list entries without reading file contents
        },
        "captureDenials": {                // Windows-only: record the process's access
            "mode": "block",               // "block" (default): access stays denied and
                                           // is logged (deny-by-default preserved). "allow":
                                           // access is allowed and logged (audit; relaxes
                                           // deny-by-default, emits a security warning).
            "outputPath": "C:\\logs\\denials.json", // JSON denials file the app reads. Parent dir
                                           // must exist; a unique per-run id is stamped into the
                                           // stem and the actual path is printed on stderr.
            "retainEtl": false             // Keep the sealed ETL after analysis and report its
                                           // path in output metadata. Defaults to false.
                                           // Retention requires a terminal wait; abandoning the
                                           // process handle deletes the internal trace.
                                           // Requires native PSEC/V2 capture; guarded-WPR fallback
                                           // rejects retention rather than exposing a host-wide ETL.
        }
                                           // Omit outputPath for a managed JSON output file.
                                           // Native PSEC/V2 capture cannot combine with leastPrivilege
                                           // or runtimeConfig.networkProxy. Hosts without that complete native set
                                           // retain an eligible legacy containment tier and use guarded WPR.
                                           // If guarded-WPR prerequisites are unavailable, the request
                                           // fails before MXC creates the sandbox.
    },

    "lxc": {                               // LXC-specific
        "distribution": "alpine",
        "release": "3.19"
    },

    "seatbelt": {                          // macOS Seatbelt settings (macOS only)
        "profileOverride": null,           // Optional raw TinyScheme profile (escape hatch)
        "guiAccess": false,                // Allow GUI Mach services / IOKit / pty for window-drawing apps
        "nestedPty": true,                 // Allow inner process to allocate its own pty (posix_openpt)
        "keychainAccess": false,           // Allow Keychain via securityd / trustd / cfprefsd / lsd.*
        "extraMachLookups": []             // Additional Mach service global-names the inner process may resolve
    },

    "telemetry": {                         // Telemetry (Windows only)
        "enabled": true                    // Request emission for this run; MXC-owned user consent
                                           // and a permitting administrative policy are also required
    },

    "wslc": {                              // WSL Container settings (v0.9+)
        "image": "alpine:latest",          // Container image name
        "imageTarPath": "C:\\images\\alpine.tar",  // Import image from local tar file
        "cpuCount": 4,                     // CPU count for WSLC session
        "memoryMb": 2048,                  // Memory in MB for WSLC session
        "gpu": false,                      // GPU passthrough
        "storagePath": "C:\\wslc-storage", // Image store path
        "portMappings": [                  // Host<->container port forwarding. TCP only -- the WSLC SDK runtime returns E_NOTIMPL for UDP, so the parser hard-rejects "udp" entries with a clear message.
            { "windowsPort": 8080, "containerPort": 80, "protocol": "tcp" }
        ]
    },

    "hyperlight": {                        // Hyperlight settings (v0.10+)
        "runtime": "node"                  // Guest runtime: agent (default), python, python-shell, node, bash or dotnet-jit
    }
}
```

> **State-aware fields.** The `phase` top-level field is the **state-aware
> discriminator**: a request that includes it is parsed as a state-aware
> lifecycle request (see below), *not* the one-shot config above. The `sandboxId`
> top-level field is state-aware-only — a one-shot request carrying `sandboxId`
> is rejected with a parse error. Callers cannot supply `correlationVector`;
> it is rejected as an unknown field because lifecycle correlation is internal
> to MXC and is not part of the request or response contract. See
> [Container lifecycle architecture](development/architecture/container-lifecycle.md)
> and [telemetry architecture](development/architecture/telemetry.md).

### Working Directory

`process.cwd` is optional. When it is set, it is passed to the backend
verbatim — an unusable value fails the launch rather than being silently
replaced. When it is **omitted**, backends do not simply inherit the launcher's
working directory: under a deny-by-default sandbox that directory is usually
unreadable, and the result ranges from a confusing silent relocation (Windows
restarts the child at the drive root) to `getcwd()` errors on the child's
stderr. Each backend therefore substitutes a directory the sandbox can actually
use:

| Backend | Default when `process.cwd` is omitted |
|---------|----------------------------------------|
| Windows ProcessContainer (AppContainer / BaseContainer) | First `readwritePaths` entry that is an existing directory, else the first such `readonlyPaths` entry, else the system drive root (`%SystemDrive%\`). Never `NULL`. |
| Seatbelt (macOS) | Same precedence, with `~` expanded as the profile expands it; falls back to `/`. |
| Bubblewrap (Linux) | No substitution — a policy grant is never adopted. `--chdir` is emitted only for an explicit `process.cwd`, which from 0.9 is also normalized against the sandbox root and used as `HOME`. With no explicit `cwd` there is no `--chdir` and `HOME` is unset — see [`docs/backends/bwrap/bubblewrap-backend.md`](backends/bwrap/bubblewrap-backend.md). |
| LXC / WSL Container | The container root — see [`docs/backends/lxc/lxc-backend.md`](backends/lxc/lxc-backend.md). |
| MicroVM (NanVix) / Hyperlight | Not applicable — these backends reject a working directory outright. |

Policy entries that are blank, name a file, or do not exist yet are skipped:
a process cannot be launched in any of them.

WSL Container one-shot runs accept an explicit `process.cwd` only as a local
Windows drive path, which is mapped under `/mnt/<drive>` (for example
`C:\work` becomes `/mnt/c/work`); any other value is rejected before the
container is created. WSL Container state-aware `exec` takes an absolute
in-container path instead. See
[`docs/backends/wslc/wsl-container-getting-started.md`](backends/wslc/wsl-container-getting-started.md).

### Environment

`process.env` and `process.inheritDefaultEnv` combine as follows from
`0.9.0-alpha`:

| `process.env` | `inheritDefaultEnv` | The child gets |
|---|---|---|
| omitted | ignored | the backend default |
| `[]` | `false` (default) | nothing |
| `[]` | `true` | the backend default |
| `["FOO=bar"]` | `false` (default) | only `FOO` |
| `["FOO=bar"]` | `true` | the default, plus `FOO`; a caller entry wins |

`inheritDefaultEnv` layers the supplied entries over the default, so supplying
none of them asks for the default itself — the same environment an omitted
`process.env` gets.

Two backends depart from the table. The Windows process container requires
`SYSTEMROOT` and `LOCALAPPDATA` to be present, so a caller-owned block that
omits them — including `[]` — is rejected before launch rather than used; the
rejection names the missing variables. IsolationSession starts every process
from the agent user's default environment and cannot replace or empty it, so
`process.env` without `inheritDefaultEnv` — including `[]` — is rejected before
launch.

What the default block contains is backend-specific; see the backend's guide.
On the WSL Container backend it is the container image's own `ENV`, which MXC
neither authors nor enumerates — see
[`docs/backends/wslc/wsl-container-getting-started.md`](backends/wslc/wsl-container-getting-started.md#environment).

### Filesystem Policy

The `filesystem` section defines path access policy shared across backends:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `readwritePaths` | string[] | `[]` | Paths the process can read and write. |
| `readonlyPaths` | string[] | `[]` | Paths the process can read but not write. |
| `deniedPaths` | string[] | `[]` | Paths the process cannot access at all. |

The ProcessContainer-only `processContainer.filesystem` section contains:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enumeratePaths` | string[] | `[]` | Paths the process can query or enumerate without reading file contents. Requires schema `0.9.0-alpha` and a Windows BaseContainer host with PSEC 1.1 `fs_enumerate` support. It cannot be combined with `processContainer.leastPrivilege`; that combination fails rather than falling back. |

On Windows, `deniedPaths` is enforced by one of two mechanisms depending on the
containment tier selected at runtime:

- **BaseContainer (Tier 1):** enforced natively by the OS when PSEC advertises
  `PSE_SUPPORT_FS_DENY`. No host filesystem changes are made.
- **AppContainer (Tier 2/3):** enforced by host-filesystem DENY ACEs, applied before
  the run and removed on exit. This path is gated by `allowDaclMutation`, requires
  `WRITE_DAC` on each denied path, and temporarily modifies host security descriptors.
  Because the ACEs are keyed on the sandbox's derived AppContainer SID, two concurrent
  runs sharing the same `containerId` can revoke each other's ACEs — use distinct
  `containerId` values for parallel runs.

#### Path grants and root directories for Windows BaseContainer

For Windows BaseContainer, a path grant in `readwritePaths` applies to that directory
and its descendants with the exception of root directories. Granting access to a
**volume root** (e.g. `C:\`) does **not** cascade to its child folders to prevent over-provisioning.

For example, `"readwritePaths": ["C:\\"]` does **not** grant access to files
under `C:\data`.

#### Upward directory traversal for Windows BaseContainer

Many tools search **upward** from the working directory toward the volume root,
looking for a marker file that defines their project. With Windows BaseContainer, when such a tool reaches a parent directory that is not in the allowlist, `ACCESS_DENIED` will be returned.

When resolving this error, grant only the specific directories the tool must reach and keep that set as small as possible.
Avoid resolving this error by granting broad profile roots. Each 'readwritePaths' grant also exposes that directory's descendants and granting broad profile roots may result in over-permissioning.

### UI Policy

The `ui` section is the cross-platform UI-restriction policy. Every field is
default-deny, so on a backend that enforces the section an omitted `ui` is
equivalent to full lockdown. **That equivalence is per-backend**: a backend that
does not enforce UI policy applies no restriction whether the section is omitted
or supplied, so an omitted `ui` there is not lockdown. Check the backend's own
documentation before relying on the default.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `disable` | boolean | `true` | Disable all UI access. On Windows ProcessContainer this maps to the Win32k system-call disable mitigation, so the process cannot create windows, use GDI, or make `NtUser*` / `NtGdi*` calls. |
| `clipboard` | enum | `"none"` | Clipboard access level: `"none"`, `"read"`, `"write"`, or `"all"`. |
| `injection` | boolean | `false` | Whether the process may inject synthetic keyboard/mouse input (`SendInput` and friends). |

**Per-backend support.** `ui` is enforced by the Windows ProcessContainer
backend (via job-object UI restrictions plus the Win32k mitigation — see
[`backends/process-container/UIPolicy_Schema.md`](backends/process-container/UIPolicy_Schema.md))
and by the macOS Seatbelt backend (via the generated sandbox profile). Other
backends do not implement UI restrictions; each backend's documentation states
whether it applies, rejects, or ignores the section. **IsolationSession and WSLc
refuse any supplied `ui` at every phase on both surfaces**, and each accepts an
omitted one without applying any UI restriction — so the section's default-deny
reading does not hold on either. The reasons differ: no `ui` posture is truthful
for a session-isolated sandbox (see
[IsolationSession state-aware Rust architecture](development/architecture/backends/isolation-session/state-aware-rust.md)),
while WSLc has no mechanism to enforce UI restrictions on a container (see
[`backends/wslc/wslc-state-aware.md`](backends/wslc/wslc-state-aware.md)).
The Windows `processContainer.ui` sub-block carries the ProcessContainer-only
fields `isolation`, `desktopSystemControl`, `systemSettings`, and `ime`.
`processContainer.filesystem` carries `enumeratePaths`. Both sub-blocks are
valid only when `containment` is `processcontainer`.

### Fallback Policy

The `fallback` section gates the runner's host-impacting fallbacks. Each flag is an explicit operator consent for a specific mechanism the runner may otherwise pick when the preferred primitive is unavailable. Defaults preserve the pre-fallback-section behavior (all permitted).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowDaclMutation` | boolean | `true` | When the BaseContainer feature and the OS-side filesystem broker helper are both unavailable, allow MXC to apply DACL ACEs on policy paths (Tier 3 fallback). **⚠️ This modifies host filesystem security descriptors**; original DACLs are restored on exit. Set to `false` to refuse this fallback; the run will then fail on machines that require Tier 3. |

### Containment Backends

The `containment` field accepts both **abstract intent values** (which the
native binary resolves per host) and **concrete backend values** (which select
a specific runner). Prefer abstract intents unless you specifically need to
force a particular backend.

#### Abstract intents

| Value | Resolution |
|-------|------------|
| `"process"` | `processcontainer` on Windows, `bubblewrap` on Linux, `seatbelt` on macOS |
| `"vm"` | Full hardware-virtualised VM isolation. Resolves to `windows_sandbox` on Windows. |
| `"microvm"` | MicroVM on Windows (NanVix via the Windows Hypervisor Platform). Experimental. |

#### Concrete backends

| Value | Description |
|-------|-------------|
| `"processcontainer"` | (Default) Windows process-level isolation. Resolves to AppContainer (legacy) or BaseContainer (newer OS sandbox API) at run time depending on host capabilities and the `--experimental` flag. |
| `"windows_sandbox"` | Windows Sandbox VM isolation. Dual-mode: a transient **one-shot** runner that launches a fresh disposable VM per execution, and a **state-aware** lifecycle backed by a long-lived per-sandbox daemon. |
| `"wslc"` | Linux containers via the WSL Container SDK |
| `"lxc"` | Native LXC container isolation. No abstract intent resolves to LXC; request it explicitly. |
| `"microvm"` | MicroVM isolation via Windows HyperV Platform (NanVix microkernel) |
| `"hyperlight"` | MicroVM isolation via Hyperlight + Unikraft with an embedded CPython snapshot (experimental) |
| `"isolation_session"` | Windows isolation session — runs the workload as a freshly-provisioned, per-execution isolated user account in its own OS-managed session. Dual-mode: one-shot and state-aware. |
| `"seatbelt"` | macOS sandbox isolation (Seatbelt). Requires macOS 15 or later — see [`docs/backends/seatbelt/seatbelt-backend.md`](backends/seatbelt/seatbelt-backend.md). |
| `"bubblewrap"` | Unprivileged Linux sandboxing via Bubblewrap/user namespaces. The Linux default — see [`docs/backends/bwrap/bubblewrap-backend.md`](backends/bwrap/bubblewrap-backend.md). |

Only the backend section matching the selected `containment` value is accepted;
a config that also carries an unrelated backend's section is **rejected** with a
"Multiple containment backends configured" error rather than silently ignored.

### State-aware lifecycle envelope

The exact development schema documents a multi-phase envelope shape for the
state-aware lifecycle (`provision` / `start` / `exec` / `stop` /
`deprovision`). Where the one-shot config above is a self-contained
`ExecutionRequest` to run once, a state-aware envelope identifies which
phase is being driven against an existing provisioned sandbox.

State-aware envelopes use an exact backend-specific contract:

- IsolationSession uses published `0.9.0-alpha`.
- WSLC uses published `0.9.0-alpha`; Windows Sandbox uses development
  `1.1.0-alpha`.

Contracts before `0.9.0-alpha` are retired. The supported published
`0.9.0-alpha` and `1.0.0` contracts contain one-shot plus IsolationSession
and WSLC state-aware request roots. This Windows Sandbox example therefore uses the
exact development schema:

```json
{
    "$schema": "./schemas/dev/mxc-config.schema.1.1.0-alpha.json",
    "version": "1.1.0-alpha",
    "phase": "exec",                       // One of: provision | start | exec | stop | deprovision
    "sandboxId": "wsb:abcd1234",           // Required for non-provision phases.
                                           // Prefix routes to the backend (wsb: -> windows_sandbox,
                                           // iso: -> isolation_session).
    "containment": "windows_sandbox",      // Required for `provision`; ignored for other phases
                                           // (the backend is inferred from sandboxId).
    "process": { "commandLine": "echo hi" }
    // Cross-cutting fields (process / filesystem / network / ui) sit at the TOP
    // level, exactly as in a one-shot request -- there is no wrapping `config`
    // object. Backend- and phase-specific config, when a phase has any, nests
    // under its permanent backend section, e.g.:
    //   "isolationSession": { "provision": { "appId": "PFN:Contoso.App_8wekyb3d8bbwe" } }
}
```

Phase / sandboxId / containment validation:

| Phase | `sandboxId` | `containment` |
|---|---|---|
| `provision`     | (not allowed) | **Required** — picks the backend whose `provision` mints a fresh sandboxId |
| `start`         | **Required** (`<prefix>:<token>`) | Ignored if present |
| `exec`          | **Required** | Ignored if present |
| `stop`          | **Required** | Ignored if present |
| `deprovision`   | **Required** | Ignored if present |

State-aware-capable backends today are `isolation_session`, `windows_sandbox`,
and `wslc` (all Windows-only). IsolationSession does not require runtime
experimental authorization; Windows Sandbox does.

Full lifecycle API: [container lifecycle](container-lifecycle.md).

### Schema Versioning

MXC execution config files require a `version` field naming an exact registered
contract. Version spelling, including patch and prerelease, is significant;
there is no range, latest-version, or missing-version fallback.

Versions with a pre-release suffix (e.g., `-alpha`) indicate the schema is not
yet stable — breaking changes may occur before publication. Version `1.0.0`
is the first stable contract. After `1.0.0`, breaking changes require a major
version bump per semver.

Registered contracts:

| Config `version` | Status |
|---|---|
| `"0.9.0-alpha"` | Published; minimum supported |
| `"1.0.0"` | Published; current stable |
| `"1.1.0-alpha"` | Mutable development contract |

An absent version, a retired version, or any unregistered spelling such as
`0.6.1-alpha`, `0.10.0-alpha`, or `1.0.1` is rejected.

#### When to bump

| Change type | Version bump | Example |
|---|---|---|
| Backward-compatible bug fix | **Patch** (0.4.0 → 0.4.1) | Fix default value |
| New optional field or functionality | **Minor** (0.4.0 → 0.5.0) | Adding `resources` section |
| Remove a field / breaking change | **Major** (0.x → 1.0.0) | Dropping legacy fields |

**Rule of thumb:** Follow [semver](https://semver.org/). While in `0.x` (initial
development), any release may include breaking changes per
[semver §4](https://semver.org/#spec-item-4). Once `1.0.0` is reached, breaking
changes require a major bump.

#### Migration process for breaking changes

1. **PR N:** Add new field with dual-read fallback from old field. Minor bump.
2. **PR N+1:** Update all configs, examples, SDK types, and docs to new format.
3. **PR N+2:** Remove fallback code. Minor bump (or major if post-1.0). Old configs
   no longer parse.

#### Version history

| Version | Changes |
|---|---|
| 0.3.0-alpha | Initial versioned schema. Added `process`, `lifecycle`, `containerId`, `wslc` alias. Dual-read fallbacks for legacy fields. |
| 0.4.0-alpha | Removed legacy fields (`script`, `workingDirectory`, `processContainer.name`, etc.). `process` section now required. |

See the `tests/examples/` directory for complete configuration examples.
