
## Configuration Schema

MXC uses a JSON configuration file. The current stable schema is at
[`schemas/stable/mxc-config.schema.0.7.0-alpha.json`](../schemas/stable/mxc-config.schema.0.7.0-alpha.json).
For development, the dev schema at
[`schemas/dev/mxc-config.schema.0.8.0-dev.json`](../schemas/dev/mxc-config.schema.0.8.0-dev.json)
includes experimental features and may change without notice.

Editors that support JSON Schema will provide autocomplete and validation when
you add a `"$schema"` reference to your config file. Use the stable schema for
production configs and the dev schema when working on experimental features:

```json
// Production
"$schema": "./schemas/stable/mxc-config.schema.0.7.0-alpha.json"

// Development (experimental features)
"$schema": "./schemas/dev/mxc-config.schema.0.8.0-dev.json"
```

### Schema 0.8 networking

Schema 0.8 uses explicit egress and ingress policy and moves the loopback proxy
endpoint into runtime configuration:

```json
{
    "version": "0.8.0-alpha",
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
connectivity models and cannot be combined. A ProcessContainer proxy requires
`ingress.default: "allow"`. Identity-scoped proxies set `allowedProxyPeer` and
keep `hostLoopback: "deny"`; identity-less host proxies omit
`allowedProxyPeer` and require `hostLoopback: "allow"`.

```json
{
    "version": "0.8.0-alpha",
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

The legacy `defaultPolicy`, `enforcementMode`, `allowLocalNetwork`,
`allowedHosts`, `blockedHosts`, and `network.proxy` fields remain supported by
schema 0.6 and 0.7. During the additive schema 0.8 transition, requests may
continue to use those legacy fields or use the directional fields above, but
cannot mix both formats in one request.

### Full Schema

```json
{
    "version": "0.6.0-alpha",              // Schema version (semver). Minimum supported: "0.6.0-alpha"; current stable: "0.7.0-alpha".
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
        "env": ["MY_VAR=value"],           // Environment variables as KEY=VALUE
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
        "defaultPolicy": "block",          // "allow" or "block"
        "enforcementMode": "firewall",     // "capabilities", "firewall", or "both"
        "proxy": { "localhost": 8080 }     // Loopback proxy port (processcontainer; bubblewrap; seatbelt)
                                           // (use { "builtinTestServer": true } for the bundled
                                           //  testing-only proxy; requires --allow-testing-features)
                                           // WSLC and LXC support the cooperative proxy too, but
                                           // only via { "url": "http://proxy.example:8080" }
                                           // (own-netns: localhost/builtinTestServer are
                                           //  unreachable, rejected)
                                           // Under LXC the proxy is enforced: forwarded egress is
                                           //  restricted to the proxy endpoint and nothing else, so
                                           //  the allow/block host lists and DNS are not opened.
                                           //  The chain hooks FORWARD, so traffic addressed to the
                                           //  bridge gateway itself is delivered locally via INPUT
                                           //  and is outside what this chain governs.
    },

    "ui": {
        "disable": true,                   // Disable all UI access (default true)
        "clipboard": "none",               // "none", "read", "write", or "all"
        "injection": false                 // Allow synthetic input injection
    },

    "processContainer": {                  // Process-based container-specific
        "leastPrivilege": false,
        "capabilities": ["internetClient"],
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
                                           // or network.proxy. Hosts without that complete native set
                                           // retain an eligible legacy containment tier and use guarded WPR.
    },

    "lxc": {                               // LXC-specific
        "distribution": "alpine",
        "release": "3.19"
    },

    "experimental": {                      // Experimental features (requires --experimental)
        "wslc": {                          // WSL Container settings
            "image": "alpine:latest",      // Container image name
            "imageTarPath": "C:\\images\\alpine.tar",  // Import image from local tar file
            "cpuCount": 4,                 // CPU count for WSLC session
            "memoryMb": 2048,              // Memory in MB for WSLC session
            "gpu": false,                  // GPU passthrough
            "storagePath": "C:\\wslc-storage",  // Image store path
            "portMappings": [              // Host<->container port forwarding. TCP only -- the WSLC SDK runtime returns E_NOTIMPL for UDP, so the parser hard-rejects "udp" entries with a clear message.
                { "windowsPort": 8080, "containerPort": 80, "protocol": "tcp" }
            ]
        },
        "seatbelt": {                 // macOS sandbox settings (macOS only)
            "profileOverride": null,       // Optional raw TinyScheme profile (escape hatch)
            "guiAccess": false,            // Allow GUI Mach services / IOKit / pty for window-drawing apps
            "launchMethod": "exec",        // "exec" or "open" (LaunchServices, for Apple-constrained apps)
            "nestedPty": true,             // Allow inner process to allocate its own pty (posix_openpt)
            "keychainAccess": false        // Allow Keychain via securityd / trustd / cfprefsd / lsd.*
        },
        "telemetry": {                // Telemetry (experimental, Windows only)
            "enabled": true                // Emit TraceLogging ETW events via pure Rust tracelogging crate
        }
    }
}
```

> **State-aware fields.** The `phase` top-level field is the **state-aware
> discriminator**: a request that includes it is parsed as a state-aware
> lifecycle request (see below), *not* the one-shot config above. The `sandboxId`
> and `correlationVector` top-level fields are state-aware-only — a one-shot
> request carrying either is rejected with a parse error. `correlationVector` is
> the Microsoft Correlation Vector (MS-CV) seeded at `provision` and relayed by
> the client onto later phases (emitted under the TraceLogging `__TlgCV__` field
> when experimental telemetry is enabled). The client relays the value verbatim;
> the executor validates it on each non-`provision` phase and *spins* a fresh
> child element off a mutable base, passes an already-frozen vector through
> unchanged, and reseeds a new base if the relayed value is missing or malformed.
> See
> [`docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md`](state-aware-lifecycle/mxc-state-aware-sandbox-api.md)
> and [`docs/telemetry/telemetry.md`](telemetry/telemetry.md#correlating-a-lifecycle).

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
| LXC / WSL Container | The container root — see [`docs/lxc-support/lxc-backend.md`](lxc-support/lxc-backend.md). |
| MicroVM (NanVix) / Hyperlight | Not applicable — these backends reject a working directory outright. |

Policy entries that are blank, name a file, or do not exist yet are skipped:
a process cannot be launched in any of them.

### Filesystem Policy

The `filesystem` section defines path access policy shared across backends:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `readwritePaths` | string[] | `[]` | Paths the process can read and write. |
| `readonlyPaths` | string[] | `[]` | Paths the process can read but not write. |
| `deniedPaths` | string[] | `[]` | Paths the process cannot access at all. |

On Windows, `deniedPaths` is enforced by one of two mechanisms depending on the
containment tier selected at runtime:

- **BaseContainer (Tier 1):** enforced natively by the OS when the build advertises
  the `SANDBOX_CAP_FS_DENY` capability. No host filesystem changes are made.
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
[`process-container/UIPolicy_Schema.md`](process-container/UIPolicy_Schema.md))
and by the macOS Seatbelt backend (via the generated sandbox profile). Other
backends do not implement UI restrictions; each backend's documentation states
whether it applies, rejects, or ignores the section. **IsolationSession refuses
any supplied `ui` at every phase on both surfaces** — no `ui` posture is truthful
for a session-isolated sandbox (see
[`isolation-session/state-aware-rust.md`](isolation-session/state-aware-rust.md)) —
and accepts an omitted one without applying any UI restriction. The Windows
`processContainer.ui` sub-block carries additional ProcessContainer-only fields
(`isolation`, `desktopSystemControl`, `systemSettings`, `ime`) and is valid only
when `containment` is `processcontainer`.

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
| `"process"` | `processcontainer` on Windows, `lxc` on Linux, `seatbelt` on macOS |
| `"vm"` | Full hardware-virtualised VM isolation. Resolves to `windows_sandbox` on Windows. |
| `"microvm"` | MicroVM on Windows (NanVix via the Windows Hypervisor Platform). Experimental. |

#### Concrete backends

| Value | Description |
|-------|-------------|
| `"processcontainer"` | (Default) Windows process-level isolation. Resolves to AppContainer (legacy) or BaseContainer (newer OS sandbox API) at run time depending on host capabilities and the `--experimental` flag. |
| `"windows_sandbox"` | Windows Sandbox VM isolation. Dual-mode: a transient **one-shot** runner that launches a fresh disposable VM per execution, and a **state-aware** lifecycle backed by a long-lived per-sandbox daemon. |
| `"wslc"` | Linux containers via the WSL Container SDK |
| `"lxc"` | Native LXC container isolation |
| `"microvm"` | MicroVM isolation via Windows HyperV Platform (NanVix microkernel) |
| `"hyperlight"` | MicroVM isolation via Hyperlight + Unikraft with an embedded CPython snapshot (experimental) |
| `"isolation_session"` | Windows isolation session — runs the workload as a freshly-provisioned, per-execution isolated user account in its own OS-managed session (experimental). Dual-mode: one-shot and state-aware. |
| `"seatbelt"` | macOS sandbox isolation (Seatbelt) |
| `"bubblewrap"` | Unprivileged Linux sandboxing via Bubblewrap/user namespaces (experimental) |

Only the backend section matching the selected `containment` value is accepted;
a config that also carries an unrelated backend's section is **rejected** with a
"Multiple containment backends configured" error rather than silently ignored.

### State-aware lifecycle envelope

The dev schema additionally documents a multi-phase envelope shape for the
state-aware lifecycle (`provision` / `start` / `exec` / `stop` /
`deprovision`). Where the one-shot config above is a self-contained
`ExecutionRequest` to run once, a state-aware envelope identifies which
phase is being driven against an existing provisioned sandbox.

The envelope follows the same supported version range as one-shot requests:
`>=0.6, <=0.8`. The example uses `0.6.0-alpha`, which is accepted throughout
that range. The state-aware field shape is documented by the current dev
schema:

```json
{
    "$schema": "./schemas/dev/mxc-config.schema.0.8.0-dev.json",
    "version": "0.6.0-alpha",
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
    // under `experimental.<backendKey>.<phase>`, e.g.:
    //   "experimental": { "isolation_session": { "provision": { "appId": "Contoso.App_8wekyb3d8bbwe" } } }
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

State-aware-capable backends today: `isolation_session` and `windows_sandbox`
(both Windows-only, both still experimental). The dispatcher rejects
state-aware envelopes for backends that have not opted in.

Full lifecycle API: [`docs/state-aware-lifecycle/mxc-state-aware-sandbox-api.md`](state-aware-lifecycle/mxc-state-aware-sandbox-api.md).

### Schema Versioning

MXC config files include an optional `version` field using
[Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH). The parser uses
this to detect incompatible configs and provide clear upgrade guidance. If
`version` is absent, the config is assumed compatible with the current version.

Versions with a pre-release suffix (e.g., `-alpha`) indicate the schema is not
yet stable — breaking changes may occur in any release. Once the schema is
stable, version `1.0.0` (no suffix) will be released. After `1.0.0`, breaking
changes require a major version bump per semver.

The parser compares the config's major.minor against its supported version
(pre-release labels are ignored for comparison):

| Config `version` | Parser supports | Result |
|---|---|---|
| absent | >=0.6, <=0.8 | Accepted (assumed compatible) |
| `"0.5.0-alpha"` | >=0.6, <=0.8 | **Rejected** — "older than supported" |
| `"0.6.0-alpha"` | >=0.6, <=0.8 | Accepted (0.6 in range) |
| `"0.7.0-alpha"` | >=0.6, <=0.8 | Accepted (0.7 in range) |
| `"0.8.0-alpha"` | >=0.6, <=0.8 | Accepted (0.8 in range) |
| `"0.9.0"` | >=0.6, <=0.8 | **Rejected** — "newer than supported" |
| `"1.0.0"` | >=0.6, <=0.8 | **Rejected** — "newer than supported" |

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
