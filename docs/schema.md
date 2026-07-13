
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
        "cwd": "C:\\workspace",            // Working directory
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
        "proxy": { "localhost": 8080 }     // Loopback proxy port (processcontainer; bubblewrap)
                                           // (use { "builtinTestServer": true } for the bundled
                                           //  testing-only proxy; requires --allow-testing-features)
    },

    "processContainer": {                  // Process-based container-specific
        "leastPrivilege": false,
        "capabilities": ["internetClient"]
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
            "portMappings": [              // Host<->container port forwarding. TCP only -- the vendored WSLC SDK 2.8.1 runtime returns E_NOTIMPL for UDP, so the parser hard-rejects "udp" entries with a clear message.
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
| `"windows_sandbox"` | Windows Sandbox VM isolation via a long-lived daemon |
| `"wslc"` | Linux containers via the WSL Container SDK |
| `"lxc"` | Native LXC container isolation |
| `"microvm"` | MicroVM isolation via Windows HyperV Platform (NanVix microkernel) |
| `"seatbelt"` | macOS sandbox isolation (Seatbelt) |
| `"bubblewrap"` | Unprivileged Linux sandboxing via Bubblewrap/user namespaces (experimental) |

Only the backend section matching the selected `containment` value is used;
other backend sections are ignored.

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