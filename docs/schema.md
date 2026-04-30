
## Configuration Schema

MXC uses a JSON configuration file. The current stable schema is at
[`schemas/stable/mxc-config.schema.0.4.0-alpha.json`](../schemas/stable/mxc-config.schema.0.4.0-alpha.json).
For development, the dev schema at
[`schemas/dev/mxc-config.schema.0.5.0-dev.json`](../schemas/dev/mxc-config.schema.0.5.0-dev.json)
includes experimental features and may change without notice.

Editors that support JSON Schema will provide autocomplete and validation when
you add a `"$schema"` reference to your config file. Use the stable schema for
production configs and the dev schema when working on experimental features:

```json
// Production
"$schema": "./schemas/stable/mxc-config.schema.0.4.0-alpha.json"

// Development (experimental features)
"$schema": "./schemas/dev/mxc-config.schema.0.5.0-dev.json"
```

### Full Schema

```json
{
    "version": "0.4.0-alpha",              // Schema version (semver). Current stable: "0.4.0-alpha". Also accepts "0.5.0-alpha".
    "containerId": "my-container",         // Externally assigned container ID
    "containment": "appcontainer",         // Backend (see table below)

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

    "network": {
        "defaultPolicy": "block",          // "allow" or "block"
        "enforcementMode": "firewall",     // "capabilities", "firewall", or "both"
        "proxy": { "localhost": 8080 }     // Localhost proxy port (appcontainer only)
    },

    "appContainer": {                      // Process-based container-specific
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
            "storagePath": "C:\\wslc-storage"  // Image store path
        },
        "telemetry": {                     // Telemetry (experimental)
            "enabled": true                // Enable TraceLogging ETW event emission
        }
    }
}
```

### Containment Backends

| Value | Description |
|-------|-------------|
| `"appcontainer"` | (Default) Windows AppContainer process-level isolation |
| `"windows_sandbox"` | Windows Sandbox VM isolation via a long-lived daemon |
| `"wslc"` | Linux containers via the WSL Container SDK |
| `"lxc"` | Native LXC container isolation |
| `"vm"` | VM-based isolation (not yet implemented) |
| `"microvm"` | MicroVM isolation via Windows HyperV Platform (NanVix microkernel) |

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
| absent | >=0.4, <=0.5 | Accepted (assumed compatible) |
| `"0.3.0-alpha"` | >=0.4, <=0.5 | **Rejected** — "older than supported" |
| `"0.4.0-alpha"` | >=0.4, <=0.5 | Accepted (0.4 in range) |
| `"0.5.0-alpha"` | >=0.4, <=0.5 | Accepted (0.5 in range) |
| `"0.6.0"` | >=0.4, <=0.5 | **Rejected** — "newer than supported" |
| `"1.0.0"` | >=0.4, <=0.5 | **Rejected** — "newer than supported" |

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
| 0.4.0-alpha | Removed legacy fields (`script`, `workingDirectory`, `appContainer.name`, etc.). `process` section now required. |

See the `examples/` directory for complete configuration examples.