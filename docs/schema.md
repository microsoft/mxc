
## Configuration Schema

MXC uses a JSON configuration file. The formal schema is at
[`schemas/mxc-config.v2.schema.json`](../schemas/mxc-config.v2.schema.json) —
editors that support JSON Schema will provide autocomplete and validation when
you add `"$schema": "./schemas/mxc-config.v2.schema.json"` to your config file.

### Full Schema

```json
{
    "version": "0.3.0-alpha",               // Schema version (current: "0.3.0-alpha")
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
    }
}
```

### Containment Backends

| Value | Description |
|-------|-------------|
| `"appcontainer"` | (Default) Windows AppContainer process-level isolation |
| `"sandbox"` | Windows Sandbox VM isolation via a long-lived daemon |
| `"wslc"` | Linux containers via the WSL Container SDK |
| `"lxc"` | Native LXC container isolation |
| `"vm"` | VM-based isolation (not yet implemented) |
| `"microvm"` | MicroVM-based isolation (not yet implemented) |

Only the backend section matching the selected `containment` value is used;
other backend sections are ignored.

### Schema Versioning

MXC config files include an optional `version` field that declares the schema
version. The parser uses this to detect incompatible configs and provide clear
upgrade guidance.

The parser declares a `SUPPORTED_MAJOR_VERSION` constant. At parse time:

| Config `version` | Parser supports | Result |
|---|---|---|
| absent | any | Accepted (assumed compatible) |
| `"1"` | 2 | Accepted (1 ≤ 2) |
| `"2"` | 2 | Accepted (2 ≤ 2) |
| `"3"` | 2 | **Rejected** — "upgrade wxc-exec" |
| `"0"` or non-numeric | any | **Rejected** — invalid format |

Version must be a positive integer (e.g., `"1"`, `"2"`). Minor versions
(e.g., `"2.1"`) are parsed by major only — `"2.1"` is treated as major `2`.

#### When to bump

| Change type | Version bump | Example |
|---|---|---|
| Add new optional field | **None** | Adding `resources` section |
| Add new enum value | **None** | Adding `"seatbelt"` to containment |
| Change a default value | **None** | Default timeout change |
| Remove a field | **Major** | Dropping `script` top-level field |
| Rename a field without fallback | **Major** | `workingDirectory` → `process.cwd` |
| Change a field's type | **Major** | `gpu: bool` → `gpu: { type: "..." }` |
| Make an optional field required | **Major** | `process` becoming required |

**Rule of thumb:** If an existing valid config would stop parsing, bump the
major version. Otherwise, don't.

#### Migration process for breaking changes

1. **PR N:** Add new field with dual-read fallback from old field. No version bump.
2. **PR N+1:** Update all configs, examples, SDK types, and docs to new format.
3. **PR N+2:** Remove fallback code. Bump `SUPPORTED_MAJOR_VERSION`. Old configs
   no longer parse.

#### Version history

| Version | Changes |
|---|---|
| 1 | Initial versioned schema. Added `process`, `lifecycle`, `containerId`, `wslc` alias. All additive with dual-read fallbacks. |
| 2 | Removed legacy fields (`script`, `workingDirectory`, `appContainer.name`, etc.). `process` section now required. |

See the `examples/` directory for complete configuration examples.