
## Configuration Schema

MXC uses a JSON configuration file. The formal schema is at
[`schemas/mxc-config.v1.schema.json`](../schemas/mxc-config.v1.schema.json) —
editors that support JSON Schema will provide autocomplete and validation when
you add `"$schema": "./schemas/mxc-config.v1.schema.json"` to your config file.

### Full Schema

```json
{
    "version": "1",                        // Schema version (current: "1")
    "containerId": "my-container",         // Externally assigned container ID
    "containment": "appcontainer",         // Backend (see table below)

    "lifecycle": {
        "destroyOnExit": true,             // Destroy container after execution
        "preservePolicy": false            // Retain filesystem/network policies after exit
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

    "appContainer": {                      // AppContainer-specific
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

The `version` field uses major-version compatibility: configs with a version
higher than the binary supports are rejected with an error suggesting to upgrade
`wxc-exec`. Missing `version` is accepted (treated as version 1). Additive
changes (new optional fields) do not require a version bump.

### Legacy Fields

The parser also accepts legacy top-level fields (`script`, `workingDirectory`,
`timeout`) as fallbacks for `process.commandLine`, `process.cwd`, and
`process.timeout` respectively. These will be removed in a future schema version.

See the `examples/` directory for complete configuration examples.