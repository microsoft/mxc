
## Configuration Schema

WXC uses a JSON configuration file with the following structure:

```json
{
    "script": "print('Hello')",            // Required: Script code to execute
    "containment": "appcontainer",         // Optional: "appcontainer" (default) or "sandbox"
    "workingDirectory": "C:\\temp",      // Optional: initial working directory
    "timeout": 30000,                    // Optional: timeout in milliseconds (default is no timeout)
    "appContainer": {                    // Optional: AppContainer-specific settings
      "name": "CLI",                       // AppContainer profile name
      "leastPrivilegeMode": false,         // Enable LPAC mode
      "learningMode": false,               // Enable learning mode tracing, if available
      "capabilities": [                    // Windows capabilities to grant
        "internetClient",
        "privateNetworkClientServer"
      ]
    },
    "sandbox": {                         // Optional: Windows Sandbox settings (used when containment is "sandbox")
      "idleTimeout": 300000,               // Daemon idle timeout in ms (default: 300000 = 5 min)
      "daemonPipeName": "wxc-sandbox"      // Named pipe name for daemon (default: "wxc-sandbox")
    },
    "filesystem": {
      "readwritePaths": ["C:\\temp"],        // Paths the container can access with Read and Write privilege
      "readonlyPaths":  ["C:\\temp"],        // Paths the container can access with Read privilege
      "deniedPaths": ["C:\\Windows"],      // Paths explicitly blocked
      "clearPolicyOnExit": true            // Remove the policy for this container when execution is complete
    },
    "network": {
      "defaultPolicy": "block",            // "allow" or "block"
      "enforcementMode": "firewall",       // "capabilities", "firewall", or "both"
      "allowedHosts": [                    // Allowed hostnames or IPs
        "api.github.com",
        "140.82.121.0/24"
      ],
      "blockedHosts": [],                  // Blocked hostnames
      "removeRulesOnExit": true,           // Remove firewall rules after execution
      "proxy": {
        "localhost": 8080                  // Port of a localhost proxy
      }
      // OR
      "proxy": {
        "builtinTestServer": true          // Launch a builtin test proxy (testing only)
      }
    }
}
```

### Containment Backends

| Value | Description |
|-------|-------------|
| `"appcontainer"` | (Default) Windows AppContainer process-level isolation on the host |
| `"sandbox"` | Windows Sandbox VM isolation via a long-lived daemon |

When `containment` is `"sandbox"`, the `appContainer` section is ignored and the
`sandbox` section is used instead.  Filesystem and network policy are managed by
the sandbox guest agent rather than by host-side BFS/firewall rules.

See the `examples/` directory for complete configuration examples.