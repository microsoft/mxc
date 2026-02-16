
## Configuration Schema

WXC uses a JSON configuration file with the following structure:

```json
{
    "script": "print('Hello')",            // Required: Script code to execute
    "workingDirectory": "C:\\temp",      // Optional: initial working directory
    "timeout": 30000                     // Optional: timeout in milliseconds (default is no timeout)
  },
  "appContainer": {
    "name": "CLI",                       // AppContainer profile name
    "leastPrivilegeMode": false,         // Enable LPAC mode
    "learningMode": false,               // Enable learning mode tracing, if available
    "capabilities": [                    // Windows capabilities to grant
      "internetClient",
      "privateNetworkClientServer"
    ]
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
    "removeRulesOnExit": true            // Remove firewall rules after execution
  }
}
```

See the `examples/` directory for complete configuration examples.