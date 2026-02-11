# Windows eXecution Container (WXC)

WXC is a sandboxed code execution environment for Windows that uses AppContainer or Restricted Token isolation to run untrusted code safely.

## Features

- **JSON-based Configuration**: Define script code, security policies, and execution parameters in JSON
- **Multiple Execution Modes**: Choose between AppContainer or Restricted Token isolation
- **Filesystem Access Control**: Explicitly allow or deny access to specific paths with filesystem policy
- **Network Policy**: Control network access with allow/block lists and firewall rules
- **Flexible Configuration Input**: Load configuration from files or base64-encoded JSON strings
- **AppContainer Capabilities**: Fine-grained control over Windows capabilities (network, registry, etc.)
- **ETW Tracing**: Debug mode with Event Tracing for Windows (ETW) to diagnose access checks

## Usage

WXC supports three ways to provide configuration:

### 1. Direct File Path
```bash
wxc-exec.exe config.json
```

### 2. Explicit --config Flag
```bash
wxc-exec.exe --config config.json
```

### 3. Base64-Encoded JSON (NEW)
```bash
wxc-exec.exe --config-base64 <base64-encoded-json>
```

The base64 mode is useful for:
- Programmatic execution where creating temporary files is inconvenient
- CI/CD pipelines
- Security scenarios where configuration files shouldn't persist on disk
- Testing and automation

**Example: Creating and using base64 configuration**
```powershell
# PowerShell: Encode JSON configuration to base64
$json = '{"script":{"code":"print(\"Hello World\")"}}'
$base64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))

# Execute with base64 configuration
wxc-exec.exe --config-base64 $base64
```

```bash
# Linux/WSL: Encode and execute
echo '{"script":{"code":"print(\"Hello World\")"}}' | base64 | xargs -I {} wxc-exec.exe --config-base64 {}
```

### Debug Mode

By default, WXC runs in **silent mode** (no console output), ideal for automated/programmatic execution. Use the `--debug` flag to enable verbose console output:

```bash
# Silent execution (default) - no console output
wxc-exec.exe config.json

# Verbose execution with debug output
wxc-exec.exe --debug config.json

# Debug flag can be combined with any configuration mode
wxc-exec.exe --debug --config config.json
wxc-exec.exe --debug --config-base64 <base64-encoded-json>
```

**Benefits of silent mode:**
- Clean output for CI/CD pipelines
- No console spam for programmatic execution
- Exit codes still work correctly for success/failure detection
- Error messages are always shown when needed

**When to use --debug:**
- Interactive troubleshooting and development
- Understanding what security policies are being applied
- Debugging configuration issues
- Viewing script output during execution

## Configuration Schema

WXC uses a JSON configuration file with the following structure:

```json
{
  "script": {
    "code": "print('Hello')",           // Required: Script code to execute
    "input": "",                         // Optional: stdin input
    "timeout": 30000                     // Optional: timeout in milliseconds
  },
  "executionMode": "appContainer",       // "appContainer" or "restrictedToken"
  "appContainer": {
    "name": "CLI",                       // AppContainer profile name
    "leastPrivilegeMode": false,         // Enable LPAC mode
    "capabilities": [                    // Windows capabilities to grant
      "internetClient",
      "registryRead"
    ]
  },
  "restrictedToken": {
    "disableMaxPrivilege": true,         // Disable all privileges
    "sidsToDisable": [],                 // SIDs to disable (e.g., "S-1-5-32-544")
    "sidsToRestrict": [],                // Restricting SIDs
    "privilegesToRemove": []             // Privileges to remove (e.g., "SeDebugPrivilege")
  },
  "filesystem": {
    "allowedPaths": ["C:\\temp"],        // Paths the script can access
    "deniedPaths": ["C:\\Windows"],      // Paths explicitly blocked
    "restoreAclsOnExit": true            // Restore original ACLs after execution
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

## Examples

### Basic Hello World
```json
{
  "script": {
    "code": "import sys\nprint('Hello from WXC!')\nprint(f'Python: {sys.version}')"
  }
}
```

### Filesystem Access Control
```json
{
  "script": {
    "code": "open('C:\\\\temp\\\\output.txt', 'w').write('test')"
  },
  "filesystem": {
    "allowedPaths": ["C:\\temp"],
    "deniedPaths": ["C:\\Windows\\System32"]
  }
}
```

### Network Restricted Execution
```json
{
  "script": {
    "code": "import urllib.request\nurllib.request.urlopen('https://api.github.com')"
  },
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "firewall",
    "allowedHosts": ["api.github.com"]
  }
}
```

### Restricted Token Mode (Requires Admin)
```json
{
  "script": {
    "code": "print('Running with restricted token')"
  },
  "executionMode": "restrictedToken",
  "restrictedToken": {
    "disableMaxPrivilege": true,
    "privilegesToRemove": ["SeDebugPrivilege"]
  }
}
```

## Debugging with ETW Traces

For troubleshooting AppContainer isolation, you can use Event Tracing for Windows (ETW) to capture access check events.

### Start Tracing

Start an administrator PowerShell console, then run:

```powershell
$name = 'WXC-Trace'
New-NetEventSession -Name $name -LocalFilePath "C:\temp\trace.etl" | Out-Null
Add-NetEventProvider -SessionName $name -Name "Microsoft-Windows-Kernel-General" -MatchAllKeyword 0x20 | Out-Null
Start-NetEventSession -Name $name
```

### Run WXC

Execute your script with AppContainer in permissive learning mode:

```json
{
  "script": {
    "code": "your_code_here"
  },
  "appContainer": {
    "capabilities": ["permissiveLearningMode"]
  }
}
```

### Stop Tracing

When execution completes:

```powershell
Stop-NetEventSession -Name $name
Remove-NetEventSession -Name $name
```

### Parse Trace

Analyze the trace file to see which access checks were performed:

```powershell
parse_access_checks.ps1 -TraceFile C:\temp\trace.etl
```

This will show you what filesystem and registry accesses the script attempted, helping you configure appropriate `allowedPaths` or capabilities.

## Requirements

- Windows 10/11 or Windows Server 2016+
- Visual Studio 2022 with C++ Desktop Development workload
- Python 3.x (for executing scripts)
- Administrator privileges (for firewall rules and restricted token mode)

## Building

Open `wxc.sln` in Visual Studio 2022 and build the solution. The executable will be created in `x64\Debug\wxc-exec.exe` or `x64\Release\wxc-exec.exe`.

## Security Considerations

- **Administrator Rights**: Firewall enforcement and restricted token mode require administrator privileges
- **LPAC Mode**: Least Privileged AppContainer (LPAC) provides stronger isolation than regular AppContainer
- **Network Enforcement**: Use `"enforcementMode": "both"` for maximum network protection (capabilities + firewall)
- **Filesystem ACLs**: Changes are applied to the actual filesystem and restored on exit (if configured)
- **Capability Selection**: Only grant necessary capabilities - avoid `permissiveLearningMode` in production

## License

See LICENSE file for details.