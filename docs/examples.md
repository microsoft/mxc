## Examples

For a more comprehensive list of examples, look in the examples\ directory.

### Basic Hello World
```json
{
  "script": "python -c \"import sys; print('Hello from WXC!'); print(f'Python version: {sys.version}');\"",
  "appContainer": {
    "name": "CLI-HelloWorld"
  }
}
```

### Filesystem Access Control
```json
{
  "script": "python -c \"open('C:\\\\temp\\\\output.txt', 'w').write('test')\"",
  "appContainer": {
    "name": "CLI-Filesystem-Test"
  },
  "filesystem": {
    "readwritePaths": [
      "C:\\temp"
    ],
    "deniedPaths": [
      "C:\\Windows\\System32"
    ],
    "clearPolicyOnExit": true
  }
}
```

### Network Restricted Execution
```json
{
  "script": "import urllib.request\nurllib.request.urlopen('https://api.github.com')",
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "firewall",
    "allowedHosts": ["api.github.com"]
  }
}
```

### Network Proxy

Route AppContainer traffic through an already-running localhost proxy. The
proxy is responsible for application-layer filtering such as domain allow/deny
lists, request inspection, and logging. Supported with the `appcontainer`
containment backend only.

```json
{
  "script": "python -c \"import urllib.request; print(urllib.request.urlopen('https://api.github.com').status)\"",
  "timeout": 30000,
  "appContainer": {
    "name": "CLI-Proxy",
    "capabilities": ["internetClient"]
  },
  "network": {
    "proxy": { "localhost": 8080 }
  }
}
```