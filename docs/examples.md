## Examples

For a more comprehensive list of examples, look in the examples\ directory.

### Basic Hello World
```json
{
  "script": "python -c \"import sys; print('Hello from MXC!'); print(f'Python version: {sys.version}');\"",
  "processContainer": {
    "name": "CLI-HelloWorld"
  }
}
```

### Filesystem Access Control
```json
{
  "script": "python -c \"open('C:\\\\temp\\\\output.txt', 'w').write('test')\"",
  "processContainer": {
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

### Schema 0.8 Directional Network Policy

Schema 0.8 adds a directional format with explicit egress CIDR, protocol, and
port rules plus separate ingress defaults:

```json
{
  "version": "0.8.0-alpha",
  "containment": "process",
  "process": {
    "commandLine": "echo schema 0.8 directional network example"
  },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [{ "cidr": "192.0.2.0/24" }],
          "ports": [{ "protocol": "tcp", "port": 443 }]
        }
      ]
    },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  }
}
```

See
[`tests/examples/30_network_0_8_directional.json`](../tests/examples/30_network_0_8_directional.json)
for the complete config and
[`sandbox-policy/0.8.0/networking/networking.md`](sandbox-policy/0.8.0/networking/networking.md)
for network modes and backend support.

### Network Proxy

Route process-container traffic through a localhost proxy. Supported with the
`processcontainer` containment backend only. Two mutually exclusive modes are available:

**External proxy** — connect to an already-running localhost proxy:

```json
{
  "script": "python -c \"import urllib.request; print(urllib.request.urlopen('https://api.github.com').status)\"",
  "timeout": 30000,
  "processContainer": {
    "name": "CLI-Proxy",
    "capabilities": ["internetClient"]
  },
  "network": {
    "proxy": { "localhost": 8080 }
  }
}
```

**Builtin test server** — `wxc-exec` launches its own minimal HTTP CONNECT proxy on
an OS-assigned port (for integration testing only, not production):

```json
{
  "script": "python -c \"import urllib.request; print(urllib.request.urlopen('https://api.github.com').status)\"",
  "timeout": 30000,
  "processContainer": {
    "name": "CLI-BuiltinProxy",
    "capabilities": ["internetClient"]
  },
  "network": {
    "proxy": { "builtinTestServer": true }
  }
}
```

When `builtinTestServer` is `true`, it must be the only key in the `proxy`
object. Because it activates a deliberately-permissive, testing-only proxy
(no auth, no body limits), it is **not** enabled by default: pass the
`--allow-testing-features` flag to `wxc-exec`/`lxc-exec`/`mxc-exec-mac`. This
is a separate axis from `--experimental` (which selects experimental backends
and features). The MXC SDK exposes the same gate as the `allowTestingFeatures`
spawn option, which must be set to `true` for a policy that uses
`builtinTestServer`.