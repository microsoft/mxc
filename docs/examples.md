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

Route sandboxed traffic through a localhost proxy via the legacy `network.proxy`
field. Supported by **ProcessContainer** (Windows), **Bubblewrap** (Linux), and
**Seatbelt** (macOS) — see each backend's doc for enforcement specifics. Two
mutually exclusive modes are available:

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

**Builtin test server** — the executor launches its own minimal HTTP CONNECT
proxy on an OS-assigned port (for integration testing only, not production):

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

#### Schema 0.8 shape: `egress` / `ingress` / `runtimeConfig.networkProxy`

Starting at `"version": "0.8.0-alpha"`, the `egress`/`ingress`/`runtimeConfig.networkProxy`
shape replaces the legacy `defaultPolicy`/`allowedHosts`/`blockedHosts`/`network.proxy`
fields above — a config must use one shape or the other, never both. This is
the official, cross-backend schema (see
[`docs/sandbox-policy/0.8.0/networking/networking.md`](sandbox-policy/0.8.0/networking/networking.md)
for the full design and per-backend enforcement matrix), not a
backend-specific format: it's parsed the same way regardless of
`containment`. Each backend independently declares which parts of it — if
any — it actually enforces; a backend that hasn't declared support for a
given field rejects a config that sets it:

| Backend | Declared schema-0.8 network support |
|---|---|
| ProcessContainer / BaseContainer (Windows) | all directional fields |
| ProcessContainer / AppContainer (Windows) | `EGRESS_DEFAULT`, `INGRESS_DEFAULT`, `HOST_LOOPBACK`, `RUNTIME_PROXY` (rejects `hostLoopback: "allow"`) |
| Bubblewrap (Linux) | `EGRESS_DEFAULT`, `EGRESS_RULES`, `INGRESS_DEFAULT`, `HOST_LOOPBACK`, `RUNTIME_PROXY` |
| LXC (Linux) | `EGRESS_DEFAULT`, `EGRESS_RULES`, `INGRESS_DEFAULT`, `HOST_LOOPBACK` |
| Seatbelt (macOS) | `EGRESS_DEFAULT`, `INGRESS_DEFAULT`, `HOST_LOOPBACK`, `RUNTIME_PROXY` (see [`docs/seatbelt/seatbelt-backend.md`](seatbelt/seatbelt-backend.md#schema-08-network-shape-egress--ingress--runtimeconfignetworkproxy)) |
| WSLc, Windows Sandbox, IsolationSession, MicroVM, Hyperlight | legacy fields only — a directional config is rejected |

Note that `EGRESS_RULES` is what carries per-CIDR/port rules; a backend
without it accepts only `egress.default`. On Seatbelt,
`runtimeConfig.networkProxy` covers only the
loopback-proxy case (`network.proxy.localhost` / loopback `network.proxy.url`);
there is no schema-0.8 equivalent for a remote proxy URL or
`builtinTestServer`. See
[`docs/sandbox-policy/0.8.0/networking/schema-updates.md`](sandbox-policy/0.8.0/networking/schema-updates.md)
for the full field mapping and [`tests/examples/30_mac_network_schema_v2.json`](../tests/examples/30_mac_network_schema_v2.json)
for a complete example:

```json
{
  "version": "0.8.0-alpha",
  "containment": "seatbelt",
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  },
  "runtimeConfig": {
    "networkProxy": "http://127.0.0.1:8080"
  }
}
```