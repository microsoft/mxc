## Examples

For a more comprehensive list of examples, see
[`tests/examples/`](../tests/examples/).

### Basic Hello World
```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "process": {
    "commandLine": "python -c \"import sys; print('Hello from MXC!'); print(sys.version)\""
  }
}
```

### Filesystem Access Control
```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "process": {
    "commandLine": "python -c \"open('C:\\\\temp\\\\output.txt', 'w').write('test')\""
  },
  "filesystem": {
    "readwritePaths": [
      "C:\\temp"
    ],
    "deniedPaths": [
      "C:\\Windows\\System32"
    ]
  }
}
```

Create `C:\temp` before running this example, or replace it with an existing
writable directory.

### Network Restricted Execution
```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "process": {
    "commandLine": "python -c \"import socket; socket.create_connection(('140.82.114.6', 443), timeout=5).close(); print('Allowed destination reached')\"",
    "timeout": 30000
  },
  "processContainer": {
    "capabilities": ["internetClient"]
  },
  "network": {
    "egress": {
      "default": "deny",
      "allow": [{
        "to": [{ "cidr": "140.82.114.6/32" }],
        "ports": [{ "protocol": "tcp", "port": 443 }]
      }]
    },
    "ingress": { "default": "deny", "hostLoopback": "deny" }
  }
}
```

The destination is numeric because directional rules accept IP/CIDR, not
hostnames. It must be reachable from the host to demonstrate the allow rule;
see the [ProcessContainer networking guide](process-container/networking.md)
for host requirements and enforcement limits.

### Directional Network Policy (schema 0.9+)

Supported contracts use explicit egress CIDR, protocol, and port rules plus
separate ingress defaults:

```json
{
  "version": "0.9.0-alpha",
  "containment": "processcontainer",
  "process": {
    "commandLine": "cmd.exe /c echo directional network example"
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
for the historical GA design; use the
[supported schema guide](schema.md) for current backend authoring.

### Network Proxy

Supported contracts name a **running** localhost proxy using
`runtimeConfig.networkProxy`. Egress must default to deny, with no direct
allow or deny rules. For an unpackaged host proxy on **ProcessContainer**,
the development/testing configuration is:

```json
{
  "version": "1.0.0",
  "containment": "processcontainer",
  "process": {
    "commandLine": "python -c \"import urllib.request; print(urllib.request.urlopen('https://api.github.com').status)\"",
    "timeout": 30000
  },
  "processContainer": {
    "capabilities": ["internetClient"]
  },
  "network": {
    "egress": { "default": "deny" },
    "ingress": { "default": "allow", "hostLoopback": "allow" }
  },
  "runtimeConfig": {
    "networkProxy": "http://127.0.0.1:8080"
  }
}
```

This identity-less host-loopback deployment restricts client egress to the
configured proxy address and port, but does not verify which process owns that
endpoint. It requires native PSEC 1.1 ingress/host-loopback support; unsupported
hosts reject the request. For production ProcessContainer deployments, identify
a packaged proxy through `processContainer.network.allowedProxyPeer` instead; see
[proxy deployment choices](process-container/networking.md#proxy-deployment-choices).
Bubblewrap and Seatbelt also support a caller-managed loopback proxy, but
their supported ingress policies differ. See their backend guides.

#### `egress` / `ingress` / `runtimeConfig.networkProxy`

Every supported contract (`0.9.0-alpha` or later) accepts the directional
shape and rejects the retired `defaultPolicy`, host-list, and `network.proxy`
fields. This is the cross-backend schema (see
[`docs/sandbox-policy/0.8.0/networking/networking.md`](sandbox-policy/0.8.0/networking/networking.md)
for the full design and per-backend enforcement matrix), not a
backend-specific format: it's parsed the same way regardless of
`containment`. Each backend independently declares which parts of it — if
any — it actually enforces; a backend that hasn't declared support for a
given field rejects a config that sets it.

Note that `EGRESS_RULES` is what carries per-CIDR/port rules; a backend
without it accepts only `egress.default`. On Seatbelt,
`runtimeConfig.networkProxy` covers only loopback endpoints; there is no
supported equivalent for a remote proxy URL or `builtinTestServer`. See
[`docs/sandbox-policy/0.8.0/networking/schema-updates.md`](sandbox-policy/0.8.0/networking/schema-updates.md)
for the full field mapping and [`tests/examples/31_mac_network_0_8.json`](../tests/examples/31_mac_network_0_8.json)
for a complete example:

```json
{
  "version": "0.9.0-alpha",
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