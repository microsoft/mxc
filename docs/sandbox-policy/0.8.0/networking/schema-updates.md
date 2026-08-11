# MXC network schema updates: 0.7 to 0.8

The planned schema 0.8 update replaces the flat 0.7 network object with
explicit egress and ingress policy. It also moves proxy runtime data outside
the shared policy.

## Field mapping

| Schema 0.7 | Schema 0.8 | Change |
|---|---|---|
| `defaultPolicy: "allow"` | `egress.default: "allow"` | Same outbound posture |
| `defaultPolicy: "block"` | `egress.default: "deny"` | `block` is renamed `deny` |
| `allowedHosts` | `egress.allow[].to[].cidr` | 0.8 uses IP/CIDR only and can scope by port/protocol |
| `blockedHosts` | `egress.deny[].to[].cidr` | 0.8 uses IP/CIDR only and deny overrides allow |
| `enforcementMode` | Removed | The backend enforces the policy or rejects it |
| `allowLocalNetwork` | `ingress.default` | Controls LAN/private-network inbound |
| No equivalent | `ingress.hostLoopback` | New host-loopback connectivity control in either direction |
| `proxy.localhost` | `runtimeConfig.networkProxy` | Loopback proxy endpoint becomes runtime data |
| `proxy.url` with an HTTP/S loopback URL | `runtimeConfig.networkProxy` | Loopback URL remains supported |
| `proxy.url` with a remote or non-loopback URL | No GA equivalent | Schema 0.8 accepts only loopback proxy URLs |

`proxy.builtinTestServer` has no schema 0.8 GA equivalent.

## Direct egress

Schema 0.7:

```jsonc
{
  "network": {
    "defaultPolicy": "block",
    "enforcementMode": "both",
    "allowedHosts": [ "140.82.112.0/20" ],
    "allowLocalNetwork": false
  }
}
```

Schema 0.8:

```jsonc
{
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ]
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

## Proxy

Schema 0.7 uses cooperative proxy variables:

```jsonc
{
  "network": {
    "proxy": { "localhost": 8080 }
  }
}
```

Schema 0.8 moves the endpoint to runtime metadata:

```jsonc
{
  "runtimeConfig": {
    "networkProxy": "http://127.0.0.1:8080"
  }
}
```

The omitted 0.8 `network` block uses deny defaults.

## Backend-specific schema 0.8 configuration

| Backend | Configuration |
|---|---|
| ProcessContainer | [Schema 0.8 proxy configuration](../../../process-container/examples/0.8.0-schema.md) |
