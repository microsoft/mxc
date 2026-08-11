# MXC network schema updates: 0.7 to 0.8

The planned schema 0.8 update replaces the flat 0.7 network object with
explicit egress and ingress policy. It also moves proxy runtime data outside
the shared policy.

## Field mapping

| Schema 0.7 | Schema 0.8 | Change |
|---|---|---|
| `defaultPolicy: "allow"` | `egress.default: "allow"` | Same default action; 0.8 includes public and private destinations |
| `defaultPolicy: "block"` | `egress.default: "deny"` | `block` is renamed `deny` |
| `allowedHosts` | `egress.allow[].to[].cidr` | 0.8 uses IP/CIDR only and can scope by port/protocol |
| `blockedHosts` | `egress.deny[].to[].cidr` | 0.8 uses IP/CIDR only and deny overrides allow |
| `enforcementMode` | Removed | The caller no longer selects an enforcement mode |
| `allowLocalNetwork` | `egress` and `ingress.default` | 0.8 separates outbound private-network access from inbound posture |
| No equivalent | `ingress.hostLoopback` | New host-loopback connectivity control in either direction |
| `proxy.localhost` | `runtimeConfig.networkProxy` | Loopback proxy endpoint becomes runtime data |
| `proxy.url` with an HTTP/S loopback URL | `runtimeConfig.networkProxy` | Loopback URL remains supported |
| `proxy.url` with a remote or non-loopback URL | No GA equivalent | Schema 0.8 accepts only loopback proxy URLs |

`proxy.builtinTestServer` has no schema 0.8 GA equivalent.

`allowLocalNetwork` does not have a one-to-one schema 0.8 replacement. In
schema 0.7 it combines private-network access behind one switch. In schema 0.8,
`egress` expresses outbound private-network access and `ingress.default`
expresses inbound private-network access. Backends derive their required
network capabilities from both directions.

A schema 0.7 policy with `defaultPolicy: "allow"` and
`allowLocalNetwork: false` therefore has no single-field translation.
`egress.default: "allow"` permits private-network destinations in schema 0.8;
preserving the old private-network denial requires explicit egress deny rules
for the applicable private ranges.

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
