# MXC network schema updates: 0.7 to 0.8

Schema 0.8 adds explicit egress and ingress policy and moves proxy runtime data
outside the shared policy. During the additive transition, a 0.8 request may
use either the legacy fields or the new fields, but cannot mix both formats.
Schemas before 0.8 cannot use the new fields.

## Field mapping

| Schema 0.7 | Schema 0.8 | Change |
|---|---|---|
| `defaultPolicy: "allow"` | `egress.default: "allow"` | Same outbound posture |
| `defaultPolicy: "block"` | `egress.default: "deny"` | `block` is renamed `deny` |
| IP/CIDR entries in `allowedHosts` | `egress.allow[].to[].cidr` | Can scope by port/protocol |
| IP/CIDR entries in `blockedHosts` | `egress.deny[].to[].cidr` | Deny overrides allow |
| DNS names in `allowedHosts` or `blockedHosts` | No GA equivalent | Schema 0.8 accepts only IP/CIDR rules |
| `enforcementMode` | Removed | The backend enforces the policy or rejects it |
| `allowLocalNetwork` | `ingress.default` | Inbound policy; outbound follows `egress` |
| No equivalent | `ingress.hostLoopback` | New bidirectional host-loopback connectivity control |
| `proxy.localhost` | `runtimeConfig.networkProxy` | Loopback proxy endpoint becomes runtime data |
| `proxy.url` with an HTTP/S loopback URL | `runtimeConfig.networkProxy` | Loopback URL remains supported |
| `proxy.url` with a remote or non-loopback URL | No GA equivalent | Schema 0.8 accepts only loopback proxy URLs |

`proxy.builtinTestServer` has no schema 0.8 GA equivalent.

On backends that cleanly separate private-network ingress from egress, `egress` governs all outbound traffic and
`ingress` governs traffic entering the container. ProcessContainer follows this model when OS ingress policy support
is available. Compatibility paths require `ingress.default: "allow"` to grant Windows' bidirectional
`privateNetworkClientServer` capability before private-network traffic can flow.

This table maps the immutable 0.7 wire fields. In schema 0.7, `allowLocalNetwork` expresses inbound bind/listen
permission and is honored by Seatbelt; ProcessContainer capabilities are separate. It maps only to
`ingress.default` and must not change `egress.default`. Under schema 0.8, ProcessContainer compatibility paths use
that ingress value as the capability gate for private-network traffic, while outbound private destinations remain
subject to `egress`.

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

This schema 0.8 example intentionally narrows the schema 0.7 all-port,
all-protocol allow to TCP port 443. Omit `ports` to preserve the schema 0.7
rule exactly.

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

The omitted 0.8 `network` block uses deny defaults. When `runtimeConfig.networkProxy` is present, cooperating HTTP(S)
clients are configured to use the proxy; clients that ignore the proxy settings are blocked from direct egress.

For example, this legacy policy:

```jsonc
{
  "network": {
    "defaultPolicy": "block",
    "allowLocalNetwork": true
  }
}
```

migrates to deny-default egress with allowed private/LAN inbound:

```jsonc
{
  "network": {
    "egress": { "default": "deny" },
    "ingress": {
      "default": "allow",
      "hostLoopback": "deny"
    }
  }
}
```

This does not grant outbound private-network or internet access when OS ingress policy support is available. On
ProcessContainer compatibility paths, `ingress.default: "allow"` grants the bidirectional private-network capability,
but deny-default `egress` still blocks outbound public and private destinations unless an allow rule or the configured
proxy path applies.

Backend-specific migration can require an additional acknowledgment without changing the shared field mapping:

- Seatbelt cannot separate host loopback from other local inbound traffic, so `ingress.hostLoopback` must equal
  `ingress.default`; a differing pair is rejected.
- Isolation Session cannot enforce any network restriction. Its directional
  acknowledgment is reserved for the backend migration work; until that lands,
  callers must continue using the legacy unrestricted acknowledgment
  (`defaultPolicy: "allow"` plus `allowLocalNetwork: true`).

## Backend-specific schema 0.8 configuration

| Backend | Configuration |
|---|---|
| ProcessContainer | [Schema 0.8 proxy configuration](../../../process-container/examples/0.8.0-schema.md) |
| Seatbelt (macOS) | [Schema 0.8 configuration](../../../seatbelt/seatbelt-backend.md#schema-08-network-shape-egress--ingress--runtimeconfignetworkproxy)
