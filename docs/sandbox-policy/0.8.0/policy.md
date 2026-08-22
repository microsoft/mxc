# MXC Sandbox Policy Spec v0.8.0

This document summarizes the policy-bearing fields in a schema 0.8
`ContainerConfig`. It describes the JSON contract consumed by MXC and does not
depend on a particular SDK authoring API. See the
[configuration schema](../../schema.md) for the complete config structure and
the backend guides for platform-specific support.

## Policy fields

### `filesystem`

| Field | Description |
|---|---|
| `readwritePaths` | Paths the sandbox can read and write. |
| `readonlyPaths` | Paths the sandbox can read but not write. |
| `deniedPaths` | Paths the sandbox cannot access. |

Omitted filesystem permissions remain denied.

### `network`

Schema 0.8 accepts either the legacy network fields or the directional fields,
but not both in one policy.

#### Legacy network fields

These fields preserve schema 0.6 and 0.7 authoring compatibility.

| Field | Description |
|---|---|
| `defaultPolicy` | Legacy outbound posture: `"allow"` or `"block"`. |
| `enforcementMode` | Legacy enforcement selection: `"capabilities"`, `"firewall"`, or `"both"`. |
| `allowLocalNetwork` | Allow local/private-network access. Defaults to `false`. |
| `allowedHosts` | Hosts or CIDRs allowed by backends that support host filtering. |
| `blockedHosts` | Hosts or CIDRs denied by backends that support host filtering. |
| `proxy` | Legacy proxy configuration: `builtinTestServer`, `localhost`, or `url`. |

#### `network.egress`

| Field | Description |
|---|---|
| `default` | Action when no rule matches: `"allow"` or `"deny"`. Defaults to `"deny"`. |
| `allow` | Direct-egress rules to allow. |
| `deny` | Direct-egress rules to deny. Deny rules take precedence. |

Each allow or deny rule has this shape:

```jsonc
{
  "to": [
    {
      "cidr": "192.0.2.0/24",
      "except": ["192.0.2.128/25"]
    }
  ],
  "ports": [
    {
      "protocol": "tcp",
      "port": 443,
      "endPort": 444
    }
  ]
}
```

| Rule field | Description |
|---|---|
| `to` | Destination CIDRs. Omission matches both IP families. |
| `to[].cidr` | IPv4 or IPv6 CIDR. |
| `to[].except` | CIDRs excluded from the containing peer. |
| `ports` | Protocol and destination-port selectors. Omission matches all. |
| `ports[].protocol` | `"tcp"`, `"udp"`, `"icmp"`, or `"any"`. Defaults to `"any"`. |
| `ports[].port` | Destination port. Omission matches every port. |
| `ports[].endPort` | Inclusive range end. Requires `port`. |

Explicit `to` and `ports` arrays must not be empty.

#### `network.ingress`

| Field | Description |
|---|---|
| `default` | LAN/private-network inbound action: `"allow"` or `"deny"`. Defaults to `"deny"`. |
| `hostLoopback` | Bidirectional host-loopback action: `"allow"` or `"deny"`. Defaults to `"deny"`. |

Backends that cannot enforce a requested ingress combination reject it rather
than weakening the policy.

### `runtimeConfig`

| Field | Description |
|---|---|
| `networkProxy` | HTTP/S loopback proxy URL with an explicit port. Selects the directional network format. |

### `processContainer.network`

| Field | Description |
|---|---|
| `allowedProxyPeer` | Package Family Name or AppContainer profile allowed to communicate over loopback. ProcessContainer only. |

`allowedProxyPeer` is a scoped loopback grant and cannot be combined with
`ingress.hostLoopback: "allow"`. See the
[ProcessContainer networking guide](../../process-container/networking.md) for
its backend-specific requirements.

### `ui`

| Field | Description |
|---|---|
| `disable` | Disable UI access. Defaults to `true`. |
| `clipboard` | `"none"`, `"read"`, `"write"`, or `"all"`. Defaults to `"none"`. |
| `injection` | Allow keyboard or mouse input injection. Defaults to `false`. |

### `process.timeout`

Execution timeout in milliseconds. Omission means no timeout.

### Default-deny

Omitted permissions remain denied. A schema 0.8 policy with no network fields
selects directional deny defaults.

## Examples and detailed behavior

- [Schema 0.8 directional config example](../../../tests/examples/30_network_0_8_directional.json)
- [Schema updates from 0.7 to 0.8](networking/schema-updates.md)
- [Network modes and rule semantics](networking/networking.md)
- [ProcessContainer identity-scoped proxy](../../process-container/examples/0.8.0-schema.md)
