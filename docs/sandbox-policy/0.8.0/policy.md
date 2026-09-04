# MXC Sandbox Policy Spec v0.8.0

## SandboxPolicy

`SandboxPolicy` is MXC's cross-platform JSON authoring contract. It expresses
portable filesystem, network, UI, and execution restrictions without selecting
backend-specific mechanisms. This page defines the language-neutral JSON shape;
SDK API coverage is version-dependent, and an SDK's native types or builders
may not yet expose every field. When supported, those APIs produce the
`ContainerConfig` consumed by MXC.

```json
{
  "version": "0.8.0-alpha",
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
  },
  "ui": {
    "allowWindows": false,
    "clipboard": "none",
    "allowInputInjection": false
  },
  "timeoutMs": 30000
}
```

### `filesystem`

| Field | Description |
|---|---|
| `readwritePaths` | Paths the sandbox can read and write. |
| `readonlyPaths` | Paths the sandbox can read but not write. |
| `deniedPaths` | Paths the sandbox cannot access. |
| `clearPolicyOnExit` | Clear retained policy after execution. Maps to the inverse of `lifecycle.preservePolicy` and can cover multiple policy types, including filesystem and network policy. Defaults to `true`. |

Omitted filesystem permissions remain denied.

### `network`

Schema 0.8 accepts either the legacy network fields or the directional fields,
but not both in one policy.

#### Legacy network fields

These fields preserve schema 0.6 and 0.7 authoring compatibility.

| Field | Description |
|---|---|
| `allowOutbound` | Allow outbound network access. Defaults to `false`. |
| `allowLocalNetwork` | Allow inbound connections from local/private networks. Defaults to `false`. |
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

```typescript
type NetworkRuleConfig = {
  to?: Array<{
    cidr: string;
    except?: string[];
  }>;
  ports?: Array<{
    protocol?: "tcp" | "udp" | "icmp" | "any";
    port?: number;
    endPort?: number;
  }>;
};
```

| Rule field | Description |
|---|---|
| `to` | Destination CIDRs. Omission matches both IP families. |
| `to[].cidr` | IPv4 or IPv6 CIDR. |
| `to[].except` | CIDRs excluded from the containing peer. Each exclusion must use the same address family and be contained within `to[].cidr`. |
| `ports` | Protocol and destination-port selectors. Omission matches all. |
| `ports[].protocol` | `"tcp"`, `"udp"`, `"icmp"`, or `"any"`. Defaults to `"any"`. |
| `ports[].port` | Destination port from 1 through 65535. Omission matches every port. Must be omitted for `"icmp"`. |
| `ports[].endPort` | Inclusive range end from 1 through 65535. Requires `port`, must be greater than or equal to it, and must be omitted for `"icmp"`. |

Explicit `to` and `ports` arrays must not be empty.

#### `network.ingress`

| Field | Description |
|---|---|
| `default` | LAN/private-network inbound action: `"allow"` or `"deny"`. Defaults to `"deny"`. |
| `hostLoopback` | Bidirectional host-loopback action: `"allow"` or `"deny"`. Defaults to `"deny"`. |

Backends that cannot enforce a requested ingress combination reject it rather
than weakening the policy.

### `runtimeConfig`

Schema 0.8 introduces `runtimeConfig` for cross-platform runtime metadata
needed to execute a policy but which is not itself security-policy intent. It
is configuration rather than policy, and it is not tied to a specific backend.
The only runtime metadata currently defined is the network proxy endpoint.

| Field | Description |
|---|---|
| `networkProxy` | HTTP/S loopback proxy URL with an explicit port. Requires `network.egress.default` to be `"deny"` with no direct allow or deny rules. |

### `ui`

| Field | Description |
|---|---|
| `allowWindows` | Allow visible windows. Defaults to `false`. |
| `clipboard` | `"none"`, `"read"`, `"write"`, or `"all"`. Defaults to `"none"`. |
| `allowInputInjection` | Allow keyboard or mouse input injection. Defaults to `false`. |

### `timeoutMs`

Execution timeout in milliseconds. Omission means no timeout.

### Default-deny

Omitted permissions remain denied. A schema 0.8 policy with no network fields
selects directional deny defaults.

## Examples and detailed behavior

- [Schema 0.8 directional config example](../../../tests/examples/30_network_0_8_directional.json)
- [Schema updates from 0.7 to 0.8](networking/schema-updates.md)
- [Network modes and rule semantics](networking/networking.md)
