# Process Container Networking Configuration, GA

The planned schema 0.8.0 ProcessContainer networking uses the shared `network.egress` and `network.ingress` policy plus
the `runtimeConfig.networkProxy` and `processContainer.network.allowedProxyPeer` configuration.

Implementation companion to the parent
[MXC Network Configuration, GA](../sandbox-policy/0.8.0/networking/networking.md)
doc. The parent owns the shared policy schema, connectivity models, and GA goal.
This doc covers only how the Windows ProcessContainer backend enforces them.

## 1. What this backend delivers at GA

Each sandbox gets two enforcement primitives, scoped to its container SID and applied with no UAC prompt per launch:

- **WFP outbound filters:** block all outbound traffic by default, then allow or block specific destinations by IP address or range, protocol, and port (a single port or a range), for both IPv4 and IPv6. An explicit block always wins over an allow, so a deny is expected to fall inside the allow it narrows; an allow and a deny matching the exact same destination, protocol, and port is rejected as an invalid policy. The rules apply only to this sandbox.
- **Per-container WinHTTP HTTP/S proxy:** points WinHTTP-stack clients (e.g., the WinHTTP/Chromium stack) at a caller-provided loopback proxy container. MXC also sets the proxy env vars (`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, plus lowercase versions) to the same loopback endpoint. Runtimes that read those variables rather than WinHTTP (Node tooling, Python `requests` / `pip`, Go `net/http`, `curl`, `git`) route through the proxy using this mechanism. These variables are a compatibility layer for well-behaved clients, not the containment boundary. All traffic not destined for the proxy loopback will be dropped.

The examples below use the proposed schema 0.8 network shape.

ProcessContainer ingress has no peer or port rules. `ingress.default` controls LAN/private-network inbound traffic;
`ingress.hostLoopback` controls host-loopback connectivity and overrides `default` for that path. WAN inbound remains
blocked.

### Model 1: direct egress, WFP-filtered (least restrictive)

- **Capabilities:** internetClient, plus a loopback exemption for same-container connections; no other network capability.
- **Enforcement:** WFP allow/block rules; no proxy.

```jsonc
{
  "network": {
    "egress": {
      "default": "deny",
      "allow": [
        { "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ] }
      ]
    },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
    // direct egress, filtered by WFP
  }
}
```

### Model 2: proxy-only egress (recommended)

#### Identity-scoped proxy (recommended)

| Item | Requirement |
|---|---|
| Client capability | MXC adds `privateNetworkClientServer` for contained-peer proxy mode |
| Proxy capabilities | `privateNetworkClientServer`; also `internetClient` for external destinations |
| Peer | Package family name for a packaged app or AppContainer profile name for an unpackaged AppContainer |
| Enforcement | Per-container WinHTTP proxy plus scoped loopback; all direct egress remains blocked |

When `runtimeConfig.networkProxy` is set, MXC adds `privateNetworkClientServer`
for this path.

MXC does not add capabilities to the proxy. The proxy developer must declare `privateNetworkClientServer` for an
AppContainer proxy and `internetClient` when the proxy connects to external destinations.

AppContainer isolation is recommended for both packaged and unpackaged proxies.

#### Unpackaged non-AppContainer proxy

| Item | Requirement |
|---|---|
| Client capability | MXC does not add `privateNetworkClientServer` |
| Peer | Omit `processContainer.network.allowedProxyPeer` |
| Network policy | Set `ingress.hostLoopback` to `"allow"` |
| Enforcement | No proxy-peer identity scoping; direct internet egress remains blocked |

This weaker path is intended primarily for debugging and development.

#### Identity-scoped proxy configuration

```jsonc
{
  "runtimeConfig": { // MXC runtime metadata (not policy)
    "networkProxy": "http://127.0.0.1:8080"
  },
  "processContainer": {
    "network": {
      // Packaged app family name or unpackaged AppContainer profile name.
      "allowedProxyPeer": "agent-proxy"
    }
  }
}
```

#### HTTP client guidance

OS-facilitated transparent HTTP/S proxy configuration is supported only for WinHTTP and HTTP libraries that query the
system for proxy information rather than proxy environment variables. The OS sets this configuration per
BaseContainer, and the WinHTTP stack uses it transparently. The proxy process itself does not use the BaseContainer's
configuration.

As a cooperative fallback, MXC also sets the standard proxy environment variables for libraries that use them. The OS
permits outbound traffic only to the configured loopback proxy address and port; direct or proxy-bypassing traffic is
blocked.

The omitted `network` block uses the default-deny posture. An explicit block with `egress.default: "deny"`,
`ingress.default: "deny"`, and `ingress.hostLoopback: "deny"` is equivalent. Proxy mode cannot contain direct egress
allow or deny rules.

The proxy endpoint is runtime metadata, not shared network policy. MXC resolves `allowedProxyPeer` when provided, adds
`privateNetworkClientServer` unless `ingress.hostLoopback` is `"allow"`, and configures the per-container WinHTTP proxy.

The caller must:

- create and authorize the proxy;
- start it before the BaseContainer;
- keep it alive until the client exits; and
- leave egress deny-default with no direct allow or deny rules.

### Model 3: fully blocked (most restrictive)

- **Capabilities:** none; no loopback exemptions.
- **Enforcement:** no proxy; all outbound and inbound dropped.

Since deny-all is the default, model 3 is also the result of providing no network policy at all: the explicit form, an omitted network block, and an empty `"network": {}` are equivalent:

```jsonc
// explicit (canonical blocked: direct egress, default deny, no allow rules)
{
  "network": {
    "egress": { "default": "deny" },   // no allow rules
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  }
}

// or
{ /* no "network" key at all */ }

// or
{ "network": {} }
```

### 1.1 Out of GA scope for this backend

Do not infer otherwise from the schema:

- Transparent TCP/UDP redirection through the proxy. GA proxying is WinHTTP HTTP/S only.
- L7 classification (e.g., HTTPS vs SSH on :443).
- Durable DNS-name rules.
- Encrypted-payload inspection.
- Per-source or per-port inbound rules. GA ingress is limited to the
  `default` and `hostLoopback` allow/deny toggles.

See the parent doc on the last 4.

## 2. Schema 0.8 selection and downlevel behavior

Both WFP filter writes and per-container WinHTTP proxy configuration require a privileged context. Schema 0.8 selects
the strongest usable process-creation contract through runtime probing.

| Current schema 0.8 selection | Downlevel (Windows 23H2) |
|---|---|
| Prefer PSEC (`CreateProcessSecurityEnvironment`) when its complete export set and runtime support probe succeed. Fall back temporarily to SBOX (`CreateProcessInSandbox`) when PSEC is unavailable, then to AppContainer when neither BaseContainer contract is usable. | Neither PSEC nor SBOX (`CreateProcessInSandbox`) is available, so MXC uses the AppContainer fallback.<br><br>Until downlevel WFP support is implemented, model 1 provides coarse egress and ingress allow/deny postures only. Proxy-configured requests receive cooperative routing through environment variables; this compatibility behavior is not model 2 enforcement. |

### 2.1 Fail loud on version skew: never silently downgrade

PSEC and SBOX support varies between Windows builds as the network-policy
surface grows. Runtime probing selects the contract, but MXC must not silently
weaken the requested policy. The documented downlevel cooperative proxy path
is the explicit compatibility exception and is not model 2 enforcement.

- Follow the PSEC, SBOX, and AppContainer fallback order only when the next path
  can preserve the requested semantics.
- Reject the launch with a typed error when no available path can enforce the
  request.

## 3. WFP enforcement

The BaseContainer contracts apply WFP filters in the OS's elevated context and
own their lifetime. Downlevel WFP installation, elevation, and cleanup are
future work and are not part of the initial schema 0.8 downlevel support.
