# Process Container Networking Configuration, GA

The planned schema 0.8.0 ProcessContainer networking uses the shared `network.egress` and `network.ingress` policy plus
the `runtimeConfig.networkProxy` and `processContainer.network.allowedProxyPeer` configuration.

Implementation companion to the parent
[MXC Network Configuration, GA](../sandbox-policy/0.8.0/networking/networking.md)
doc. The parent owns the shared policy schema, connectivity models, and GA goal.
This doc covers only how the Windows ProcessContainer backend enforces them.

## 1. What this backend targets at GA

On ProcessContainer paths with OS-scoped enforcement, each container gets two enforcement primitives scoped to its
container SID and applied with no UAC prompt per launch. The AppContainer compatibility behavior is documented in
section 2 and is not equivalent to these guarantees.

- **WFP egress filters:** block outbound traffic by default, then allow or block specific public or private
  destinations by IP address or range, protocol, and port for both IPv4 and IPv6. An explicit block always wins over
  an allow. The rules apply only to this container.
- **Per-container WinHTTP HTTP/S proxy:** points WinHTTP-stack clients (e.g., the WinHTTP/Chromium stack) at a
  caller-provided loopback proxy container. MXC also sets `HTTP_PROXY`, `HTTPS_PROXY`, and their lowercase variants to
  the loopback endpoint for runtimes that use proxy environment variables rather than WinHTTP. `NO_PROXY` is a bypass
  list and does not carry the proxy endpoint. The containment boundary is the absence of direct internet capability.
  Private-network traffic remains available in both directions when `ingress.default` is `"allow"`.

The examples below use the proposed schema 0.8 network shape.

Windows exposes `privateNetworkClientServer` as one bidirectional AppContainer capability. ProcessContainer therefore
requires `ingress.default: "allow"` before the container can communicate with private-network addresses. Enabling it
also permits private-network server traffic. `ingress.default` gates whether the capability exists; `egress` then
narrows the outbound public and private destinations reachable through the granted capabilities.
`ingress.hostLoopback` remains the separate host-loopback control.

| Egress default | Ingress default | AppContainer capabilities | Result |
|---|---|---|---|
| `deny` | `deny` | None | Internet and private-network traffic are denied. |
| `allow` | `deny` | `internetClient` | Internet outbound is allowed; private-network traffic is denied. |
| `deny` | `allow` | `privateNetworkClientServer` | Outbound denied; private-network inbound allowed. |
| `allow` | `allow` | Both capabilities | Internet outbound and bidirectional private-network traffic are allowed. |

This matrix covers the direction defaults without explicit internet egress rules or proxy mode.

### Model 1: direct egress, WFP-filtered (least restrictive)

- **Capabilities:** `internetClient`, plus `privateNetworkClientServer` only when `ingress.default` is `"allow"`.
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
  }
}
```

### Model 2: proxy-only egress (recommended)

| Item | Requirement |
|---|---|
| Client capability | `privateNetworkClientServer`, enabled by `ingress.default: "allow"` |
| Proxy capabilities | `privateNetworkClientServer`; also `internetClient` for external destinations |
| Network policy | `egress.default: "deny"` and `ingress.default: "allow"` |
| Enforcement | Capability is bidirectional; WFP permits client egress only to the configured proxy endpoint |

This is a ProcessContainer-specific mapping. Callers that need a private-network proxy or any other private-network
communication must set `ingress.default` to `"allow"` and accept that Windows enables both private-network client and
server behavior. On an enforcing BaseContainer path, per-container WFP permits the MXC client container to connect only
to the configured loopback address and port and blocks direct public and private destinations.

#### Proxy deployment choices

Model 2 involves two separate processes:

- **MXC client container:** the BaseContainer created by MXC, which runs the caller's workload and initiates HTTP/S
  connections to the proxy.
- **Proxy process:** a caller-created process that is already running outside the MXC client container. It may be
  packaged or unpackaged, with or without AppContainer isolation.

| External proxy | `allowedProxyPeer` | MXC client policy | Additional proxy identity |
|---|---|---|---|
| Packaged proxy | PFN | `default: "allow"`; `hostLoopback: "deny"` | Package identity |
| Unpackaged AppContainer | Profile | `default: "allow"`; `hostLoopback: "deny"` | AppContainer profile |
| Unpackaged non-AppContainer | Omit | `default: "allow"`; `hostLoopback: "allow"` | None |

Regardless of proxy type, an enforcing BaseContainer path applies per-container WFP rules that permit the MXC client
container to connect only to the configured loopback address and port. `allowedProxyPeer` adds proxy identity binding
on top of that common endpoint enforcement.

All deployments use `ingress.default: "allow"` because ProcessContainer uses it as the capability gate for
`privateNetworkClientServer`. This is a Windows capability requirement, not a statement that the proxy connection
enters the MXC client container; the client initiates that connection. The capability is bidirectional, so it also
permits private-network server traffic.

`ingress.hostLoopback` is bidirectional. `allowedProxyPeer` authorizes a package family or AppContainer profile without
opening general host-loopback access, so identity-scoped paths keep `hostLoopback: "deny"`. Only an unpackaged
non-AppContainer proxy lacks an accepted peer identity and requires `hostLoopback: "allow"`. That also permits the MXC
client container to reach other host-loopback services and permits host-loopback clients to reach listeners in the MXC
client container.

#### Identity-scoped proxy

Use the canonical [ProcessContainer schema 0.8 configuration](examples/0.8.0-schema.md), which shows
`runtimeConfig.networkProxy`, `processContainer.network.allowedProxyPeer`, and their relationship in one place.
Use the installed Package Family Name for a packaged proxy, regardless of whether it has AppContainer isolation. Use
the AppContainer profile name for an unpackaged AppContainer proxy.

#### Unpackaged non-AppContainer proxy

An unpackaged non-AppContainer proxy has no package family or AppContainer profile identity:

```jsonc
{
  "network": {
    "egress": { "default": "deny" },
    "ingress": {
      "default": "allow",
      "hostLoopback": "allow"
    }
  },
  "runtimeConfig": {
    "networkProxy": "http://127.0.0.1:8080"
  }
  // No processContainer.network.allowedProxyPeer.
}
```

MXC grants the client container `privateNetworkClientServer` through `ingress.default: "allow"`, just as it does for an
identity-scoped proxy. The difference is that MXC identifies this proxy only by the configured endpoint and enables
bidirectional host-loopback access. This is the lowest-enforcement deployment option because common WFP endpoint
scoping remains, but Windows cannot verify which host process owns that endpoint. It is intended primarily for
development and debugging and requires an installer- or administrator-owned firewall rule.

#### HTTP client guidance

Code inside the ProcessContainer should use WinHTTP or an HTTP library that queries the system for proxy information.
The OS sets this configuration per BaseContainer, and the WinHTTP stack uses it transparently. The proxy process itself
does not use the BaseContainer's configuration.

MXC also sets the standard proxy environment variables for libraries that use cooperative proxying. Direct internet
traffic that bypasses the proxy is blocked. On an enforcing BaseContainer path, per-container WFP permits egress only to
the configured loopback proxy address and port and blocks direct public and private destinations.

Model 2 requires `egress.default: "deny"` and `ingress.default: "allow"`. When `allowedProxyPeer` names a package or
AppContainer profile, MXC authorizes only that peer and `ingress.hostLoopback` remains denied. An identity-less host
proxy omits `allowedProxyPeer` and requires `ingress.hostLoopback: "allow"`. Direct egress allow and deny rules do not
apply when `runtimeConfig.networkProxy` is present.

The proxy endpoint is runtime metadata, not shared network policy. MXC configures the per-container WinHTTP proxy,
applies WFP endpoint scoping, and grants the private-network capability selected by `ingress.default`.

The identity-scoped and host-loopback paths are
mutually exclusive. When `allowedProxyPeer` is present, MXC resolves the package family or AppContainer profile and
grants the private-network capability selected by `ingress.default`. When it is omitted, MXC uses the configured proxy
endpoint without peer identity binding and requires bidirectional host-loopback access. MXC configures the per-container
WinHTTP proxy for either path.

The caller must:

- create and authorize the proxy;
- start it before the BaseContainer;
- keep it alive until the client exits; and
- leave egress deny-default with no direct allow or deny rules.

#### Proxy identity and firewall authorization

The WFP loopback-address-and-port restriction described above applies to every row. The table compares the additional
OS enforcement provided for the external proxy. A packaged AppContainer proxy provides the best enforcement.

| Proxy deployment | `allowedProxyPeer` | Additional OS enforcement |
|---|---|---|
| Packaged AppContainer | Package family name | **Best:** AppContainer isolation, package identity, package firewall |
| Unpackaged AppContainer | AppContainer profile name | AppContainer isolation and administrator firewall rule |
| Packaged non-AppContainer | Package family name | Package identity and package firewall; no AppContainer isolation |
| Unpackaged non-AppContainer | Omit | **Least:** no proxy identity or isolation; administrator firewall |

The scoped peer rule and `privateNetworkClientServer` do not bypass Windows
Firewall's block-inbound-to-non-allowed-apps policy. A packaged AppContainer proxy uses the package-owned firewall
declaration shown in the [schema 0.8 examples](examples/0.8.0-schema.md); its application entry uses
`uap10:RuntimeBehavior="packagedClassicApp"` with `uap10:TrustLevel="appContainer"`. An unpackaged AppContainer proxy
requires its installer or administrator to own an equivalent rule scoped to the proxy executable and configured port. See
[CreateAppContainerProfile](https://learn.microsoft.com/windows/win32/api/userenv/nf-userenv-createappcontainerprofile)
for unpackaged profile creation.

### Model 3: externally blocked (most restrictive)

- **Capabilities:** none; no host or peer loopback exemptions.
- **Enforcement:** no proxy; external outbound and inbound are dropped.
  Intra-sandbox loopback is not part of the shared external-network policy.

When no runtime proxy or backend proxy peer is configured, deny-all is the default and model 3 is also the result of
providing no network policy at all: the explicit form, an omitted network block, and an empty `"network": {}` are
equivalent:

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

Both WFP filter writes and per-container WinHTTP proxy configuration require a
privileged context. The planned schema 0.8 behavior selects the strongest
usable process-creation contract through runtime probing.

**Preferred selection:** Use PSEC (`CreateProcessSecurityEnvironment`) when its complete export set and runtime support
probe succeed. Fall back temporarily to the legacy SBOX contract through CPIS when PSEC is unavailable, then to
AppContainer when neither BaseContainer contract is usable. The MXC probe must account for the process network
containment required by the request, just as it accounts for filesystem containment support.

**Downlevel behavior:** When neither PSEC nor CPIS is available, MXC uses the AppContainer fallback.
`egress.default: "allow"` grants `internetClient`; `ingress.default: "allow"` grants the bidirectional
`privateNetworkClientServer` capability. This is the documented ProcessContainer mapping on every tier, not a
downlevel weakening. Proxy-configured requests receive cooperative routing through environment variables; this
compatibility behavior is not model 2 enforcement.

Outside that documented proxy compatibility path, the AppContainer fallback is selected only when its capability
mapping preserves the request. Explicit egress rules, and private-network egress restrictions that require WFP, fail
with a typed unsupported-policy error when no BaseContainer contract can enforce them.

## 3. WFP enforcement

The BaseContainer contracts apply outbound WFP filters in the OS's elevated context and own their lifetime.
Downlevel WFP installation, elevation, and cleanup are future work and are not part of the initial schema 0.8
downlevel support.

WFP implements `egress` rules for public and private destinations. `internetClient` enables public-network access.
`privateNetworkClientServer`, selected through `ingress.default`, is the prerequisite for private-network access and
also enables private-network inbound traffic. ProcessContainer therefore cannot allow private-network outbound while
denying private-network inbound.
