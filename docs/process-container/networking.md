# Process Container Networking Configuration, GA

Schema 0.8.0 ProcessContainer networking uses the shared `network.egress` and `network.ingress` policy plus
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
  Private-network inbound follows `ingress.default`; outbound follows `egress` and the proxy endpoint restriction.

The examples below use the schema 0.8 network shape.

When the host supports native ingress controls, ProcessContainer applies `ingress.default` and
`ingress.hostLoopback` independently from WFP egress policy and does not grant the bidirectional
`privateNetworkClientServer` capability. On compatibility paths, `ingress.default: "allow"` uses that capability.
The BaseContainer compatibility path can still narrow outbound traffic with WFP; the final AppContainer fallback
rejects combinations whose directionality it cannot preserve.

| Egress default | Ingress default | Native enforcement | Compatibility behavior |
|---|---|---|---|
| `deny` | `deny` | Both directions denied | No network capability |
| `allow` | `deny` | Outbound allowed; inbound denied | `internetClient` |
| `deny` | `allow` | Outbound denied; inbound allowed | BaseContainer preserves this with WFP; AppContainer fallback rejects it |
| `allow` | `allow` | Both directions allowed | Both network capabilities |

This matrix covers the direction defaults without explicit internet egress rules or proxy mode.

### Model 1: direct egress, WFP-filtered (least restrictive)

- **Native path:** `internetClient` when required by egress; ingress is enforced directly.
- **Compatibility paths:** `privateNetworkClientServer` when `ingress.default` is `"allow"`, plus `internetClient`
  when required by egress.
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
| Client private-network enforcement | Native ingress controls when available; `privateNetworkClientServer` on the compatibility path |
| Proxy capabilities | `privateNetworkClientServer`; also `internetClient` for external destinations |
| Network policy | `egress.default: "deny"` and `ingress.default: "allow"` |
| Enforcement | Native ingress is independent; the compatibility capability is bidirectional. WFP permits client egress only to the configured proxy endpoint on both paths. |

This is a ProcessContainer-specific mapping. Model 2 requires `ingress.default: "allow"`. Native enforcement applies
that value only to ingress; the compatibility path enables both private-network client and server behavior through
the bidirectional capability. On an enforcing BaseContainer path, per-container WFP permits the MXC client container
to connect only to the configured loopback address and port and blocks direct public and private destinations.

#### Proxy deployment choices

Model 2 involves two separate processes:

- **MXC client container:** the BaseContainer created by MXC, which runs the caller's workload and initiates HTTP/S
  connections to the proxy.
- **Proxy process:** a caller-created process that is already running outside the MXC client container. It may be
  packaged or unpackaged, with or without AppContainer isolation.

MXC must reject a `runtimeConfig.networkProxy` endpoint that is not loopback. The caller must configure the proxy to
bind only the exact loopback address and port supplied to MXC.

> [!IMPORTANT]
> The proxy still needs an inbound Windows Firewall rule for its configured loopback port. The Windows change that
> removes this requirement for Windows 11, version 24H2 and later is rolling out in the September 2026 Windows
> updates. Until that update is installed, add the rule manually or, more easily, declare it in the proxy's MSIX
> package.

| External proxy | `allowedProxyPeer` | MXC client policy | Additional proxy identity |
|---|---|---|---|
| Packaged proxy | Package Family Name | `default: "allow"`; `hostLoopback: "deny"` | Package identity |
| Unpackaged AppContainer | Profile | `default: "allow"`; `hostLoopback: "deny"` | AppContainer profile |
| Unpackaged non-AppContainer (development/testing compatibility) | Omit | `default: "allow"`; `hostLoopback: "allow"` | None |

All deployments retain the base Model 2 client policy. `allowedProxyPeer` adds proxy identity binding on top of the
common WFP endpoint enforcement. The proxy endpoint is the loopback address and port in
`runtimeConfig.networkProxy`. The packaged row covers both AppContainer and non-AppContainer proxies because their
client policy and package identity are the same; the enforcement table below separates their additional protections.

`ingress.hostLoopback` is bidirectional. `allowedProxyPeer` authorizes a package family or AppContainer profile without
opening general host-loopback access, so identity-scoped paths keep `hostLoopback: "deny"`. Only an unpackaged
non-AppContainer proxy lacks an accepted peer identity and requires `hostLoopback: "allow"`. This is a weaker
development/testing compatibility deployment, not the shared policy's strict host-loopback-closure guarantee. It
authorizes both host-loopback directions, although WFP still restricts client-container egress to the configured proxy
endpoint. Host-loopback clients can reach listeners in the MXC client container.
When native ingress controls are available, MXC applies `hostLoopback` directly. Caller-supplied
`allowedProxyPeer` remains reserved for the configured proxy identity; MXC does not add a synthetic peer identity for
unrestricted host loopback. Compatibility paths cannot represent `hostLoopback: "allow"`, so a request that needs it
fails as unsupported instead of falling back to a path that would drop the policy.

#### Identity-scoped proxy

Use the canonical [ProcessContainer schema 0.8 configuration](examples/0.8.0-schema.md), which shows
`runtimeConfig.networkProxy`, `processContainer.network.allowedProxyPeer`, and their relationship in one place.
Use the installed Package Family Name for a packaged proxy, regardless of whether it has AppContainer isolation. Use
the AppContainer profile name for an unpackaged AppContainer proxy.

#### Unpackaged non-AppContainer proxy (development/testing compatibility)

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

MXC applies `ingress.default: "allow"` just as it does for an identity-scoped proxy: through native ingress controls
when available or the `privateNetworkClientServer` capability on the compatibility path. The difference is that MXC
identifies this proxy only by the configured endpoint and enables bidirectional host-loopback access. This is the
lowest-enforcement deployment option because common WFP endpoint scoping remains, but Windows cannot verify which
host process owns that endpoint. It is intended primarily for development and debugging.

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
applies WFP endpoint scoping, and enforces `ingress.default` through native controls or the compatibility capability.

The identity-scoped and host-loopback paths are mutually exclusive. When `allowedProxyPeer` is present, MXC resolves
the package family or AppContainer profile and applies the requested ingress policy. When it is omitted, MXC uses the
configured proxy endpoint without peer identity binding and requires bidirectional host-loopback access. MXC
configures the per-container WinHTTP proxy for either path.

The caller must:

- create and authorize the proxy;
- start it before the BaseContainer;
- keep it alive until the client exits; and
- leave egress deny-default with no direct allow or deny rules.

#### Proxy identity enforcement

The WFP loopback-address-and-port restriction described above applies to every row. The table compares the additional
OS enforcement provided for the external proxy. A packaged AppContainer proxy provides the best enforcement. The two
middle rows provide different protections and are not ordered relative to each other.

| Proxy deployment | `allowedProxyPeer` | Additional OS enforcement |
|---|---|---|
| Packaged AppContainer | Package family name | **Best:** AppContainer isolation and package identity |
| Unpackaged AppContainer | AppContainer profile name | AppContainer isolation |
| Packaged non-AppContainer | Package family name | Package identity; no AppContainer isolation |
| Unpackaged non-AppContainer | Omit | **Least:** no proxy identity or isolation |

The packaged AppContainer example uses
`uap10:RuntimeBehavior="packagedClassicApp"` with `uap10:TrustLevel="appContainer"`. An unpackaged AppContainer proxy
uses the profile created for its executable.
See
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
privileged context. Schema 0.8 selects the strongest
usable process-creation contract through runtime probing.

**Preferred selection:** MXC uses the strongest available ProcessContainer path that can enforce the complete request.
Native enforcement supports schema 0.8 egress filters, proxy peer identity, and host-loopback configuration. If that
path is unavailable or incompatible with another requested policy, MXC tries compatibility paths only when they can
preserve the requested behavior. Otherwise the policy is rejected instead of being weakened.

MXC detects native ingress support at runtime. When available, ingress and egress are enforced independently.
Otherwise BaseContainer uses the compatibility capability mapping. That mapping preserves ingress defaults but
cannot represent unrestricted `ingress.hostLoopback: "allow"`, so such a request fails rather than silently weakening
the policy. Capture-denial support is detected independently from network-policy support.

Compatibility paths receive only the network settings they can enforce. Schema 0.8 filters, proxy peer identity, and
host-loopback configuration never fall back to a path that would ignore them. A runtime proxy request is rejected when
the enforcing BaseContainer path is unavailable because the fallback cannot preserve its identity or host-loopback
requirements.

**Downlevel behavior:** Compatible requests use capability-based enforcement:
`egress.default: "allow"` grants `internetClient`, while `ingress.default: "allow"` grants the bidirectional
`privateNetworkClientServer` capability. Legacy proxy requests retain their existing compatibility behavior.

The AppContainer fallback is selected only when its capability mapping preserves the request. Explicit egress rules,
proxy peer identity, and host-loopback allow fail with a typed unsupported-policy error when native enforcement is
unavailable.

## 3. WFP enforcement

The native BaseContainer path applies outbound WFP filters in the OS context and owns their lifetime. Compatibility
paths that cannot guarantee cleanup do not receive those filters. Downlevel WFP installation and reliable cleanup are
future work and are not part of schema 0.8 compatibility support.

WFP implements `egress` rules for public and private destinations. `internetClient` enables public-network access.
Native ingress controls manage private-network inbound independently and require no policy-owned
`privateNetworkClientServer` capability. The BaseContainer compatibility path uses that bidirectional capability for
`ingress.default: "allow"`, with WFP preserving the requested outbound posture. The final AppContainer fallback cannot
preserve every asymmetric combination because it lacks the schema 0.8 WFP policy.
