# MXC Network Configuration, GA

The `network.egress` and `network.ingress` sections described in this document
are planned for schema 0.8.0 but are not yet accepted by the current parser.
Schema 0.7 and earlier retain their legacy network configuration shape.

## Overview

The MXC network configuration describes what network access a sandboxed workload has. The schema is shared across all
container types. Enforcement varies by backend and platform.

This document covers the GA scope for the General Availability release.

**GA Goal:** Reduce the network surface an AI agent can use to escape its sandbox or exfiltrate data. By default, all outbound traffic is dropped. The recommended path for GA is: localhost HTTP/S proxy for application traffic (API calls, package downloads). Direct outbound connections (raw sockets, SSH, custom TCP/UDP) are blocked by default and only allowed when explicitly permitted by IP/CIDR rules. This is a hard problem to solve across multiple platforms. GitHub Copilot expects sandboxes to behave consistently cross-platform, but each platform has different enforcement primitives. This document describes what MXC can enforce on each backend, where platform limitations exist.

### GA Commitments: What Traffic Goes Where

This document specifies the shared MXC networking schema and GA behavior for backends that support network configuration. Backend-specific support, enforcement differences, and unsupported modes are described in the GA Scope by Backend section.

#### Connectivity models

MXC defines three outbound connectivity models, listed in increasing order of
network restriction. Model 1 applies the configured L3/L4 filtering
(IP/CIDR/port/protocol allow/block rules). Models 2 and 3 have no direct egress
path and therefore do not accept direct egress allow or deny rules.

- **Direct internet + L3/L4 filtering, no proxy (least restrictive).** The sandbox reaches the internet directly over HTTP(S) (and other protocols), subject only to IP/CIDR/port/protocol allow/block rules. No proxy is configured, so there is no application-layer (domain/URL/content) inspection.
- **No direct internet + loopback HTTP(S) proxy (more restrictive).** The sandbox has no direct internet path; the only reachable egress is the loopback proxy port, and all other outbound is dropped. Cooperating clients route their HTTP(S) to the proxy (via the proxy environment variables / platform proxy configuration), where it is fully inspectable/filterable by the consumer. A client that ignores the proxy and tries to reach the internet directly is dropped, since no other egress path exists.
- **No direct internet + no inbound (most restrictive):** This is the most
  restrictive model. External network traffic is dropped; backend-local
  intra-sandbox IPC is described separately below.

There was a fourth model that was looked at Direct internet + L3/L4 filtering + loopback HTTP(S) proxy. However, unlike model 2 which only allows traffic through a specific loopback port, direct internet access greatly decreases the ways to control egress and increases the opportunities for agent bypass. It is not a model we will have for GA.

**GA goal:** model 2 (recommended to mxc consumers) on every backend. The shape of model 2 is the same everywhere: restrict the sandbox's outbound so the only reachable destination is the loopback proxy port, and configure the proxy information so cooperating clients route there.

This loopback-only-plus-proxy-routing pattern is a well-established way to
confine sandboxed agent egress. The GA target enforces a strict localhost-only
egress restriction. See GA Scope by Backend for
per-backend details and compatibility limitations.

Throughout this document, the deny-all-except-proxy posture (the GA goal) refers to model 2.

#### Outbound Traffic Routing

**Default stance:** outbound is blocked by default. The paths below describe how allowed traffic flows.

**Proxy path (recommended for application traffic):**

- **Protocol:** HTTP and HTTPS only
- **Destination:** Localhost proxy only (e.g., 127.0.0.1, ::1)
- **Ports:** Any port within the 1 – 65535 range.
- **Routing mechanism:** This applies to HTTP(S) only, never to other protocols. The sandbox's outbound is restricted
  so the only reachable destination is the loopback proxy port. Cooperating clients use platform proxy configuration
  or proxy environment variables. A client that ignores the proxy cannot reach the internet directly on an enforcing
  model-2 path because the egress restriction drops everything except the proxy port. In model 1, such a client may
  instead egress directly, subject to the IP/CIDR/port/protocol rules.
- **What is NOT routed:** Non-HTTP traffic (raw TCP/UDP sockets, SSH, custom protocols, QUIC, WebRTC, etc.) is never
  redirected to the proxy. In model 2, direct internet traffic is blocked. Backend-specific private-network behavior
  is described in the GA Scope by Backend section. In model 1, non-HTTP traffic is subject to the
  IP/CIDR/port/protocol rules.

**Direct outbound path (model 1 only):**

- **When allowed:** Only when explicitly allowed by IP/CIDR + port + protocol rules in `egress.allow`. In model 2 there is no direct egress path, so these connections are not possible regardless of any allow rules.
- **Use case:** e.g. SSH to a specific dev server, a direct TCP connection to a database, UDP to a specific endpoint, ICMP for diagnostics.
- **Caveat (coarse filtering):** Rules match IP/CIDR + port + protocol, not the application protocol. A port number does not identify a service (DNS need not use 53; a database may listen on any port), so allowing or denying a port is a blunt control rather than service-level filtering.
- **Enforcement:** Backend-specific filtering described in the GA Scope by Backend section.

**Example:**

| Consumer scenario | Which model they should use |
|---|---|
| HTTP/HTTPS API calls → localhost proxy (e.g., port 8080) | model 2 |
| SSH to 192.0.2.10:22 → explicit allow rule required | model 1 |
| DNS to 8.8.8.8:53 → explicit allow rule required (or blocked if resolver IP not allowed) | model 1 |
| Raw TCP to 140.82.112.0/20:443 → explicit allow rule required | model 1 |

#### Host Loopback and Inbound Policy

**Default stance:** Host-loopback and LAN/private-network inbound traffic are
blocked by default on backends that enforce the GA network policy.

On backends with private loopback, this does not affect intra-container
loopback. Processes inside the same sandbox may communicate over localhost /
127.0.0.1 / ::1.

Ingress has two allow/deny controls and no rule arrays:

- `ingress.default` controls LAN/private-network inbound traffic where the
  backend supports it.
- `ingress.hostLoopback` controls inbound connections originating from the host loopback path and targeting a listener
  in the sandbox.

The specific `hostLoopback` value overrides `default` for the host-loopback
path. For example, `default: deny` with `hostLoopback: allow` permits
host-loopback connectivity while denying other inbound traffic.

**Scope:**

- Intra-container loopback: allowed on backends with private loopback
- Sandbox-originated private-network traffic: controlled by `egress` on backends that cleanly separate
  private-network ingress from egress; backend-specific limitations are documented below
- Host-loopback-to-sandbox traffic: controlled by `ingress.hostLoopback`
- LAN/private-network inbound: controlled by `ingress.default`, where supported
- WAN inbound: not enabled by the GA policy

**Use cases for `ingress.hostLoopback: allow`:**

- MCP servers in SSE/WebSocket mode (server listens on a port for client connections from host)
- Language server daemons (e.g., TypeScript language server) accessed from host IDE
- Local dev servers (e.g., npm run dev on port 3000) accessed from host browser

#### Inter-Container Networking Policy

**GA stance:** Only Windows process containers support this today.

- **Windows process containers:** Two AppContainers can communicate over host loopback only if AppContainer loopback-exemption rules are installed for the pair. These rules are directional, so both directions must be granted. This allows pointed container to container communication over the loopback. MXC will allow this for GA.
- **WSLc / LXC / Bubblewrap:** Each sandbox has its own network namespace, so 127.0.0.1 is private to the sandbox and separate sandboxes cannot reach each other over loopback. Inter-container communication requires explicit virtual networking (veth/bridge/routing, a shared namespace, or a brokered host proxy/IPC path). LXC has mature primitives for this; Bubblewrap would require MXC to build the networking around it. This is out of scope for GA for all 3.
#### Intra-Container Networking Policy

Backends with private loopback allow loopback traffic within the same sandbox.
This enables multi-process applications, local IPC over localhost sockets, and
sandbox-local helper processes.

On backends with private loopback, traffic between processes in the same
sandbox is not governed by outbound IP/CIDR rules or host-to-container inbound
policy.

## Proposed Schema

### Connectivity model 1 and 3

Direct internet, no proxy (least restrictive). OR no egress at all: default deny with no allow rules (most restrictive)

```json
{
  "network": { // Network policy
    "egress": {
      "default": "deny",
      "allow": [
        {
          "to": [ { "cidr": "140.82.112.0/20" } ],
          "ports": [ { "protocol": "tcp", "port": 443 } ]
        }
      ],
      "deny": []
    },
    "ingress": {
      "default": "deny",
      "hostLoopback": "deny"
    }
  }
}
```

### Connectivity model 2

No direct internet, loopback proxy only (more restrictive). Proxy

```json
{
  "runtimeConfig": { // runtime data passed to MXC (not policy)
    // http(s)://localhost:<port>, 127.0.0.1:<port>, or [::1]:<port>
    "networkProxy": "http://127.0.0.1:8080"
  }
}
```

The omitted `network` block uses deny defaults. When `runtimeConfig.networkProxy` is present, direct egress rules do
not apply because egressible HTTP(S) traffic is forwarded to the proxy. Without runtime proxy configuration, the deny
defaults form model 3. Backend-specific proxy reachability requirements are documented below.

This schema follows container-ecosystem conventions (CIDR peers, egress/ingress, to/ports), modeled loosely on Kubernetes NetworkPolicy (the CNCF standard layered on CNI/OCI) rather than on platform firewall primitives. MXC keeps an explicit deny list and a per-direction default, which are a deliberate extension over pure Kubernetes NetworkPolicy (allow-only with `ipBlock.except`) to give an auditable default and block-precedence.

Egress peer and port fields (used in `egress.allow[]` / `egress.deny[]`; not shown in the minimal example above):

| Field | Type | Notes |
|---|---|---|
| `to[].cidr` | IPv4 / IPv6 CIDR, or 0.0.0.0/0 / ::/0 for any | Single CIDR string (CNI/Kubernetes style), replacing separate address + prefix length. |
| `to[].except` | list of CIDRs, optional | CIDR exclusions; backend-dependent. |
| `ports[].protocol` | tcp / udp / icmp / any | `any` matches all protocols. Backend support is described below. |
| `ports[].port` | uint16, optional | Destination port. Omit `ports` to match all ports/protocols. |
| `ports[].endPort` | uint16, optional | Numeric port-range end; backend-dependent. |

Ingress has no CIDR peers or port rules. `ingress.default` and
`ingress.hostLoopback` are the complete GA ingress surface.

## Design decisions

### D1: Default-deny outbound

**Decision:** Unlisted destinations are unreachable. A configuration that mentions nothing grants nothing.

**Why:** This ensures the configuration explicitly describes the sandbox's network permissions (auditable on enforcing backends). Forgotten rules fail closed (safer). The same configuration means the same thing on different hosts and container types (portable intent, though enforcement fidelity varies by platform).

**Limitation:** Enforcement requires an OS-level egress restriction. Backend-specific docs identify unsupported modes
and temporary compatibility behaviors whose enforcement is intentionally coarser. Outside those documented
exceptions, a backend rejects configurations it cannot enforce.

### D2: Inbound and host-loopback are blocked by default

**Decision:** GA defines outbound configuration and inbound control.
`ingress.default: deny` blocks LAN/private-network inbound traffic, and
`ingress.hostLoopback: deny` separately blocks host-loopback-to-sandbox
connectivity. The host-loopback value overrides `default` for that path.
Intra-container loopback is allowed on backends with private loopback.

**Why inbound is blocked by default:**

- **Attack surface:** Allowing host-to-container inbound means the sandbox can run servers accessible from the host. For agentic workloads, this creates a risk of command-and-control servers, exfiltration channels, or lateral movement vectors.
- **Opt-in model:** Customer scenarios that need host-to-container inbound (MCP servers in SSE/WebSocket mode accessed from host, language server daemons accessed from host IDE) must explicitly set `ingress.hostLoopback: allow`.
- **GA enforcement:** Windows process containers use loopback exemption rules
  scoped to the AppContainer SID, and WSLc/LXC/Bubblewrap use iptables INPUT.

**Elevation caveat:** Installing these filters (WFP on Windows, iptables on the Linux backends) generally requires elevation. Elevating on every sandbox launch is out of the question, so MXC applies them through a privileged broker/service rather than from the unelevated launch path. A per-platform, per-technology elevation story must be defined in a separate MXC elevation design doc and is a prerequisite for this enforcement.

### D3: IP literals and CIDRs only (no DNS names)

**Decision:** Rule addresses must be IPv4/IPv6 literals or CIDRs. DNS names are rejected at validation time. The backend does not resolve names on behalf of callers.

**Why:** Names are bypassable and non-deterministic. A container that resolves DNS itself can map a blocked name to an IP and connect directly. These results can change between config-time and runtime (TOCTOU) and vary by resolver/TTL/cache. IP/CIDR literals are deterministic and auditable.

**GA DNS behavior:** GA does not implement domain-based DNS policy. DNS is not a first-class policy surface. If firewall rules block the DNS resolver IP, DNS queries fail. If rules allow the resolver IP, the sandbox can resolve any domain.

**Secure domain allow-listing:** For HTTP(S) routed to the proxy, the proxy can inspect the domain on each CONNECT request in the HTTP header, and then choose to allow or deny by domain. The proxy resolves the hostname on the sandbox's behalf and enforces the domain allow-list before connecting. DNS resolution security at this point is on the proxy and not MXC.

### D4: Explicit deny takes precedence over explicit allow

**Decision:** When a connection matches both an `egress.allow` rule and an `egress.deny` rule, the deny wins. With `egress.default: "deny"`, no matching allow means no outbound access. With `egress.default: "allow"`, no matching deny means unrestricted outbound.

**Why:** Fail-closed security posture. Deny rules act as overrides for broader allow rules (e.g., allow 0.0.0.0/0 but deny specific malicious IPs).

### D5: Proxy is HTTP/S via platform-native APIs; localhost only for GA

**Decision:** For GA, proxy routing covers HTTP and HTTPS traffic routed through the platform's native proxy surface. The proxy must be on localhost (same-machine loopback) for GA. Remote proxies are out of scope for GA.

**Platform-specific enforcement:**

| Platform | Enforcement Mechanism |
|---|---|
| Windows (Process Containers) | Enforcing BaseContainer path: per-AppContainer WinHTTP proxy configuration and scoped proxy-only access. AppContainer fallback: cooperative routing only. |
| Linux (WSLc, LXC, Bubblewrap) | iptables in the sandbox network namespace: default-DROP all outbound except the configured proxy endpoint. This DROP is the enforcement. MXC-set `HTTP_PROXY`/`HTTPS_PROXY` env variables are an advisory routing hint; an app that ignores them does not gain direct internet access. |

**Why localhost only:** Remote proxies introduce trust boundary issues (proxy on different machine = different security context). Localhost proxy simplifies GA implementation and ensures proxy is under the same administrative control as the sandbox.

**Proxy environment-variable hygiene (all backends):** The sandbox starts
with all HTTP(S)-related proxy environment variables cleared to empty
(`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY`, and their
lowercase variants). The sandbox never inherits host or stale proxy settings.
In model 2, MXC sets `HTTP_PROXY`, `HTTPS_PROXY`, and their lowercase variants
to the configured loopback proxy. Bypass variables such as `NO_PROXY` do not
carry the proxy endpoint. In model 1 the variables remain empty.

**Consumer-provided proxy (all backends):** MXC does not provide, launch, or
manage the proxy, and knows nothing about it beyond the host:port in the
configuration. The consumer must start the proxy listening before launching
the workload. On enforcing paths, MXC restricts the sandbox's egress to that
endpoint and points the proxy variables at it. Backend-specific compatibility
paths may provide cooperative routing only and are documented separately.
Making the proxy reachable from inside the sandbox is MXC's responsibility and
is backend-specific.

What is and is not routed through the proxy is described under Outbound Traffic Routing.

### D6: Per-sandbox scoping

**Decision:** Every configuration is scoped to one sandbox instance. Two concurrent sandboxes from different clients (e.g., gh-copilot and vscode) have independent configurations. One sandbox's configuration cannot affect another's network access.

**Why:** Isolation between sandboxes prevents cross-sandbox interference and ensures configuration changes in one sandbox do not weaken another.

**Implementation:** The sandbox identity used for scoping is backend-specific, such as an AppContainer SID or network
namespace.

### D7: Schema is container-type-agnostic; enforcement is backend-specific

**Decision:** The network schema block is shared across all container types. The same JSON configuration expresses the
same policy intent across backends.

**Why:** Portable intent across platforms. Customers write one configuration that expresses their security policy; MXC maps it to backend-specific enforcement.

**Reality:** Linux network namespaces cleanly separate private-network ingress from egress. Windows AppContainer
exposes `privateNetworkClientServer` as one bidirectional capability, so ProcessContainer requires
`ingress.default: "allow"` for private-network access in either direction and uses `egress` for internet-bound policy.
Cooperation-dependent routing is allowed only above an enforcing layer that blocks non-cooperative internet traffic.

### D8: Delegation from the invoking user

**Decision:** Like the filesystem configuration, the network configuration is a delegation: the contained code receives no more network access than the invoking user could exercise themselves.

**Why:** The sandbox can only be more restricted, never less. A sandboxed process cannot reach a network destination that the invoking user's own process could not reach. Host-level firewalls, VPN configuration, and similar environmental controls still apply on top of this.

## GA Scope by Backend

GA includes all backends for their respective isolation capabilities. Network
configuration enforcement varies by backend. This section describes the GA
target for each backend; it does not claim that unfinished roadmap work is
already implemented.

### Process containers (Windows): GA target and compatibility behavior

The model-2 guarantees below apply to ProcessContainer paths with OS-scoped
proxy enforcement. The AppContainer compatibility fallback is cooperative and
does not satisfy model 2; see the implementation doc for its limitations.

**Connectivity models:**

- **Model 2 (recommended):** Grants no `internetClient`, so direct internet traffic is blocked. A packaged or
  unpackaged AppContainer proxy uses `allowedProxyPeer` and requires `ingress.default: "allow"` to grant
  `privateNetworkClientServer`. That capability permits private-network client and server traffic by Windows design.
- **Model 1:** Grants `internetClient`, allowing direct internet egress under WFP IP/CIDR/port/protocol rules;
  private-network communication still depends on `ingress.default`.
- **Model 3:** Grants no `internetClient`, private-network capability, or loopback exemptions.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| IP/CIDR allow/block | WFP dynamic filters for IPv4/IPv6, scoped to AppContainer SID | Internet destinations only |
| Port filtering | Port filtering via WFP | Port ranges supported. |
| Protocol filtering | Protocol filtering via WFP | Schema values are `tcp`, `udp`, `icmp`, and `any`; WFP maps ICMP by address family. |
| Default-deny | WFP block-all baseline filter at lower precedence than explicit allows. AppContainer has no internetClient capability. | |
| Proxy (HTTP/S only) | Per-AppContainer WinHTTP configuration | Private network follows `ingress.default` |
| Per-sandbox scoping | AppContainer SID, unique per sandbox instance | |
| Private network | `privateNetworkClientServer` via `ingress.default` | Bidirectional; not narrowed by `egress` |
| Inbound | Capabilities and loopback rules | Private network uses `ingress.default`; loopback is separate |
| DNS | DNS queries follow same IP/CIDR allow/block rules as other traffic. No domain-based filtering. | If DNS resolver IP is blocked, DNS fails. If allowed, sandbox can resolve any domain. **For HTTP(S) via the proxy, DNS resolution happens in the proxy.** |
| Bypass resistance | High. Kernel-enforced WFP filters. Bypass requires kernel compromise or AppContainer escape (elevation). | |

**Implementation doc:** [Process Container Networking Configuration, GA](../../../process-container/networking.md)

### WSLc: GA enforcement

**Default stance:** Deny all outbound (iptables default DROP in container network namespace).

**Connectivity model:** Model 2 achievable, iptables kernel-enforces deny-all-except-loopback-proxy within the container network namespace. Model 1 by relaxing the allow-list (permit direct egress) and using iptables for filtering. Model 3 is enforced with the container network namespace and iptables/nftables blocking all in and out traffic.

**Recommended path:** Localhost proxy (HTTP/S via env vars) with no direct
egress allow-list.

**Enforcement:**

| Configuration concept | Enforcement mechanism | Notes |
|---|---|---|
| IP/CIDR allow/block | iptables rules in container network namespace. | IPv4 + IPv6 at GA |
| Port filtering | iptables rules in container network namespace. | Port ranges supported. |
| Protocol filtering | iptables rules in container network namespace. | tcp, udp, icmp. |
| Default-deny | iptables rules in container network namespace. | |
| Proxy (HTTP/S only) | `HTTP_PROXY` / `HTTPS_PROXY` environment variable injection. Apps honoring these vars are routed. iptables rules allow outbound to only localhost proxy provided by MXC caller. | Apps ignoring env vars are still subject to allow/block rules (cannot bypass iptables). |
| Per-sandbox scoping | Container network namespace (each container has isolated network namespace) | |
| Inbound | Enforced via iptables INPUT chain. When `ingress.hostLoopback: deny` (default), all host/external inbound blocked. When allow, iptables rules allow host loopback inbound to the container. | Loopback only. |
| DNS | DNS queries follow same IP/CIDR allow/block rules as other traffic. No domain-based filtering. | If DNS resolver IP is blocked, DNS fails. If allowed, sandbox can resolve any domain. **For HTTP(S) via the proxy, DNS resolution happens in the proxy.** |
| Bypass resistance | Medium. Container escape bypasses iptables, but kernel-enforced within container. | |

### LXC and Bubblewrap: GA enforcement

Same model and enforcement as WSLc (model 2 achievable; iptables/nftables on
the veth interface; default-deny outbound, loopback proxy only, and
`ingress.hostLoopback` via INPUT).

### macOS (Seatbelt): GA enforcement

Seatbelt supports models 2 and 3 only. It can confine outbound traffic to the local proxy or deny networking, but it
cannot enforce arbitrary IP/CIDR, port, or protocol rules. Because it shares the host network stack, it also cannot
cleanly separate host loopback from intra-sandbox TCP loopback; unsupported ingress combinations are rejected.

### Other backends

- **Windows Sandbox:** Guest-side firewall only, with hardcoded rules. In GA for development/testing scenarios where network isolation is not critical.
- **Isolation Session:** No network filtering or denial is possible — outbound is open and a process inside can listen on a localhost-reachable port. Provision therefore requires the canonical unrestricted-network acknowledgment (`network.defaultPolicy=allow` + `network.allowLocalNetwork=true`) and rejects every other network/proxy policy at validation time. In GA for process isolation only (identity, lifecycle).
- **Hyperlight, Nanvix:** Not in this GA scope doc. Additional follow up is needed to confirm their capabilities and whether they align with this doc.

## Gaps and limitations

**What GA cannot do:**

- **DNS domain filtering:** The IP/CIDR schema cannot distinguish hostnames that resolve to the same IP. Domain allow/deny requires either deeper platform support or the proxy inspecting the CONNECT/request host plus blocking direct DNS egress (see D3).
- **Inter-container networking:** Containers cannot communicate with each other (except Windows process containers).
- **Proxy arbitrary network traffic:** GA MXC configures proxies for HTTP/S traffic only. Applications that do not use
  the platform proxy configuration or proxy environment variables are not routed through the proxy and instead have
  their egress blocked.
